//! Server policy conversion and actual campaign-only scheduler notification.
//! Private SQL lifecycle oracles live in storage's server_campaign_tests and
//! server_lifecycle_tests modules, where the connection is owned.
mod common;
use loupe_core::text::policy::Payload;
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
use loupe_server::review::campaign::{self, KindHint, OpenCampaign, Opened, RequestedRef};
use loupe_server::review::policy::ReviewPolicy;
use loupe_storage::{campaigns, generations, jobs};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn created(opened: Opened) -> (i64, i64) {
	match opened {
		Opened::Created { campaign_id, job_id } => (campaign_id, job_id),
		other => panic!("expected a new campaign: {other:?}"),
	}
}
fn request(
	reference: RequestedRef<'_, loupe_provenance::Operator>,
) -> OpenCampaign<'_, loupe_provenance::Operator> {
	OpenCampaign {
		trigger: campaigns::Trigger::Manual,
		requested_ref: reference,
		base_sha: None,
		kind_hint: KindHint::Incremental,
	}
}

fn assert_campaign_allocations(db: &loupe_storage::Db, repo: i64, campaign: i64) {
	let count =
		common::jobs(db, repo).into_iter().filter(|job| job.campaign_id == Some(campaign)).count();
	let spent = common::with_repo(db, repo, |scope| {
		loupe_storage::admission::get_spending(scope, campaign)?.unwrap().total()
	})
	.unwrap();
	assert_eq!((count, spent), (1, 1), "campaign {campaign} allocations");
}

#[tokio::test]
async fn background_scheduler_does_not_allocate_or_notify_speculative_coverage() {
	let mut fixture = common::offline::OfflineDatabase::new();
	let db = fixture.open();
	let repo = common::register_repo(&db, &common::new_repo(), None);
	assert!(
		common::repo(&db, repo).scan_interval_seconds.is_none(),
		"campaign work must be the sole notification trigger"
	);
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
		as i64;
	let (campaign, job, generation) = common::with_repo(&db, repo, |scope| {
		let (campaign, job) = created(campaign::open(
			scope,
			&request(RequestedRef::Pinned(&common::marked::operator::text(SHA))),
			&ReviewPolicy::default(),
			now,
		)?);
		let generation = jobs::get(scope, job)?.unwrap().generation_id.unwrap();
		generations::set_profile(
			scope,
			generation,
			1,
			&common::marked::agent::json::<Payload>("{}"),
		)?;
		Ok((campaign, job, generation))
	})
	.unwrap();
	// Inventory finalization has no runtime producer. Author that worker state
	// in this test-owned encrypted file, then reopen the ordinary Db.
	let entry = loupe_proto::review_api::ManifestEntry {
		raw_path_hex: common::marked::operator::identifier("7372632e7273"),
		git_mode: 0o100644,
		object_id: common::marked::operator::identifier(SHA),
	}
	.to_manifest()
	.unwrap();
	let mut manifest = loupe_core::inventory_manifest::ManifestHasher::new(SHA, 1).unwrap();
	manifest.push(&entry).unwrap();
	let bytes = manifest.bytes();
	let digest = manifest.finish().unwrap();
	drop(db);
	fixture.edit(|conn| {
        conn.execute("UPDATE review_generations SET inventory_digest=?2 WHERE generation_id=?1",rusqlite::params![generation,digest.as_slice()])?;
        conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,received_canonical_bytes,expected_digest,created_at,sealed_at) VALUES(?1,1,?2,1,1,?3,?4,0,0)",rusqlite::params![generation,job,bytes,digest.as_slice()])?;
        conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,manifest_position,git_mode,blob_sha,entry_kind,disposition,disposition_reason,created_at) VALUES(?1,'src.rs','src.rs',?2,0,33188,?3,'tracked','context','fixture source',0)",rusqlite::params![generation,b"src.rs".as_slice(),SHA])?;
        conn.execute("UPDATE jobs SET state='succeeded',finished_at=?2,head_sha=?3 WHERE id=?1",rusqlite::params![job,now,SHA])?;
        conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_by_job_id,created_at) VALUES(?1,'u','t','o','[{\"path\":\"src.rs\"}]','high',?2,0)",rusqlite::params![generation,job])?;
        Ok(())
    });
	let db = fixture.open();
	common::with_repo(&db, repo, |scope| {
		campaign::activate_generation(scope, campaign, now)?;
		assert_eq!(generations::get(scope, generation)?.unwrap().state, generations::State::Active);
		Ok(())
	})
	.unwrap();
	assert_campaign_allocations(&db, repo, campaign);
	assert!(common::jobs(&db, repo).iter().all(|job| job.state != JobState::Queued));
	let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
	let cancelled = tokio_util::sync::CancellationToken::new();
	let notified = arrived.notified();
	tokio::pin!(notified);
	notified.as_mut().enable();
	let handle =
		loupe_server::background::spawn_scheduler(db.clone(), arrived.clone(), cancelled.clone());
	let notification = tokio::time::timeout(std::time::Duration::from_millis(100), notified).await;
	cancelled.cancel();
	handle.await.unwrap();
	assert!(notification.is_err(), "unchanged pending coverage is not a newly queued job");
	assert_campaign_allocations(&db, repo, campaign);
	let queued: Vec<_> =
		common::jobs(&db, repo).into_iter().filter(|job| job.state == JobState::Queued).collect();
	assert!(queued.is_empty(), "only a winning first claim may create coverage work");
	common::with_repo(&db, repo, |scope| {
		assert_eq!(
			campaigns::get(scope, campaign)?.unwrap().state,
			campaigns::State::Active,
			"no worker is not a completion condition"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn open_pins_only_known_commits_and_freezes_policy() {
	for pinned in [false, true] {
		let db = loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())
			.unwrap();
		let repo = common::register_repo(&db, &common::new_repo(), None);
		common::with_repo(&db, repo, |scope| {
			let policy = ReviewPolicy {
				campaign_max_jobs: 9,
				survey_token_budget: Some(123),
				..ReviewPolicy::default()
			};
			let value = common::marked::operator::text(if pinned { SHA } else { "main" });
			let reference =
				if pinned { RequestedRef::Pinned(&value) } else { RequestedRef::Branch(&value) };
			let (campaign, job) =
				created(campaign::open(scope, &request(reference), &policy, 100)?);
			let row = campaigns::get(scope, campaign)?.unwrap();
			assert_eq!(row.recipe, campaigns::Recipe::Bootstrap);
			assert_eq!(row.deadline_at, Some(21700));
			assert_eq!(
				serde_json::from_str::<serde_json::Value>(row.effective_policy.expose()).unwrap(),
				serde_json::to_value(policy.snapshot_v2().unwrap()).unwrap()
			);
			assert_eq!(row.generation_id.is_some(), pinned);
			let job = jobs::get(scope, job)?.unwrap();
			assert_eq!(job.kind, JobKind::Survey);
			assert_eq!(job.generation_id, row.generation_id);
			assert_eq!(job.workflow_contract_version, Some(WORKFLOW_CONTRACT_VERSION));
			assert_eq!(job.token_budget, Some(123));
			assert_eq!(job.state, JobState::Queued);
			Ok(())
		})
		.unwrap();
	}
}
