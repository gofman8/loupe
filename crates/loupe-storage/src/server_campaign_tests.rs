use loupe_core::text::policy::Payload;
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
use loupe_storage::{campaigns, generations, jobs, transaction, Conflict, Db, Error};

use crate::admission_policy::CampaignPolicyV2 as ReviewPolicy;
use crate::campaign_workflow::{KindHint, OpenCampaign, Opened, RequestedRef};
use crate::server_campaign_support as common;
use crate::server_campaign_support::campaign;

#[path = "server_campaign_v2_tests.rs"]
mod v2;

#[path = "server_campaign_maintenance_tests.rs"]
mod maintenance;

// Pinning only accepts complete object ids, so fixtures use full SHA-1s.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OLD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NEW: &str = "cccccccccccccccccccccccccccccccccccccccc";
const DIFFERENT: &str = "dddddddddddddddddddddddddddddddddddddddd";
const OTHER: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn fixture() -> Db {
	let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| {
		c.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		Ok(())
	}).unwrap();
	db
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

fn created(opened: Opened) -> (i64, i64) {
	match opened {
		Opened::Created { campaign_id, job_id } => (campaign_id, job_id),
		other => panic!("expected a new campaign: {other:?}"),
	}
}

fn assert_campaign_allocations(
	conn: &rusqlite::Connection, campaign: i64, expected_jobs: i64, expected_spent: i64,
) -> loupe_storage::Result<()> {
	let jobs: i64 =
		conn.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [campaign], |row| {
			row.get(0)
		})?;
	let spent: i64 = conn.query_row(
		"SELECT general_spent+urgent_spent+verification_spent FROM campaign_admission_spending WHERE campaign_id=?1",
		[campaign], |row| row.get(0),
	)?;
	assert_eq!((jobs, spent), (expected_jobs, expected_spent), "campaign {campaign} allocations");
	Ok(())
}

pub(crate) fn ready(tx: &rusqlite::Transaction<'_>, generation: i64) -> loupe_storage::Result<()> {
	use loupe_core::inventory_manifest::{ManifestEntry, ManifestHasher};
	use rusqlite::OptionalExtension;
	let repo: i64 = tx.query_row(
		"SELECT repo_id FROM review_generations WHERE generation_id=?1",
		[generation],
		|row| row.get(0),
	)?;
	generations::set_profile(
		&crate::test_support::scope(tx, repo),
		generation,
		1,
		&common::marked::agent::json::<Payload>("{}"),
	)?;
	let commit =
		generations::get(&crate::test_support::scope(tx, repo), generation)?.unwrap().commit_sha;
	let entry = crate::test_support::worker("synthetic manifest", |_, mark| {
		ManifestEntry::new(mark, b"src.rs", 0o100644, SHA)
	})
	.unwrap();
	let mut manifest = ManifestHasher::new(commit.expose(), 1).unwrap();
	manifest.push(&entry).unwrap();
	let bytes = manifest.bytes();
	let digest = manifest.finish().unwrap();
	tx.execute(
		"UPDATE review_generations SET inventory_digest=?2 WHERE generation_id=?1",
		rusqlite::params![generation, digest.as_slice()],
	)?;
	let owner: Option<i64> = tx
		.query_row(
			"SELECT id FROM jobs WHERE generation_id=?1 AND repo_id=?2 ORDER BY id LIMIT 1",
			rusqlite::params![generation, repo],
			|r| r.get(0),
		)
		.optional()?;
	let owner = if let Some(owner) = owner {
		owner
	} else {
		tx.execute("INSERT INTO jobs(repo_id,kind,state,generation_id,enqueued_at,workflow_contract_version) VALUES(?1,'survey','succeeded',?2,0,?3)",rusqlite::params![repo,generation,WORKFLOW_CONTRACT_VERSION])?;
		tx.last_insert_rowid()
	};
	// A ready baseline includes the immutable manifest seal, not just its digest.
	tx.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,received_canonical_bytes,expected_digest,created_at,sealed_at) VALUES(?1,1,?2,1,1,?3,?4,0,0)",rusqlite::params![generation,owner,bytes,digest.as_slice()])?;
	tx.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,manifest_position,git_mode,blob_sha,entry_kind,disposition,disposition_reason,created_at) VALUES(?1,'src.rs','src.rs',?2,0,33188,?3,'tracked','context','fixture source',0)",rusqlite::params![generation,entry.raw_path(),entry.object_id()])?;
	Ok(())
}

fn idle_campaign(
	tx: &rusqlite::Transaction<'_>, repo_id: i64, policy: &ReviewPolicy, now: i64, has_work: bool,
) -> loupe_storage::Result<(i64, i64)> {
	let reference = common::marked::operator::text(SHA);
	let new = request(RequestedRef::Pinned(&reference));
	let (campaign_id, job_id) =
		created(campaign::open(&crate::test_support::scope(tx, repo_id), &new, policy, now)?);
	let generation = jobs::get(&crate::test_support::scope(tx, repo_id), job_id)?
		.unwrap()
		.generation_id
		.unwrap();
	ready(tx, generation)?;
	campaign::activate_generation(&crate::test_support::scope(tx, repo_id), campaign_id, now)?;
	tx.execute(
		"UPDATE jobs SET state='succeeded',finished_at=?2,head_sha=?3 WHERE id=?1",
		rusqlite::params![job_id, now, SHA],
	)?;
	if has_work {
		tx.execute(
			"INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,
			 source_refs,priority_band,created_by_job_id,created_at) VALUES(?1,'u','t','o','[{\"path\":\"src.rs\"}]','high',?2,0)",
			rusqlite::params![generation, job_id],
		)?;
	}
	Ok((campaign_id, generation))
}

#[test]
fn open_pins_only_known_commits_and_freezes_policy() {
	for pinned in [false, true] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let policy = ReviewPolicy {
					campaign_max_jobs: 9,
					survey_token_budget: Some(123),
					..ReviewPolicy::default()
				};
				let value = common::marked::operator::text(if pinned { SHA } else { "main" });
				let reference = if pinned {
					RequestedRef::Pinned(&value)
				} else {
					RequestedRef::Branch(&value)
				};
				let (campaign, job) = created(campaign::open(
					&crate::test_support::scope(tx, 1),
					&request(reference),
					&policy,
					100,
				)?);
				let row = campaigns::get(&crate::test_support::scope(tx, 1), campaign)?.unwrap();
				assert_eq!(row.recipe, campaigns::Recipe::Bootstrap);
				assert_eq!(row.deadline_at, Some(21700));
				assert_eq!(
					serde_json::from_str::<serde_json::Value>(row.effective_policy.expose())
						.unwrap(),
					serde_json::to_value(&policy).unwrap()
				);
				assert_eq!(row.generation_id.is_some(), pinned);
				let job = jobs::get(&crate::test_support::scope(tx, 1), job)?.unwrap();
				assert_eq!(job.kind, JobKind::Survey);
				assert_eq!(job.generation_id, row.generation_id);
				assert_eq!(job.workflow_contract_version, Some(WORKFLOW_CONTRACT_VERSION));
				assert_eq!(job.token_budget, Some(123));
				assert_eq!(job.state, JobState::Queued);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn pending_triggers_do_not_write_and_pinned_triggers_coalesce_boundedly() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (campaign, job) = created(campaign::open(
				&crate::test_support::scope(tx, 1),
				&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
				&ReviewPolicy::default(),
				0,
			)?);
			let before = tx.total_changes();
			assert_eq!(
				campaign::open(
					&crate::test_support::scope(tx, 1),
					&request(RequestedRef::Pinned(&common::marked::operator::text(NEW))),
					&ReviewPolicy::default(),
					1
				)?,
				Opened::Pending { campaign_id: campaign }
			);
			assert_eq!(tx.total_changes(), before, "pending must not pretend to persist a trigger");
			let generation = campaign::pin(
				&crate::test_support::scope(tx, 1),
				campaign,
				job,
				&common::marked::repo::text(SHA),
				2,
			)?;
			for at in 0..20 {
				assert_eq!(
					campaign::open(
						&crate::test_support::scope(tx, 1),
						&request(RequestedRef::Pinned(&common::marked::operator::text(&format!(
							"next-{at}"
						)))),
						&ReviewPolicy::default(),
						at + 3
					)?,
					Opened::Coalesced { campaign_id: campaign }
				);
			}
			let follow = generations::get(&crate::test_support::scope(tx, 1), generation)?
				.unwrap()
				.pending_follow_up
				.unwrap();
			let value: serde_json::Value = serde_json::from_str(follow.expose()).unwrap();
			assert_eq!(value["triggers"].as_array().unwrap().len(), 16);
			assert_eq!(value["triggers"][0]["ref"], "next-4");
			assert_eq!(value["newest_ref"], "next-19");
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn coalescing_retains_the_strongest_kind_hint_after_truncation() {
	for full_review in [true, false] {
		let db = fixture();
		let (campaign_id, generation_id) = db
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let (campaign_id, _) = created(campaign::open(
						&crate::test_support::scope(tx, 1),
						&request(RequestedRef::Pinned(&common::marked::operator::text(SHA))),
						&ReviewPolicy::default(),
						0,
					)?);
					let generation_id =
						campaigns::get(&crate::test_support::scope(tx, 1), campaign_id)?
							.unwrap()
							.generation_id
							.unwrap();
					// Older version-1 payloads have no kind hints. Keep them readable.
					generations::set_pending_follow_up(
						&crate::test_support::scope(tx, 1),
						generation_id,
						&common::marked::operator::json::<Payload>(
							r#"{"version":1,"triggers":[{"trigger":"manual","ref":"old","at":0}],"newest_ref":"old"}"#,
						),
					)?;
					Ok((campaign_id, generation_id))
				})
			})
			.unwrap();
		for at in 1..=20 {
			db.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let reference = common::marked::operator::text(&format!("next-{at}"));
					let mut new = request(RequestedRef::Branch(&reference));
					if full_review && at == 1 {
						new.kind_hint = KindHint::FullReview;
					}
					assert_eq!(
						campaign::open(
							&crate::test_support::scope(tx, 1),
							&new,
							&ReviewPolicy::default(),
							at
						)?,
						Opened::Coalesced { campaign_id }
					);
					Ok(())
				})
			})
			.unwrap();
		}
		db.with_conn(|conn| {
			let pending = generations::get(&crate::test_support::scope(conn, 1), generation_id)?
				.unwrap()
				.pending_follow_up
				.unwrap();
			let value: serde_json::Value = serde_json::from_str(pending.expose()).unwrap();
			assert_eq!(
				value["kind_hint"],
				if full_review { "full_review" } else { "incremental" },
				"coalesced review intent must survive trigger-history truncation"
			);
			let triggers = value["triggers"].as_array().unwrap();
			assert_eq!(triggers.len(), 16);
			assert_eq!(triggers[0]["ref"], "next-5");
			assert!(triggers.iter().all(|t| t["kind_hint"] == "incremental"));
			assert_eq!(value["newest_ref"], "next-20");
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn pin_is_idempotent_but_never_changes_an_already_pinned_commit() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (campaign, job) = created(campaign::open(
				&crate::test_support::scope(tx, 1),
				&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
				&ReviewPolicy::default(),
				0,
			)?);
			let generation = campaign::pin(
				&crate::test_support::scope(tx, 1),
				campaign,
				job,
				&common::marked::repo::text(SHA),
				1,
			)?;
			let before = tx.total_changes();
			assert_eq!(
				campaign::pin(
					&crate::test_support::scope(tx, 1),
					campaign,
					job,
					&common::marked::repo::text(SHA),
					2
				)?,
				generation
			);
			assert_eq!(before, tx.total_changes());
			assert!(matches!(
				campaign::pin(
					&crate::test_support::scope(tx, 1),
					campaign,
					job,
					&common::marked::repo::text(DIFFERENT),
					2
				),
				Err(Error::Conflict(Conflict::CampaignPinned))
			));
			assert!(campaign::pin(
				&crate::test_support::scope(tx, 1),
				campaign,
				job + 100,
				&common::marked::repo::text(SHA),
				2
			)
			.is_err());
			tx.execute("UPDATE jobs SET state='failed' WHERE id=?1", [job])?;
			assert!(campaign::pin(
				&crate::test_support::scope(tx, 1),
				campaign,
				job,
				&common::marked::repo::text(SHA),
				2
			)
			.is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn bootstrap_abandons_all_building_leftovers_without_relaxing_retire() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let same = generations::create(
				&crate::test_support::scope(tx, 1),
				&generations::NewGeneration {
					predecessor_generation_id: None,
					commit_sha: &common::marked::repo::text(SHA),
					workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
				},
				0,
			)?;
			ready(tx, same)?;
			let other = generations::create(
				&crate::test_support::scope(tx, 1),
				&generations::NewGeneration {
					predecessor_generation_id: None,
					commit_sha: &common::marked::repo::text(OTHER),
					workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
				},
				0,
			)?;
			assert!(generations::retire(
				&crate::test_support::scope(tx, 1),
				same,
				&common::marked::operator::text("test"),
				1
			)
			.is_err());
			let (campaign, _) = created(campaign::open(
				&crate::test_support::scope(tx, 1),
				&request(RequestedRef::Pinned(&common::marked::operator::text(SHA))),
				&ReviewPolicy::default(),
				2,
			)?);
			let new = campaigns::get(&crate::test_support::scope(tx, 1), campaign)?
				.unwrap()
				.generation_id
				.unwrap();
			assert_ne!(new, same);
			assert_ne!(new, other);
			for id in [same, other] {
				let row = generations::get(&crate::test_support::scope(tx, 1), id)?.unwrap();
				assert_eq!(row.state, generations::State::Retired);
				assert_eq!(row.activated_at, None);
				assert_eq!(row.retired_at, Some(2));
				assert_eq!(row.retired_reason.unwrap().expose(), "superseded bootstrap");
				assert!(generations::abandon(
					&crate::test_support::scope(tx, 1),
					id,
					&common::marked::operator::text("again"),
					3
				)
				.is_err());
			}
			ready(tx, new)?;
			campaign::activate_generation(&crate::test_support::scope(tx, 1), campaign, 3)?;
			assert!(generations::abandon(
				&crate::test_support::scope(tx, 1),
				new,
				&common::marked::operator::text("active"),
				4
			)
			.is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn pin_selects_active_continuation_or_matching_successor() {
	for (active_sha, active_version, reuse_successor, expected_same) in [
		(SHA, WORKFLOW_CONTRACT_VERSION, false, true),
		(OLD, WORKFLOW_CONTRACT_VERSION, false, false),
		(OLD, WORKFLOW_CONTRACT_VERSION, true, false),
		// The pre-framing workflow must not be reused for the same commit.
		(SHA, 1, false, false),
	] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let active = generations::create(
					&crate::test_support::scope(tx, 1),
					&generations::NewGeneration {
						predecessor_generation_id: None,
						commit_sha: &common::marked::repo::text(active_sha),
						workflow_contract_version: active_version,
					},
					0,
				)?;
				ready(tx, active)?;
				generations::activate(&crate::test_support::scope(tx, 1), active, 1)?;
				let successor = if reuse_successor {
					Some(generations::create(
						&crate::test_support::scope(tx, 1),
						&generations::NewGeneration {
							predecessor_generation_id: Some(active),
							commit_sha: &common::marked::repo::text(SHA),
							workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
						},
						1,
					)?)
				} else {
					None
				};
				let (campaign, job) = created(campaign::open(
					&crate::test_support::scope(tx, 1),
					&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
					&ReviewPolicy::default(),
					2,
				)?);
				campaign::pin(
					&crate::test_support::scope(tx, 1),
					campaign,
					job,
					&common::marked::repo::text(SHA),
					2,
				)?;
				let row = campaigns::get(&crate::test_support::scope(tx, 1), campaign)?.unwrap();
				assert_eq!(row.recipe, campaigns::Recipe::Incremental);
				let generation = row.generation_id.unwrap();
				assert_eq!(
					generations::get(&crate::test_support::scope(tx, 1), generation)?
						.unwrap()
						.workflow_contract_version,
					WORKFLOW_CONTRACT_VERSION
				);
				assert_eq!(generation == active, expected_same);
				if let Some(successor) = successor {
					assert_eq!(generation, successor);
				}
				if !expected_same {
					assert_eq!(
						generations::get(&crate::test_support::scope(tx, 1), generation)?
							.unwrap()
							.predecessor_generation_id,
						Some(active)
					);
					assert!(matches!(
						campaign::activate_generation(
							&crate::test_support::scope(tx, 1),
							campaign,
							3
						),
						Err(Error::Conflict(Conflict::GenerationPredecessor))
					));
					assert_eq!(
						generations::get(&crate::test_support::scope(tx, 1), generation)?
							.unwrap()
							.state,
						generations::State::Building
					);
					assert_eq!(
						generations::get(&crate::test_support::scope(tx, 1), active)?
							.unwrap()
							.state,
						generations::State::Active
					);
				}
				assert_campaign_allocations(tx, campaign, 1, 1)?;
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn recipe_selection_uses_only_an_active_baseline() {
	for state in [None, Some("retired"), Some("building"), Some("active")] {
		for hint in [KindHint::Incremental, KindHint::FullReview] {
			let db = fixture();
			db.with_conn(|c|transaction::immediate(c,|tx| {
				if let Some(state)=state {
					tx.execute("INSERT INTO review_generations(repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(1,?2,?1,?3,0)",rusqlite::params![state, SHA, WORKFLOW_CONTRACT_VERSION])?;
				}
				let reference = common::marked::operator::text("main");let mut new=request(RequestedRef::Branch(&reference));new.kind_hint=hint;
				let opened=campaign::open(&crate::test_support::scope(tx,1),&new,&ReviewPolicy::default(),0)?;
				let (campaign,job)=match opened { Opened::Created{campaign_id,job_id}=>(campaign_id,Some(job_id)),Opened::Deferred{campaign_id}=>(campaign_id,None),other=>panic!("new campaign {other:?}") };
				let expected=if state!=Some("active") {campaigns::Recipe::Bootstrap} else if hint==KindHint::FullReview {campaigns::Recipe::Reconciliation} else {campaigns::Recipe::Incremental};
				assert_eq!(campaigns::get(&crate::test_support::scope(tx,1),campaign)?.unwrap().recipe,expected);
				if let Some(job) = job { common::assert_survey_recipe(tx, &jobs::get(&crate::test_support::scope(tx,1), job)?.unwrap(), expected.as_str()); } else { assert_eq!(expected,campaigns::Recipe::Reconciliation); }
				Ok(())
			})).unwrap();
		}
	}
}

#[test]
fn bootstrap_activation_requires_profile_and_inventory() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx| {
		let (campaign,job)=created(campaign::open(&crate::test_support::scope(tx,1),&request(RequestedRef::Pinned(&common::marked::operator::text(SHA))),&ReviewPolicy::default(),0)?);
		let generation=jobs::get(&crate::test_support::scope(tx,1),job)?.unwrap().generation_id.unwrap();
		assert!(campaign::activate_generation(&crate::test_support::scope(tx,1),campaign,1).is_err());
		generations::set_profile(&crate::test_support::scope(tx,1),generation,1,&common::marked::agent::json::<Payload>("{}"))?;
		assert!(campaign::activate_generation(&crate::test_support::scope(tx,1),campaign,1).is_err());
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		campaign::activate_generation(&crate::test_support::scope(tx,1),campaign,1)?;
		assert_eq!(generations::get(&crate::test_support::scope(tx,1),generation)?.unwrap().state,generations::State::Active);
		Ok(())
	})).unwrap();
}

#[test]
fn first_claim_allocates_coverage_with_frozen_budget_after_activation() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let policy = ReviewPolicy {
				campaign_max_jobs: 2,
				campaign_urgent_reserve: 0,
				campaign_verification_reserve: 0,
				..ReviewPolicy::default()
			};
			let (campaign, generation) = idle_campaign(tx, 1, &policy, 0, true)?;
			let worker = loupe_storage::workers::insert(
				tx,
				&common::marked::operator::text("coverage"),
				loupe_storage::workers::WorkerKind::Worker,
				&[9; 32],
				0,
			)?;
			assert_eq!(
				campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 1)?,
				None
			);
			assert_campaign_allocations(tx, campaign, 1, 1)?;
			let req = loupe_storage::admission_candidates::Request {
				worker_id: worker,
				legacy_kinds: &[],
				phase_kinds: &[JobKind::<loupe_provenance::Db>::Survey],
				now: 1,
				policy: &crate::scheduler::ClaimPolicy::default(),
				limit: 1,
			};
			let candidates = loupe_storage::admission_candidates::ranked_raw(tx, &req)?;
			assert_eq!(candidates.len(), 1);
			let outcome = loupe_storage::admission_claim::materialize(
				tx,
				&candidates[0],
				&req,
				&[8; 32],
				900,
			)?;
			let loupe_storage::admission_claim::Outcome::Uncommitted(claimed) = outcome else {
				panic!("winning ordinary work")
			};
			let row = claimed.job;
			assert_eq!(row.kind, JobKind::Survey);
			assert_eq!(row.state, JobState::Leased);
			assert_eq!(row.scheduling_band, Some(loupe_storage::scheduler::Band::High));
			assert_eq!(
				row.continuation_of_job_id, None,
				"ordinary coverage is not a logical continuation"
			);
			let recipe: serde_json::Value =
				serde_json::from_str(row.recipe.unwrap().expose()).unwrap();
			assert_eq!(recipe["recipe"], "coverage");
			assert_eq!(claimed.assigned_units.len(), 1);
			assert_campaign_allocations(tx, campaign, 2, 2)?;
			tx.execute("UPDATE jobs SET state='succeeded',finished_at=2 WHERE id=?1", [row.id])?;
			assert_eq!(
				campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 3)?,
				Some(campaign::Finish::Completed)
			);
			assert_eq!(
				campaigns::get(&crate::test_support::scope(tx, 1), campaign)?
					.unwrap()
					.terminal_reason
					.unwrap()
					.expose(),
				"campaign_budget"
			);
			let generation =
				generations::get(&crate::test_support::scope(tx, 1), generation)?.unwrap();
			assert_eq!(generation.profile_version, 1);
			assert_eq!(generation.activated_at, Some(0));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn cancellation_keeps_leased_children_and_records_a_summary() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx| {
		let (campaign,job)=created(campaign::open(&crate::test_support::scope(tx,1),&request(RequestedRef::Pinned(&common::marked::operator::text(SHA))),&ReviewPolicy::default(),0)?);
		tx.execute("UPDATE jobs SET state='leased' WHERE id=?1",[job])?;
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,enqueued_at) VALUES(1,'survey','queued',?1,1)",[campaign])?;
		let queued=tx.last_insert_rowid();
		campaign::cancel(&crate::test_support::scope(tx,1),campaign,&common::marked::operator::text("operator"),2)?;
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),job)?.unwrap().state,JobState::Leased);
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),queued)?.unwrap().state,JobState::Cancelled);
		let row=campaigns::get(&crate::test_support::scope(tx,1),campaign)?.unwrap();
		assert_eq!(row.state,campaigns::State::Cancelled);
		assert!(row.terminal_counts.is_some());
		assert!(row.coverage_at_finish.is_some());
		Ok(())
	})).unwrap();
}

#[test]
fn idle_campaign_preserves_pending_work_or_snapshots_terminal_counts() {
	for has_work in [true, false] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let (id, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, has_work)?;
				let finish = campaign::try_finish(&crate::test_support::scope(tx, 1), id, 1)?;
				assert_campaign_allocations(tx, id, 1, 1)?;
				let row = campaigns::get(&crate::test_support::scope(tx, 1), id)?.unwrap();
				if has_work {
					assert_eq!(finish, None);
					assert_eq!(row.state, campaigns::State::Active);
					let queued: i64 = tx.query_row(
						"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1 AND state='queued'",
						[id],
						|r| r.get(0),
					)?;
					assert_eq!(
						queued, 0,
						"pending ordinary work is not a speculative queued child"
					);
				} else {
					assert_eq!(finish, Some(campaign::Finish::Completed));
					assert_eq!(row.state, campaigns::State::Finished);
					assert_eq!(row.terminal_reason.unwrap().expose(), "partial");
					assert_eq!(row.coverage_at_finish, Some(generations::Coverage::Unknown));
					let summary: serde_json::Value =
						serde_json::from_str(row.terminal_counts.unwrap().expose()).unwrap();
					assert_eq!(
						summary["jobs"],
						serde_json::json!([{"kind":"survey","state":"succeeded","count":1}])
					);
					let before = tx.total_changes();
					assert_eq!(
						campaign::try_finish(&crate::test_support::scope(tx, 1), id, 2)?,
						None
					);
					assert_eq!(tx.total_changes(), before);
				}
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn deadline_cancels_only_queued_work_and_waits_for_the_leased_child() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let policy = ReviewPolicy { survey_units_per_job: 1, ..ReviewPolicy::default() };
			let (id, generation) = idle_campaign(tx, 1, &policy, 0, true)?;
			tx.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(?1,'second','Second unit','Review boundary','[{\"path\":\"src.rs\"}]',0)",[generation])?;
			let worker=loupe_storage::workers::insert(tx,&common::marked::operator::text("deadline"),loupe_storage::workers::WorkerKind::Worker,&[4;32],0)?;
			let claim_policy=crate::scheduler::ClaimPolicy { active_surveys_per_repo: 2, ..Default::default() };
			let req=loupe_storage::admission_candidates::Request {worker_id:worker,legacy_kinds:&[],phase_kinds:&[JobKind::<loupe_provenance::Db>::Survey],now:1,policy:&claim_policy,limit:1};
			let mut children=Vec::new();
			for capability in 5..7 {
				let candidate=loupe_storage::admission_candidates::ranked_raw(tx,&req)?.remove(0);
				let loupe_storage::admission_claim::Outcome::Uncommitted(claimed)=loupe_storage::admission_claim::materialize(tx,&candidate,&req,&[capability;32],22000)? else {panic!("coverage claim")};
				assert_eq!(claimed.assigned_units.len(),1);
				children.push(claimed.job.id);
			}
			let (leased,queued)=(children[0],children[1]);
			assert_campaign_allocations(tx, id, 3, 3)?;
			// A real execution retry retains its original charge and exact assignment.
			tx.execute("UPDATE jobs SET state='queued',worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,eligible_at=21600 WHERE id=?1",[queued])?;
			assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1), id, 21599)?, None);
			assert_eq!(jobs::get(&crate::test_support::scope(tx,1), queued)?.unwrap().state, JobState::Queued);
			assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1), id, 21600)?, None);
			let cancelled = jobs::get(&crate::test_support::scope(tx,1), queued)?.unwrap();
			assert_eq!(cancelled.state, JobState::Cancelled);
			assert_eq!(cancelled.error.as_ref().map(|v| v.expose()), Some("campaign_deadline"));
			assert_eq!(jobs::get(&crate::test_support::scope(tx,1), leased)?.unwrap().state, JobState::Leased);
			assert_campaign_allocations(tx, id, 3, 3)?;
			tx.execute("UPDATE jobs SET state='succeeded',finished_at=21601 WHERE id=?1", [leased])?;
			assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1), id, 21601)?, Some(campaign::Finish::DeadlineReached));
			let row = campaigns::get(&crate::test_support::scope(tx,1), id)?.unwrap();
			assert_eq!(row.terminal_reason.unwrap().expose(), "deadline");
			assert!(row.terminal_counts.is_some());
			assert!(row.coverage_at_finish.is_some());
			assert_campaign_allocations(tx, id, 3, 3)?;
			Ok(())
		})
	}).unwrap();
}

#[test]
fn tick_without_active_campaigns_performs_no_writes() {
	let db = fixture();
	let before = db.with_conn(|c| Ok(c.total_changes())).unwrap();
	assert_eq!(campaign::tick(&db, 1).unwrap(), campaign::TickReport::default());
	assert_eq!(db.with_conn(|c| Ok(c.total_changes())).unwrap(), before);
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (id, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			campaign::try_finish(&crate::test_support::scope(tx, 1), id, 1)?;
			Ok(())
		})
	})
	.unwrap();
	let before = db.with_conn(|c| Ok(c.total_changes())).unwrap();
	assert_eq!(campaign::tick(&db, 2).unwrap(), campaign::TickReport::default());
	assert_eq!(db.with_conn(|c| Ok(c.total_changes())).unwrap(), before);
}

#[test]
fn tick_reports_budget_exhaustion_once_without_claiming_complete_coverage() {
	let db = fixture();
	let id = db
		.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let policy = ReviewPolicy {
					campaign_max_jobs: 1,
					campaign_urgent_reserve: 0,
					campaign_verification_reserve: 0,
					..ReviewPolicy::default()
				};
				let (id, _) = idle_campaign(tx, 1, &policy, 0, true)?;
				Ok(id)
			})
		})
		.unwrap();
	let report = campaign::tick(&db, 1).unwrap();
	assert_eq!(report.completed, 1);
	assert_eq!(report.budget_exhausted, 1);
	db.with_conn(|c| {
		assert_campaign_allocations(c, id, 1, 1)?;
		let row = campaigns::get(&crate::test_support::scope(c, 1), id)?.unwrap();
		assert_eq!(row.coverage_at_finish, Some(generations::Coverage::Unknown));
		assert_eq!(row.state, campaigns::State::Finished);
		Ok(())
	})
	.unwrap();
	assert_eq!(campaign::tick(&db, 2).unwrap(), campaign::TickReport::default());
	db.with_conn(|c| assert_campaign_allocations(c, id, 1, 1)).unwrap();
}

#[test]
fn tick_rolls_back_a_failed_campaign_and_still_processes_other_repositories() {
	let db = fixture();
	let (first, second) = db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (first, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(2,'v','github.com','o','r2','{\"kind\":\"manual\"}',0)", [])?;
			let (second, _) = idle_campaign(tx, 2, &ReviewPolicy::default(), 0, false)?;
			tx.execute_batch("CREATE TEMP TRIGGER reject_first_campaign BEFORE UPDATE OF state ON review_campaigns WHEN NEW.repo_id=1 BEGIN SELECT RAISE(ABORT,'injected campaign failure'); END")?;
			Ok((first, second))
		})
	}).unwrap();
	let report = campaign::tick(&db, 1).unwrap();
	assert_eq!(report.failed, 1);
	assert_eq!(report.completed, 1);
	db.with_conn(|c| {
		assert_eq!(
			campaigns::get(&crate::test_support::scope(c, 1), first)?.unwrap().state,
			campaigns::State::Active
		);
		assert_eq!(
			campaigns::get(&crate::test_support::scope(c, 2), second)?.unwrap().state,
			campaigns::State::Finished
		);
		assert_campaign_allocations(c, first, 1, 1)?;
		assert_campaign_allocations(c, second, 1, 1)?;
		c.execute_batch("DROP TRIGGER reject_first_campaign")?;
		Ok(())
	})
	.unwrap();
	let report = campaign::tick(&db, 2).unwrap();
	assert_eq!(report.failed, 0);
	assert_eq!(report.completed, 1);
	db.with_conn(|c| {
		assert_eq!(
			campaigns::get(&crate::test_support::scope(c, 1), first)?.unwrap().state,
			campaigns::State::Finished
		);
		assert_campaign_allocations(c, first, 1, 1)?;
		assert_campaign_allocations(c, second, 1, 1)
	})
	.unwrap();
}

#[test]
fn pin_accepts_only_full_lowercase_hex_commit_ids() {
	// The pinned commit arrives from the worker's checkout checkpoint,
	// so it is boundary input: only a complete SHA-1 or SHA-256 object id
	// may reach `target_commit_sha` and generation selection.
	let sha1 = "0123456789abcdef0123456789abcdef01234567";
	let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	for good in [sha1, sha256] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let (campaign, job) = created(campaign::open(
					&crate::test_support::scope(tx, 1),
					&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
					&ReviewPolicy::default(),
					0,
				)?);
				for bad in [
					"main",
					"sha",
					"ABCDEF0123456789ABCDEF0123456789ABCDEF01",
					&"a".repeat(39),
					&"a".repeat(41),
					&format!("{}\n", "a".repeat(39)),
					&"g".repeat(40),
				] {
					match common::marked::repo::try_text(bad) {
						Ok(revision) => {
							let outcome = campaign::pin(
								&crate::test_support::scope(tx, 1),
								campaign,
								job,
								&revision,
								1,
							);
							assert!(
								matches!(outcome, Err(Error::Validation(_))),
								"{bad:?} → {outcome:?}"
							);
						},
						Err(error) => {
							// Newlines are rejected by field validation before this API.
							assert!(bad.ends_with('\n'));
							assert_eq!(error.field, "revision");
							assert_eq!(error.rule, loupe_core::text::Rule::Character);
							assert_eq!(error.code_point, Some(10));
						},
					}
				}
				let row = campaigns::get(&crate::test_support::scope(tx, 1), campaign)?.unwrap();
				assert!(row.generation_id.is_none());
				assert_eq!(row.target_commit_sha.expose(), "main");
				campaign::pin(
					&crate::test_support::scope(tx, 1),
					campaign,
					job,
					&common::marked::repo::text(good),
					1,
				)?;
				assert_eq!(
					campaigns::get(&crate::test_support::scope(tx, 1), campaign)?
						.unwrap()
						.target_commit_sha
						.expose(),
					good
				);
				Ok(())
			})
		})
		.unwrap();
	}
}
