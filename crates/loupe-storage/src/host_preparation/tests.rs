use loupe_core::inventory_manifest::{self, ManifestHasher};
use loupe_core::review_metadata::ReviewCommit;
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::WORKFLOW_CONTRACT_VERSION;
use loupe_provenance::Worker;
use rusqlite::params;

use super::*;
use crate::jobs::LeaseIdentity;
use crate::review_authority::{with_phase_transaction, Access, Context, Phase, PolicyDecision};
use crate::secrets::MasterKey;
use crate::{inventory, review_tests, Db, Error, Result};

const SHA: &str = "1111111111111111111111111111111111111111";
const CAP: [u8; 32] = [7; 32];

fn identity() -> LeaseIdentity<'static> {
	LeaseIdentity { job_id: 101, worker_id: 1, capability_hash: &CAP }
}
fn policy(_: Phase, _: Access, context: &Context) -> Result<Option<PolicyDecision>> {
	Ok(Some(if context.campaign_recipe == crate::campaigns::Recipe::Bootstrap {
		PolicyDecision::Bootstrap
	} else {
		PolicyDecision::Ordinary
	}))
}
fn seed(db: &Db) {
	review_tests::seed(db);
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'host','worker',zeroblob(32),0);
		 UPDATE review_generations SET state='building' WHERE generation_id=11;
		 UPDATE review_campaigns SET deadline_at=1000 WHERE campaign_id=1;
		 UPDATE jobs SET state='leased',worker_id=1,attempts=1,lease_expires_at=100,hard_deadline_at=90,
		 recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"bootstrap\",\"assignment_key\":\"ordinary\"}' WHERE id=101;")?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,workflow_contract_version=?2 WHERE generation_id=11", params![SHA,WORKFLOW_CONTRACT_VERSION])?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1 WHERE campaign_id=1", [SHA])?;
		conn.execute("UPDATE jobs SET job_capability_hash=?1,workflow_contract_version=?2 WHERE id=101", params![CAP.as_slice(),WORKFLOW_CONTRACT_VERSION])?;
		Ok(())
	}).unwrap();
}
fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}
fn commit(raw: &str) -> ReviewCommit<Worker> {
	crate::test_support::worker(raw, |raw, mark| ReviewCommit::new(mark, raw)).unwrap()
}
fn prepare_at(db: &Db, identity: LeaseIdentity<'_>, now: i64) -> Result<()> {
	with_phase_transaction(
		db,
		identity,
		|| now,
		|tx| {
			assert!(matches!(
				tx.pin_target(&commit(SHA), &[3; 32], policy)?,
				PinOutcome::Prepared(_)
			));
			Ok(())
		},
	)
}
fn prepare(db: &Db) {
	prepare_at(db, identity(), 10).unwrap();
}
fn host_at<T>(
	db: &Db, identity: LeaseIdentity<'_>, now: i64,
	body: impl FnOnce(&PhaseScope<'_, '_>) -> Result<T>,
) -> Result<T> {
	with_phase_transaction(
		db,
		identity,
		|| now,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::PreparedHost, |context| {
					policy(Phase::Survey, Access::PreparedHost, context)
				})?
				.ok_or(Error::ScopeDenied)?;
			body(&scope)
		},
	)
}
fn host<T>(db: &Db, body: impl FnOnce(&PhaseScope<'_, '_>) -> Result<T>) -> Result<T> {
	host_at(db, identity(), 10, body)
}
fn mode_entry(path: &[u8], mode: u32, oid: &str) -> ManifestEntry<Worker> {
	crate::test_support::worker("synthetic manifest", |_, mark| {
		ManifestEntry::new(mark, path, mode, oid)
	})
	.unwrap()
}
fn entry(path: &[u8]) -> ManifestEntry<Worker> {
	mode_entry(path, 0o100644, &"22".repeat(20))
}
fn digest(entries: &[ManifestEntry<Worker>]) -> [u8; 32] {
	let mut hasher = ManifestHasher::new(SHA, entries.len() as u64).unwrap();
	for entry in entries {
		hasher.push(entry).unwrap();
	}
	hasher.finish().unwrap()
}
fn ingest(db: &Db, entries: &[ManifestEntry<Worker>]) {
	prepare(db);
	host(db, |scope| {
		scope.declare_manifest(entries.len() as u64, &digest(entries))?;
		scope.upload_manifest(0, entries)?;
		scope.seal_manifest()?;
		Ok(())
	})
	.unwrap();
}
fn inventory(db: &Db) -> Vec<inventory::Entry> {
	db.with_conn(|conn| inventory::list(&crate::test_support::scope(conn, 1), 11)).unwrap()
}

#[test]
fn campaign_summary_filters_repository_before_decoding_foreign_content() {
	for column in ["effective_policy", "target_commit_sha"] {
		let db = fixture();
		db.with_conn(|conn| {
			conn.execute(
				&format!("UPDATE review_campaigns SET {column}=x'ff' WHERE campaign_id=2"),
				[],
			)?;
			let foreign = crate::campaigns::summarize(&crate::test_support::scope(conn, 1), 2);
			assert!(
				matches!(foreign, Err(Error::NotFound(crate::Entity::Campaign, 2))),
				"repository scope must exclude foreign malformed content before decoding"
			);
			let owned = crate::campaigns::summarize(&crate::test_support::scope(conn, 2), 2);
			assert!(
				owned.is_ok(),
				"metadata-only summary must not decode unrelated corrupt campaign content"
			);
			let owned = crate::campaigns::get(&crate::test_support::scope(conn, 2), 2);
			assert!(owned.is_err(), "the content reader must still reject corrupt stored content");
			assert!(
				!matches!(owned, Err(Error::NotFound(..))),
				"the owning row exists and must reach admission"
			);
			Ok(())
		})
		.unwrap();
	}
}

fn ordinary(db: &Db) {
	db.with_conn(|conn| {
		let campaign_policy = serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap();
		conn.execute("UPDATE review_campaigns SET recipe='incremental',effective_policy=?1 WHERE campaign_id=1",[campaign_policy])?;
		conn.execute("UPDATE review_generations SET state='active',profile_version=1,generated_profile='{}',generated_profile_digest=?1,generated_profile_source='agent' WHERE generation_id=11",[loupe_core::canonical::digest(b"{}").as_slice()])?;
		conn.execute_batch("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=101;
		 INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,0,zeroblob(32),0,1);
		 INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_at) VALUES(31,11,'first','title','objective','[]',3,0);")?;
		Ok(())
	}).unwrap();
}

#[test]
fn ordinary_pin_initializes_exact_batch_once_before_returning_scope() {
	let db = fixture();
	ordinary(&db);
	for repeat in [false, true] {
		with_phase_transaction(
			&db,
			identity(),
			|| 10,
			|tx| {
				let PinOutcome::Prepared(scope) = tx.pin_target(&commit(SHA), &[3; 32], policy)?
				else {
					panic!("ordinary checkout must prepare")
				};
				assert!(
					scope.survey_unit(31, 4)?,
					"ordinary pin must assign the batch before returning its scope"
				);
				Ok::<_, Error>(())
			},
		)
		.unwrap();
		db.with_conn(|conn| {
			assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=101",[],|row|row.get::<_,i64>(0))?,1);
			if !repeat {
				conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(32,11,'later','title','objective','[]',1)")?;
			}
			Ok(())
		}).unwrap();
	}
}

#[test]
fn empty_ordinary_pin_batch_is_not_refilled_on_retry() {
	let db = fixture();
	ordinary(&db);
	db.with_conn(|conn| {
		conn.execute("DELETE FROM review_units WHERE review_unit_id=31", [])?;
		Ok(())
	})
	.unwrap();
	prepare(&db);
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(32,11,'later','title','objective','[]',1)")?;
		Ok(())
	}).unwrap();
	prepare_at(&db, identity(), 11).unwrap();
	db.with_conn(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=101",[],|row|row.get::<_,i64>(0))?,0);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101 AND operation='initialize_survey_batch'",[],|row|row.get::<_,i64>(0))?,1);
		Ok(())
	}).unwrap();
}

// debug-ok: callback failures are two closed categories with no caller data.
#[derive(Debug, PartialEq, Eq)]
enum CallbackError {
	Storage,
	Render,
}
impl From<Error> for CallbackError {
	fn from(_: Error) -> Self {
		Self::Storage
	}
}

#[test]
fn response_callback_errors_roll_back_host_publication_and_new_successor() {
	let db = fixture();
	let result: std::result::Result<(), CallbackError> = with_phase_transaction(
		&db,
		identity(),
		|| 10,
		|tx| {
			let PinOutcome::Prepared(scope) = tx.pin_target(&commit(SHA), &[3; 32], policy)? else {
				panic!("bootstrap prepares")
			};
			scope.declare_manifest(0, &digest(&[]))?;
			scope.seal_manifest()?;
			scope.publish_profile(&crate::test_support::json("{}").unwrap())?;
			Err(CallbackError::Render)
		},
	);
	assert_eq!(result, Err(CallbackError::Render));
	db.with_conn(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM generation_manifests WHERE generation_id=11",[],|row|row.get::<_,i64>(0))?,0);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101",[],|row|row.get::<_,i64>(0))?,0);
		assert!(conn.query_row("SELECT prepared_at IS NULL AND head_sha IS NULL FROM jobs WHERE id=101",[],|row|row.get::<_,bool>(0))?);
		assert!(conn.query_row("SELECT generated_profile IS NULL AND generated_profile_digest IS NULL AND inventory_digest IS NULL FROM review_generations WHERE generation_id=11",[],|row|row.get::<_,bool>(0))?);
		Ok(())
	}).unwrap();
	successor(&db, None);
	db.with_conn(|conn| {
		conn.execute("DELETE FROM review_generations WHERE generation_id=12", [])?;
		Ok(())
	})
	.unwrap();
	let result: std::result::Result<(), CallbackError> = with_phase_transaction(
		&db,
		identity(),
		|| 10,
		|tx| {
			assert!(matches!(
				tx.pin_target(&commit(&"33".repeat(20)), &[3; 32], policy)?,
				PinOutcome::Deferred { .. }
			));
			Err(CallbackError::Render)
		},
	);
	assert_eq!(result, Err(CallbackError::Render));
	db.with_conn(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM review_generations WHERE repo_id=1",[],|row|row.get::<_,i64>(0))?,1);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_terminal_receipts",[],|row|row.get::<_,i64>(0))?,0);
		assert!(conn.query_row("SELECT generation_id IS NULL AND state='leased' AND job_capability_hash IS NOT NULL AND finished_at IS NULL FROM jobs WHERE id=101",[],|row|row.get::<_,bool>(0))?);
		assert!(conn.query_row("SELECT generation_id IS NULL AND state='active' AND target_commit_sha='refs/heads/requested' FROM review_campaigns WHERE campaign_id=1",[],|row|row.get::<_,bool>(0))?);
		Ok(())
	}).unwrap();
}

#[test]
fn confirmation_is_shared_by_child_phases_and_keeps_exact_attempt_binding() {
	for phase in [Phase::Drilldown, Phase::Verify] {
		let db = fixture();
		ordinary(&db);
		db.with_conn(|conn| {
			conn.execute_batch("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(41,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0);
			 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at,report_identity) VALUES(51,1,101,'test','high','title','description','f',0,x'11111111111111111111111111111111');")?;
			conn.execute("UPDATE jobs SET kind=?1,assigned_lead_id=?2,target_finding_id=?3 WHERE id=101",params![phase.job_kind().as_str(),(phase==Phase::Drilldown).then_some(41),(phase==Phase::Verify).then_some(51)])?;
			Ok(())
		}).unwrap();
		assert!(with_phase_transaction(
			&db,
			identity(),
			|| 10,
			|tx| tx.pin_target(&commit(&"33".repeat(20)), &[3; 32], policy).map(|_| ())
		)
		.is_err());
		prepare(&db);
		prepare_at(&db, identity(), 11).unwrap();
		db.with_conn(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT prepared_at,prepared_attempt FROM jobs WHERE id=101",
					[],
					|row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
				)?,
				(10, 1)
			);
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=101",
					[],
					|row| row.get::<_, i64>(0)
				)?,
				0,
				"child pin must not initialize a Survey batch"
			);
			conn.execute(
				"UPDATE jobs SET attempts=2,job_capability_hash=?1 WHERE id=101",
				[[8u8; 32].as_slice()],
			)?;
			Ok(())
		})
		.unwrap();
		assert!(prepare_at(&db, identity(), 12).is_err());
		let next = LeaseIdentity { capability_hash: &[8; 32], ..identity() };
		with_phase_transaction(
			&db,
			next,
			|| 12,
			|tx| {
				assert!(tx
					.authorize(phase, Access::Domain, |context| policy(
						phase,
						Access::Domain,
						context
					))?
					.is_none());
				let PinOutcome::Prepared(scope) = tx.pin_target(&commit(SHA), &[3; 32], policy)?
				else {
					panic!("child checkout must prepare")
				};
				assert_eq!(scope.job().phase, phase);
				assert_eq!(scope.assigned_lead(41)?, phase == Phase::Drilldown);
				assert_eq!(scope.assigned_finding(51)?, phase == Phase::Verify);
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
}

fn successor(db: &Db, prior: Option<&str>) {
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE review_generations SET state='active' WHERE generation_id=11;
		 UPDATE review_campaigns SET recipe='incremental',generation_id=NULL,target_commit_sha='refs/heads/requested' WHERE campaign_id=1;
		 UPDATE jobs SET generation_id=NULL WHERE id=101;
		 UPDATE jobs SET state='cancelled' WHERE id=102;")?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,workflow_contract_version=?2,pending_follow_up=?3 WHERE generation_id=12",params!["33".repeat(20),WORKFLOW_CONTRACT_VERSION,prior])?;
		Ok(())
	}).unwrap();
}
fn defer(db: &Db) -> Result<()> {
	with_phase_transaction(
		db,
		identity(),
		|| 10,
		|tx| {
			let PinOutcome::Deferred { receipt, commit } =
				tx.pin_target(&commit(&"33".repeat(20)), &[3; 32], policy)?
			else {
				panic!("successor must defer")
			};
			assert_eq!(receipt.terminal_reason.expose(), "unsupported_recipe");
			assert_eq!(commit.expose(), "33".repeat(20));
			Ok(())
		},
	)
}

#[test]
fn successor_deferral_preserves_prior_state_and_replays_after_generation_purge() {
	let db = fixture();
	successor(
		&db,
		Some(r#"{"prior":{"unknown":true},"triggers":[1],"unsupported_review":{"replace":true}}"#),
	);
	defer(&db).unwrap();
	db.with_conn(|conn| {
		let raw:String=conn.query_row("SELECT pending_follow_up FROM review_generations WHERE generation_id=12",[],|row|row.get(0))?;
		let follow:serde_json::Value=serde_json::from_str(&raw).unwrap();
		assert_eq!(follow["prior"]["unknown"],true);
		assert_eq!(follow["triggers"],serde_json::json!([1]));
		assert_eq!(follow["unsupported_review"]["requested_ref"],"refs/heads/requested");
		assert!(follow["unsupported_review"].get("replace").is_none());
		assert_eq!(conn.query_row("SELECT state,terminal_reason FROM review_campaigns WHERE campaign_id=1",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?,("finished".to_owned(),"unsupported_recipe".to_owned()));
		assert!(conn.query_row("SELECT state='cancelled' AND job_capability_hash IS NULL AND lease_expires_at IS NULL AND prepared_at IS NULL FROM jobs WHERE id=101",[],|row|row.get::<_,bool>(0))?);
		conn.execute_batch("DELETE FROM review_generations WHERE generation_id=12;
		 UPDATE jobs SET recipe=x'ff',head_sha=x'ff',workflow_contract_version=x'ff',hard_deadline_at=x'ff' WHERE id=101;
		 UPDATE review_campaigns SET effective_policy=x'ff',target_commit_sha=x'ff' WHERE campaign_id=1;")?;
		Ok(())
	}).unwrap();
	with_phase_transaction(
		&db,
		identity(),
		|| i64::MAX,
		|tx| {
			let PinReplay::Receipt { receipt, commit: resolved } =
				tx.replay_pin_target(&commit(&"33".repeat(20)), &[3; 32])?
			else {
				panic!("exact terminal replay must survive purged live context")
			};
			assert_eq!(resolved.expose(), "33".repeat(20));
			let audit: serde_json::Value =
				serde_json::from_str(receipt.effective_recipe.expose()).unwrap();
			assert_eq!(audit["requested_ref"], "refs/heads/requested");
			assert_eq!(audit["resolved_commit"], resolved.expose());
			assert!(matches!(
				tx.replay_pin_target(&commit(&"33".repeat(20)), &[4; 32])?,
				PinReplay::Reject(crate::terminal_receipt::Reject::WrongDigest)
			));
			Ok::<_, Error>(())
		},
	)
	.unwrap();
	for identity in [
		LeaseIdentity { worker_id: 2, ..identity() },
		LeaseIdentity { capability_hash: &[8; 32], ..identity() },
	] {
		with_phase_transaction(
			&db,
			identity,
			|| i64::MAX,
			|tx| {
				assert!(matches!(
					tx.replay_pin_target(&commit(&"33".repeat(20)), &[4; 32])?,
					PinReplay::Reject(crate::terminal_receipt::Reject::Denied)
				));
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
}

#[test]
fn invalid_or_oversized_successor_composition_rolls_back_every_mutation() {
	let large = serde_json::json!({"prior":"p".repeat(65400)}).to_string();
	for prior in ["[]", large.as_str()] {
		let db = fixture();
		successor(&db, Some(prior));
		assert!(defer(&db).is_err(), "invalid or aggregate-oversized follow-up must fail");
		db.with_conn(|conn| {
			assert!(conn.query_row("SELECT generation_id IS NULL AND state='leased' AND job_capability_hash IS NOT NULL AND finished_at IS NULL FROM jobs WHERE id=101",[],|row|row.get::<_,bool>(0))?);
			assert!(conn.query_row("SELECT generation_id IS NULL AND state='active' AND target_commit_sha='refs/heads/requested' FROM review_campaigns WHERE campaign_id=1",[],|row|row.get::<_,bool>(0))?);
			assert_eq!(conn.query_row("SELECT pending_follow_up FROM review_generations WHERE generation_id=12",[],|row|row.get::<_,String>(0))?,prior);
			assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_terminal_receipts",[],|row|row.get::<_,i64>(0))?,0);
			Ok(())
		}).unwrap();
	}
}

#[test]
fn pin_checks_post_resolution_policy_and_rolls_back_confirmation_on_rejection() {
	let db = fixture();
	let calls = std::cell::RefCell::new(Vec::new());
	let result: Result<()> = with_phase_transaction(
		&db,
		identity(),
		|| 10,
		|tx| {
			tx.pin_target(&commit(SHA), &[3; 32], |phase, access, context| {
				calls.borrow_mut().push((phase, access));
				if access == Access::Checkout {
					policy(phase, access, context)
				} else {
					Ok(None)
				}
			})?;
			Ok(())
		},
	);
	assert!(result.is_err());
	assert_eq!(
		*calls.borrow(),
		vec![(Phase::Survey, Access::Checkout), (Phase::Survey, Access::PreparedHost)]
	);
	db.with_conn(|conn| {
		assert!(conn.query_row(
			"SELECT prepared_at IS NULL AND head_sha IS NULL FROM jobs WHERE id=101",
			[],
			|row| row.get::<_, bool>(0)
		)?);
		Ok(())
	})
	.unwrap();
}

#[test]
fn confirmation_is_exact_attempt_bound_and_keeps_first_confirmation_time() {
	let db = fixture();
	assert!(with_phase_transaction(
		&db,
		identity(),
		|| 10,
		|tx| tx.pin_target(&commit(&"33".repeat(20)), &[3; 32], policy).map(|_| ())
	)
	.is_err());
	prepare(&db);
	prepare_at(&db, identity(), 11).unwrap();
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT prepared_attempt,prepared_at,head_sha FROM jobs WHERE id=101",
				[],
				|r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
			)?,
			(1, 10, SHA.to_owned())
		);
		conn.execute(
			"UPDATE jobs SET attempts=2,job_capability_hash=?1 WHERE id=101",
			[[8u8; 32].as_slice()],
		)?;
		Ok(())
	})
	.unwrap();
	assert!(prepare_at(&db, identity(), 12).is_err());
	let next = LeaseIdentity { capability_hash: &[8; 32], ..identity() };
	assert!(host_at(&db, next, 12, |scope| scope.declare_manifest(0, &digest(&[]))).is_err());
	prepare_at(&db, next, 12).unwrap();
	assert!(host_at(&db, next, 12, |scope| scope.declare_manifest(0, &digest(&[]))).is_ok());
}

#[test]
fn uploads_require_preparation_owner_and_unexpired_analysis_window() {
	let db = fixture();
	assert!(host(&db, |scope| scope.declare_manifest(0, &digest(&[]))).is_err());
	for sql in [
		"UPDATE workers SET revoked_at=9 WHERE id=1",
		"UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1",
		"UPDATE review_campaigns SET deadline_at=10 WHERE campaign_id=1",
		"UPDATE jobs SET hard_deadline_at=10 WHERE id=101",
		"UPDATE review_generations SET state='active' WHERE generation_id=11",
	] {
		let db = fixture();
		prepare(&db);
		db.with_conn(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap();
		assert!(
			host(&db, |scope| scope.declare_manifest(0, &digest(&[]))).is_err(),
			"must reject {sql}"
		);
	}
}

#[test]
fn lossless_multichunk_manifest_replays_and_survives_restart() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("host.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	prepare(&db);
	let entries = vec![
		entry(b"bad%FF.rs"),
		entry(b"bad\xff.rs"),
		mode_entry(b"submodule", 0o160000, &"22".repeat(20)),
		mode_entry(b"symlink", 0o120000, &"22".repeat(20)),
	];
	host(&db, |scope| {
		scope.declare_manifest(4, &digest(&entries))?;
		assert_eq!(scope.upload_manifest(0, &entries[..2])?.received_count, 2);
		Ok(())
	})
	.unwrap();
	assert!(host(&db, |scope| scope.seal_manifest()).is_err());
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	let sealed = host(&db, |scope| {
		assert_eq!(scope.declare_manifest(4, &digest(&entries))?.received_count, 2);
		assert_eq!(scope.upload_manifest(0, &entries[..2])?.received_count, 2);
		scope.upload_manifest(2, &entries[2..])?;
		scope.seal_manifest()
	})
	.unwrap();
	assert_eq!(sealed.received_count, 4);
	assert_eq!(sealed.digest, digest(&entries));
	assert_eq!(host_at(&db, identity(), 11, |scope| scope.seal_manifest()).unwrap(), sealed);
	assert_eq!(host(&db, |scope| scope.upload_manifest(0, &entries)).unwrap(), sealed);
	let rows = inventory(&db);
	assert_eq!(rows.len(), 4);
	assert_eq!(rows[0].path.expose(), rows[1].path.expose());
	assert_ne!(rows[0].path.raw_bytes(), rows[1].path.raw_bytes());
	assert_eq!(
		rows.iter().filter(|r| r.disposition == inventory::Disposition::Excluded).count(),
		1
	);
}

#[test]
fn descriptor_prefix_and_sealed_membership_are_immutable() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	host(&db, |scope| {
		scope.declare_manifest(2, &digest(&entries))?;
		scope.upload_manifest(0, &entries[..1])?;
		Ok(())
	})
	.unwrap();
	assert!(host(&db, |scope| scope.declare_manifest(0, &digest(&[]))).is_err());
	assert!(
		host(&db, |scope| scope.upload_manifest(0, &entries)).is_err(),
		"partial overlap is not an append"
	);
	assert!(host(&db, |scope| scope.upload_manifest(2, &[])).is_err(), "no prefix holes");
	assert!(
		host(&db, |scope| scope.upload_manifest(1, &[entry(b"a")])).is_err(),
		"strict cross-chunk ordering"
	);
	host(&db, |scope| {
		scope.upload_manifest(1, &entries[1..])?;
		scope.seal_manifest()
	})
	.unwrap();
	assert!(host(&db, |scope| scope
		.upload_manifest(0, &[mode_entry(b"a", 0o100644, &"33".repeat(20))]))
	.is_err());
	assert!(host(&db, |scope| scope.upload_manifest(2, &[entry(b"c")])).is_err());
	assert_eq!(
		host(&db, |scope| scope.declare_manifest(2, &digest(&entries))).unwrap().received_count,
		2
	);
}

#[test]
fn owner_transfer_requires_terminal_owner_and_preserves_prefix() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	host(&db, |scope| {
		scope.declare_manifest(2, &digest(&entries))?;
		scope.upload_manifest(0, &entries[..1])?;
		Ok(())
	})
	.unwrap();
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET generation_id=11,state='leased',worker_id=1,attempts=1,lease_expires_at=100,hard_deadline_at=90,workflow_contract_version=?1,job_capability_hash=?2 WHERE id=102",params![WORKFLOW_CONTRACT_VERSION,[8u8;32].as_slice()])?;
		Ok(())
	}).unwrap();
	let next = LeaseIdentity { job_id: 102, capability_hash: &[8; 32], ..identity() };
	prepare_at(&db, next, 10).unwrap();
	assert!(
		matches!(
			host_at(&db, next, 10, |scope| scope.declare_manifest(2, &digest(&entries))),
			Err(Error::Conflict(crate::Conflict::GenerationState))
		),
		"a live logical manifest owner prevents transfer with a state conflict"
	);
	assert!(
		matches!(
			host_at(&db, next, 10, |scope| scope.upload_manifest(0, &entries[..1])),
			Err(Error::Conflict(crate::Conflict::GenerationState))
		),
		"another validly scoped attempt cannot mutate the current owner's manifest"
	);
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET state='failed' WHERE id=101", [])?;
		Ok(())
	})
	.unwrap();
	host_at(&db, next, 10, |scope| {
		let transferred = scope.declare_manifest(2, &digest(&entries))?;
		assert_eq!(transferred.owner_job_id, Some(102));
		assert_eq!(transferred.received_count, 1);
		scope.upload_manifest(1, &entries[1..])?;
		scope.seal_manifest()?;
		Ok(())
	})
	.unwrap();
	assert!(host(&db, |scope| scope.upload_manifest(0, &entries[..1])).is_err());
}

#[test]
fn historical_enrichment_preserves_ids_and_never_decodes_display_aliases() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,entry_kind,disposition,disposition_reason,source_path,created_at) VALUES (1,11,'a','tracked','context',NULL,'a',0),(2,11,'bad%FF.rs','tracked','excluded','unrepresentable-path',NULL,0);")?;Ok(())
	}).unwrap();
	let entries = [entry(b"a"), entry(b"bad%FF.rs"), entry(b"bad\xff.rs")];
	ingest(&db, &entries);
	let rows = inventory(&db);
	assert_eq!(rows.len(), 4);
	let old = rows.iter().find(|row| row.inventory_entry_id == 1).unwrap();
	assert_eq!(old.path.raw_bytes(), Some(b"a".as_slice()));
	assert_eq!(old.disposition, inventory::Disposition::Context);
	let excluded = rows.iter().find(|row| row.inventory_entry_id == 2).unwrap();
	assert!(excluded.path.raw_bytes().is_none());
	assert!(excluded.path.source_path().is_none());
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT COUNT(*) FROM generation_inventory WHERE manifest_position IS NOT NULL",
				[],
				|row| row.get::<_, i64>(0)
			)?,
			3
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn historical_conflicts_roll_back_partial_chunk_and_unaccounted_sources_block_seal() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	db.with_conn(|conn| {conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,blob_sha,entry_kind,created_at) VALUES(11,'b','b',?1,'tracked',0)",["33".repeat(20)])?;Ok(())}).unwrap();
	host(&db, |scope| scope.declare_manifest(2, &digest(&entries))).unwrap();
	assert!(host(&db, |scope| scope.upload_manifest(0, &entries)).is_err());
	assert_eq!(
		host(&db, |scope| scope.declare_manifest(2, &digest(&entries))).unwrap().received_count,
		0
	);
	assert_eq!(inventory(&db).len(), 1, "earlier chunk insertion rolls back");
	db.with_conn(|conn| {
		conn.execute("UPDATE generation_inventory SET blob_sha=NULL", [])?;
		Ok(())
	})
	.unwrap();
	host(&db, |scope| scope.upload_manifest(0, &entries)).unwrap();
	db.with_conn(|conn| {conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,entry_kind,created_at) VALUES(11,'missing','missing','tracked',0)",[])?;Ok(())}).unwrap();
	assert!(host(&db, |scope| scope.seal_manifest()).is_err());
	assert!(host(&db, |scope| scope.declare_manifest(2, &digest(&entries)))
		.unwrap()
		.sealed_at
		.is_none());
}

#[test]
fn seal_checks_digest_counters_and_contiguous_positions() {
	for corruption in [
		"UPDATE generation_manifests SET expected_digest=zeroblob(32)",
		"UPDATE generation_manifests SET received_canonical_bytes=0",
		"UPDATE generation_inventory SET manifest_position=8",
	] {
		let db = fixture();
		prepare(&db);
		let entries = [entry(b"a")];
		host(&db, |scope| {
			scope.declare_manifest(1, &digest(&entries))?;
			scope.upload_manifest(0, &entries)?;
			Ok(())
		})
		.unwrap();
		db.with_conn(|conn| {
			conn.execute_batch(corruption)?;
			Ok(())
		})
		.unwrap();
		assert!(host(&db, |scope| scope.seal_manifest()).is_err(), "must detect {corruption}");
		db.with_conn(|conn| {
			assert!(conn.query_row(
				"SELECT sealed_at IS NULL FROM generation_manifests WHERE generation_id=11",
				[],
				|row| row.get::<_, bool>(0)
			)?);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn exact_limits_refuse_without_truncating_or_partially_accepting() {
	let db = fixture();
	prepare(&db);
	assert!(host(&db, |scope| scope
		.declare_manifest(inventory_manifest::MAX_ENTRIES + 1, &[0; 32]))
	.is_err());
	host(&db, |scope| scope.declare_manifest(5000, &[0; 32])).unwrap();
	let many: Vec<_> = (0..4097).map(|index| entry(format!("{index:05}").as_bytes())).collect();
	assert!(host(&db, |scope| scope.upload_manifest(0, &many)).is_err());
	let huge: Vec<_> = (0..17)
		.map(|index| {
			let mut raw = vec![b'a'; 65536];
			raw[0] += index;
			entry(&raw)
		})
		.collect();
	assert!(host(&db, |scope| scope.upload_manifest(0, &huge)).is_err());
	assert!(host(&db, |scope| scope.upload_manifest(u64::MAX, &[entry(b"a")])).is_err());
	assert_eq!(
		host(&db, |scope| scope.declare_manifest(5000, &[0; 32])).unwrap().received_count,
		0
	);
	assert!(inventory(&db).is_empty());
	db.with_conn(|conn| {
		conn.execute(
			"UPDATE generation_manifests SET received_canonical_bytes=?1",
			[inventory_manifest::MAX_BYTES],
		)?;
		Ok(())
	})
	.unwrap();
	assert!(host(&db, |scope| scope.upload_manifest(0, &[entry(b"a")])).is_err());
}

#[test]
fn exact_chunk_count_and_byte_boundaries_are_accepted() {
	let count_entries: Vec<_> =
		(0..4096).map(|index| entry(format!("{index:05}").as_bytes())).collect();
	let byte_entries: Vec<_> = (0..16)
		.map(|index| {
			let mut raw = vec![b'a'; 65536 - 29];
			raw[0] += index;
			entry(&raw)
		})
		.collect();
	assert_eq!(
		byte_entries.iter().map(|entry| entry.canonical_len().unwrap()).sum::<u64>(),
		inventory_manifest::MAX_CHUNK_BYTES
	);
	for entries in [count_entries, byte_entries] {
		let db = fixture();
		ingest(&db, &entries);
		let manifest =
			host(&db, |scope| scope.declare_manifest(entries.len() as u64, &digest(&entries)))
				.unwrap();
		assert_eq!(manifest.received_count, entries.len() as u64);
		assert!(manifest.sealed_at.is_some());
	}
}

#[test]
fn publish_before_seal_is_a_generation_state_conflict() {
	let db = fixture();
	prepare(&db);
	host(&db, |scope| scope.declare_manifest(0, &digest(&[]))).unwrap();
	let result =
		host(&db, |scope| scope.publish_profile(&crate::test_support::json("{}").unwrap()));
	assert!(
		matches!(result, Err(Error::Conflict(crate::Conflict::GenerationState))),
		"an authorized pre-seal publication must be a generation-state conflict"
	);
}

#[test]
fn missing_manifest_is_a_generation_state_conflict() {
	let db = fixture();
	prepare(&db);
	assert!(
		matches!(
			host(&db, |scope| scope.upload_manifest(0, &[])),
			Err(Error::Conflict(crate::Conflict::GenerationState))
		),
		"upload before declare must be a state conflict"
	);
	assert!(
		matches!(
			host(&db, |scope| scope.seal_manifest()),
			Err(Error::Conflict(crate::Conflict::GenerationState))
		),
		"seal before declare must be a state conflict"
	);
}

#[test]
fn unpublishable_profile_is_a_generation_state_conflict() {
	for sql in [
		"UPDATE review_generations SET profile_version=2 WHERE generation_id=11",
		"UPDATE review_generations SET generated_profile='{}' WHERE generation_id=11",
	] {
		let db = fixture();
		ingest(&db, &[]);
		db.with_conn(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap();
		let result =
			host(&db, |scope| scope.publish_profile(&crate::test_support::json("{}").unwrap()));
		assert!(
			matches!(result, Err(Error::Conflict(crate::Conflict::GenerationState))),
			"a guarded profile UPDATE matching zero rows must be a state conflict"
		);
		db.with_conn(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101",
					[],
					|row| row.get::<_, i64>(0)
				)?,
				0,
				"a rejected publication must not leave a checkpoint"
			);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn host_state_conflicts_do_not_turn_scope_failures_into_conflicts() {
	let db = fixture();
	assert!(
		matches!(
			host(&db, |scope| scope.declare_manifest(0, &digest(&[]))),
			Err(Error::ScopeDenied)
		),
		"unprepared attempts remain unauthorized"
	);
	prepare(&db);
	assert!(
		matches!(
			host_at(&db, LeaseIdentity { capability_hash: &[8; 32], ..identity() }, 10, |scope| {
				scope.declare_manifest(0, &digest(&[]))
			}),
			Err(Error::ScopeDenied)
		),
		"wrong capability remains unauthorized"
	);
	with_phase_transaction(
		&db,
		identity(),
		|| 10,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::LeaseControl, |_| {
					panic!("LeaseControl does not evaluate policy")
				})?
				.unwrap();
			assert!(
				matches!(scope.declare_manifest(0, &digest(&[])), Err(Error::ScopeDenied)),
				"wrong purpose remains unauthorized"
			);
			Ok::<_, Error>(())
		},
	)
	.unwrap();
	db.with_conn(|conn| {
		conn.execute("UPDATE review_generations SET state='active' WHERE generation_id=11", [])?;
		Ok(())
	})
	.unwrap();
	assert!(
		matches!(
			host(&db, |scope| scope.declare_manifest(0, &digest(&[]))),
			Err(Error::Conflict(crate::Conflict::GenerationState))
		),
		"an authorized bootstrap generation no longer building is a state conflict"
	);
}

#[test]
fn empty_manifest_and_immutable_profile_replay_across_execution_attempts() {
	let db = fixture();
	prepare(&db);
	let profile: GeneratedProfile<loupe_provenance::Agent> =
		crate::test_support::json(r#"{"languages":["rust"]}"#).unwrap();
	host(&db, |scope| scope.declare_manifest(0, &digest(&[]))).unwrap();
	assert!(host(&db, |scope| scope.publish_profile(&profile)).is_err());
	host(&db, |scope| scope.seal_manifest()).unwrap();
	// A fresh modern publication writes its content designation explicitly.
	db.with_conn(|conn| {
		conn.execute(
			"UPDATE review_generations SET generated_profile_source='repo' WHERE generation_id=11",
			[],
		)?;
		Ok(())
	})
	.unwrap();
	let published = host(&db, |scope| scope.publish_profile(&profile)).unwrap();
	assert_eq!(host(&db, |scope| scope.publish_profile(&profile)).unwrap(), published);
	assert!(host(&db, |scope| scope.publish_profile(&crate::test_support::json("{}").unwrap()))
		.is_err());
	db.with_conn(|conn| {
		conn.execute(
			"UPDATE jobs SET attempts=2,job_capability_hash=?1 WHERE id=101",
			[[8u8; 32].as_slice()],
		)?;
		Ok(())
	})
	.unwrap();
	let next = LeaseIdentity { capability_hash: &[8; 32], ..identity() };
	assert!(
		host_at(&db, next, 10, |scope| scope.publish_profile(&profile)).is_err(),
		"retry must reconfirm checkout"
	);
	prepare_at(&db, next, 10).unwrap();
	assert_eq!(host_at(&db, next, 10, |scope| scope.publish_profile(&profile)).unwrap(), published);
	db.with_conn(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_checkpoints",[],|row|row.get::<_,i64>(0))?,1);
		assert_eq!(conn.query_row("SELECT generated_profile,generated_profile_source FROM review_generations WHERE generation_id=11",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?,(profile.expose().to_owned(),"agent".to_owned()));
		conn.execute("UPDATE review_generations SET generated_profile_source='repo' WHERE generation_id=11",[])?;Ok(())
	}).unwrap();
	assert!(host_at(&db, next, 10, |scope| scope.publish_profile(&profile)).is_err());
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT generated_profile_source FROM review_generations WHERE generation_id=11",
				[],
				|row| row.get::<_, String>(0)
			)?,
			"repo"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn seal_and_competing_changed_upload_serialize_without_mutating_membership() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("race.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	prepare(&db);
	let entries = [entry(b"a")];
	host(&db, |scope| {
		scope.declare_manifest(1, &digest(&entries))?;
		scope.upload_manifest(0, &entries)?;
		Ok(())
	})
	.unwrap();
	let second = Db::open(&path, &key).unwrap();
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let other_barrier = barrier.clone();
	let worker = std::thread::spawn(move || {
		other_barrier.wait();
		host(&second, |scope| scope.upload_manifest(0, &[entry(b"b")])).is_err()
	});
	barrier.wait();
	host(&db, |scope| scope.seal_manifest()).unwrap();
	assert!(worker.join().unwrap());
	assert_eq!(inventory(&db)[0].path.raw_bytes(), Some(b"a".as_slice()));
}
