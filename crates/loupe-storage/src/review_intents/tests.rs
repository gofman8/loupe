use loupe_core::review_payload::GeneratedProfile;
use rusqlite::Transaction;

use super::*;
use crate::test_support::{self as input, scope};
use crate::{review_tests, transaction, Db};

pub(crate) const SHA: &str = "0123456789012345678901234567890123456789";
pub(crate) const NORMAL: AcceptedPriority =
	AcceptedPriority { band: crate::scheduler::Band::Normal, score: 0 };
pub(crate) fn ready(db: &Db) {
	db.with_conn(|conn| {
		let profile=input::agent("{\"languages\":[\"rust\"]}", |raw, mark| GeneratedProfile::new(mark, raw)).unwrap();
		let policy=CampaignPolicyV2::default().canonical_bytes()?;
		let legacy=crate::canonical::canonical_bytes(&serde_json::to_value(crate::scheduler::CampaignPolicy::default()).unwrap());
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2",params![std::str::from_utf8(&legacy).unwrap(),crate::canonical::digest(&legacy).as_slice()])?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1,effective_policy=?2,effective_policy_digest=?3,deadline_at=10000 WHERE campaign_id=1",params![SHA,std::str::from_utf8(&policy).unwrap(),crate::canonical::digest(&policy).as_slice()])?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,workflow_contract_version=2,profile_version=1,generated_profile=?2,generated_profile_digest=?3,generated_profile_source='agent' WHERE generation_id=11",params![SHA,profile.expose(),profile.digest().as_slice()])?;
		let entry = input::database("", |_, mark| {
			loupe_core::inventory_manifest::ManifestEntry::new(mark, b"src.rs", 0o100644, SHA)
		}).unwrap();
		let mut manifest = loupe_core::inventory_manifest::ManifestHasher::new(SHA, 1).unwrap();
		manifest.push(&entry).unwrap();
		let digest = manifest.finish().unwrap();
		conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,1,1,?1,0,0)",[digest.as_slice()])?;
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
		conn.execute_batch("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',zeroblob(32),0);")?;
		conn.execute("UPDATE jobs SET state='leased',worker_id=1,attempts=1,lease_expires_at=10000,job_capability_hash=zeroblob(32),head_sha=?1,workflow_contract_version=2,scheduling_band='normal' WHERE id=101",[SHA])?;
		Ok(())
	}).unwrap();
}
pub(crate) fn fixture() -> Db {
	let db = review_tests::fixture();
	ready(&db);
	db
}
pub(crate) fn lead(tx: &Transaction<'_>, id: i64) -> Result<()> {
	let identity = crate::identity::Identity {
		family: input::identifier("family").unwrap(),
		anchor: input::anchor("anchor").unwrap(),
		instance: Some(input::anchor(&format!("endpoint-{id}")).unwrap()),
	};
	tx.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_by_job_id,created_at) VALUES(?1,11,'family','anchor',?4,?2,'{}',zeroblob(32),?3,101,0)",params![id,identity.fingerprint().as_slice(),SHA,identity.instance.as_ref().unwrap().expose()])?;
	Ok(())
}
pub(crate) fn child(
	tx: &Transaction<'_>, id: i64, subject: Option<Subject>, parent: i64, logical: bool,
) -> Result<()> {
	let kind = subject.map_or(JobKind::Survey, Subject::phase);
	tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,head_sha,parent_job_id,continuation_of_job_id,assigned_lead_id,target_finding_id,worker_id,attempts,lease_expires_at,job_capability_hash,workflow_contract_version,scheduling_band,enqueued_at) VALUES(?1,1,?2,'leased',1,11,?3,?4,?5,?6,?7,1,1,10000,?8,2,'normal',0)",params![id,kind.as_str(),SHA,parent,logical.then_some(parent),match subject{Some(Subject::Lead(id))=>Some(id),_=>None},match subject{Some(Subject::Finding(id))=>Some(id),_=>None},id.to_be_bytes().repeat(4)])?;
	tx.execute("UPDATE jobs SET hard_deadline_at=10000,prepared_at=0,prepared_attempt=attempts,prepared_capability_hash=job_capability_hash WHERE id=?1",[id])?;
	Ok(())
}
fn finding(tx: &Transaction<'_>, id: i64, lead_id: i64, job: i64) -> Result<()> {
	tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity) VALUES(?1,1,?2,'review','high','Finding','Evidence',?3,'validating',0,?4)",params![id,job,format!("finding-{id}"),crate::report_identity::generate()?.as_slice()])?;
	let profile =
		input::agent("{\"languages\":[\"rust\"]}", |raw, mark| GeneratedProfile::new(mark, raw))
			.unwrap();
	tx.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,evidence_payload,submitted_rung,origin_lead_id,created_at) VALUES(?1,1,2,1,?2,?3,'family','anchor',?4,'{}','L2',?5,0)",params![id,profile.digest().as_slice(),SHA,id.to_be_bytes().repeat(4),lead_id])?;
	tx.execute("UPDATE leads SET status='closed',disposition='promoted',promoted_finding_id=?2 WHERE lead_id=?1",params![lead_id,id])?;
	Ok(())
}

#[test]
fn intent_production_requires_a_lease_compatible_profile_version() {
	for (version, accepted) in
		[("1", true), ("4294967295", true), ("4294967296", false), ("1.5", false)]
	{
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					lead(tx, 1)?;
					tx.execute(
						&format!("UPDATE review_generations SET profile_version={version} WHERE generation_id=11"),
						[],
					)?;
					let produced = ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0);
					assert_eq!(
						produced.is_ok(), accepted,
						"intent production must require a lease-compatible profile version: {version}"
					);
					let intent = get_subject(&scope(tx, 1), Subject::Lead(1))?;
					assert_eq!(intent.is_some(), accepted, "rejection must not insert an intent");
					if let Some(intent) = intent {
						assert_eq!(intent.profile_version.to_string(), version);
					}
					assert_eq!(
						tx.query_row("SELECT CAST(profile_version AS TEXT) FROM review_generations WHERE generation_id=11", [], |r| r.get::<_, String>(0))?,
						version, "validation must not rewrite the stored profile version"
					);
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn subject_first_admission_precedes_checkout_but_production_does_not() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx, 1)?;
				ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
				child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
				tx.execute("UPDATE jobs SET head_sha=?1 WHERE id=110", ["a".repeat(40)])?;
				assert!(
					admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1).is_err(),
					"known wrong checkout must not admit"
				);
				tx.execute("UPDATE jobs SET head_sha=NULL WHERE id=110", [])?;
				admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1)
					.expect("first subject admission must not require a completed child checkout");
				assert!(jobs::get(&scope(tx, 1), 110)?.unwrap().head_sha.is_none());
				assert!(producer(tx, 1, 110).is_err(), "admission is not checkout preparation");
				tx.execute("UPDATE jobs SET head_sha=?1 WHERE id=110", [SHA])?;
				assert!(producer(tx, 1, 110).is_ok());
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn prepared_bootstrap_admits_subjects_before_survey_finalization() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute(
					"UPDATE review_generations SET state='building' WHERE generation_id=11",
					[],
				)?;
				lead(tx, 1)?;
				ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
				child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
				admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1)
					.expect("prepared bootstrap lead must compete before survey finalize");
				finding(tx, 7, 1, 110)?;
				ensure_verification_intent(&scope(tx, 1), 7, 110, NORMAL, 2)?;
				child(tx, 111, Some(Subject::Finding(7)), 110, false)?;
				admit_subject(&scope(tx, 1), Subject::Finding(7), 1, 111, 3)
					.expect("mandatory verification may also run during prepared bootstrap");
				assert_eq!(jobs::get(&scope(tx, 1), 101)?.unwrap().state, JobState::Leased);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn bootstrap_admission_rejects_missing_preparation_or_successor_context() {
	for mutation in [
		"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
		"UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL WHERE generation_id=11",
		"UPDATE review_generations SET predecessor_generation_id=12 WHERE generation_id=11",
		"UPDATE review_campaigns SET recipe='incremental' WHERE campaign_id=1",
	] {
		fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
			tx.execute("UPDATE review_generations SET state='building' WHERE generation_id=11",[])?;
			lead(tx,1)?;
			ensure_drilldown_intent(&scope(tx, 1),1,101,NORMAL,0)?;
			child(tx,110,Some(Subject::Lead(1)),101,false)?;
			tx.execute(mutation,[])?;
			assert!(admit_subject(&scope(tx, 1),Subject::Lead(1),1,110,1).is_err(),"{mutation}");
			assert_eq!(get_subject(&scope(tx, 1),Subject::Lead(1))?.unwrap().state,State::Pending);
			Ok(())
		})).unwrap();
	}
}

#[test]
fn repeated_observations_preserve_rank_owner_and_dependency_state() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			let initial = ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 10)?.unwrap();
			let urgent = AcceptedPriority { band: crate::scheduler::Band::Urgent, score: 550 };
			assert_eq!(
				ensure_drilldown_intent(&scope(tx, 1), 1, 101, urgent, 11)?,
				Some(initial.clone())
			);
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			let admitted = admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 12)?;
			assert_eq!(ensure_drilldown_intent(&scope(tx, 1), 1, 101, urgent, 13)?, Some(admitted));
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
			let blocked = continue_subject(
				&scope(tx, 1),
				Subject::Lead(1),
				110,
				ContinuationClass::ExternalDependency,
				14,
			)?;
			assert_eq!(blocked.state, State::Blocked);
			assert_eq!(blocked.not_before, None);
			assert_eq!(blocked.priority, NORMAL);
			assert_eq!(ensure_drilldown_intent(&scope(tx, 1), 1, 101, urgent, 15)?, Some(blocked));
			assert_eq!(list_subjects(&scope(tx, 1), Subject::Lead(0), 1, 0, 1)?.len(), 1);
			assert!(list_subjects(&scope(tx, 1), Subject::Lead(0), 1, 0, 257).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn logical_revision_tracks_finishing_producer_and_positive_frozen_backoff() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn,|tx| {
			lead(tx,1)?;
			ensure_drilldown_intent(&scope(tx, 1),1,101,NORMAL,0)?;
			child(tx,110,Some(Subject::Lead(1)),101,false)?;
			admit_subject(&scope(tx, 1),Subject::Lead(1),1,110,1)?;
			tx.execute("UPDATE jobs SET state='succeeded',attempts=3 WHERE id=110",[])?;
			tx.execute("UPDATE leads SET status='deferred',defer_reason='source work',retry_condition='source_analysis_remaining' WHERE lead_id=1",[])?;
			let next=continue_subject(&scope(tx, 1),Subject::Lead(1),110,ContinuationClass::SourceAnalysisRemaining,10)?;
			assert_eq!((next.revision,next.logical_sequence,next.originating_job_id,next.admitted_job_id,next.not_before),(2,1,110,None,Some(70)));
			child(tx,111,Some(Subject::Lead(1)),110,true)?;
			assert!(admit_subject(&scope(tx, 1),Subject::Lead(1),2,111,69).is_err());
			assert!(admit_subject(&scope(tx, 1),Subject::Lead(1),1,111,70).is_err());
			admit_subject(&scope(tx, 1),Subject::Lead(1),2,111,70)?;
			assert_eq!(tx.query_row("SELECT status FROM leads WHERE lead_id=1",[],|r|r.get::<_,String>(0))?,"open");
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=111",[])?;
			let next=continue_subject(&scope(tx, 1),Subject::Lead(1),111,ContinuationClass::SourceAnalysisRemaining,80)?;
			assert_eq!((next.revision,next.logical_sequence,next.originating_job_id,next.not_before),(3,2,111,Some(200)));
			assert!(continue_subject(&scope(tx, 1),Subject::Lead(1),110,ContinuationClass::SourceAnalysisRemaining,81).is_err());
			Ok(())
		})?;
		// A separate transaction recovers the same current revision, not the old child.
		assert_eq!(get_subject(&scope(conn, 1),Subject::Lead(1))?.unwrap().originating_job_id,111);
		Ok(())
	}).unwrap();
}

fn dependency_continuation_admission(verify: bool) {
	for class in [ContinuationClass::SourceAnalysisRemaining, ContinuationClass::ExternalDependency]
	{
		fixture().with_conn(|conn| transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1)?;
			let (subject, producer) = if verify {
				finding(tx, 7, 1, 110)?;
				ensure_verification_intent(&scope(tx, 1), 7, 110, NORMAL, 2)?;
				child(tx, 111, Some(Subject::Finding(7)), 110, false)?;
				admit_subject(&scope(tx, 1), Subject::Finding(7), 1, 111, 3)?;
				(Subject::Finding(7), 111)
			} else {
				tx.execute("UPDATE leads SET status='deferred',defer_reason='remaining work',retry_condition='source_analysis_remaining' WHERE lead_id=1", [])?;
				(Subject::Lead(1), 110)
			};
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=?1", [producer])?;
			let intent = continue_subject(&scope(tx, 1), subject, producer, class, 100)?;
			// Schema-valid corruption cannot turn an external dependency into
			// admissible work; the source-analysis neighbor remains admissible.
			tx.execute(&format!("UPDATE {} SET state='pending',block_reason=NULL,not_before=100", subject.table()), [])?;
			child(tx, 200, Some(subject), producer, true)?;
			let admitted = admit_subject(&scope(tx, 1), subject, intent.revision, 200, 101);
			if class == ContinuationClass::ExternalDependency {
				assert!(admitted.is_err(), "a due timestamp cannot authorize a dependency continuation");
				assert_eq!(get_subject(&scope(tx, 1), subject)?.unwrap().state, State::Pending);
			} else {
				assert!(admitted.is_ok(), "due source-analysis continuation must remain admissible: {admitted:?}");
				assert_eq!(get_subject(&scope(tx, 1), subject)?.unwrap().state, State::Admitted);
			}
			Ok(())
		})).unwrap();
	}
}

#[test]
fn subject_admission_rejects_dependency_lead_continuation_despite_due_time() {
	dependency_continuation_admission(false);
}

#[test]
fn subject_admission_rejects_dependency_finding_continuation_despite_due_time() {
	dependency_continuation_admission(true);
}

#[test]
fn ownership_closed_subjects_and_first_live_lease_are_checked() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			lead(tx, 2)?;
			tx.execute("UPDATE leads SET created_by_job_id=NULL WHERE lead_id=2", [])?;
			assert!(ensure_drilldown_intent(&scope(tx, 1), 2, 101, NORMAL, 0).is_err());
			ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			tx.execute(
				"UPDATE review_generations SET state='building' WHERE generation_id=11",
				[],
			)?;
			tx.execute(
				"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
				[],
			)?;
			assert!(
				admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1).is_err(),
				"bootstrap intent cannot dispatch before host preparation"
			);
			tx.execute("UPDATE generation_manifests SET sealed_at=0 WHERE generation_id=11", [])?;
			tx.execute("UPDATE review_generations SET state='active' WHERE generation_id=11", [])?;
			tx.execute("UPDATE jobs SET attempts=2 WHERE id=110", [])?;
			assert!(admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1).is_err());
			tx.execute("UPDATE jobs SET attempts=1,job_capability_hash=NULL WHERE id=110", [])?;
			assert!(admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1).is_err());
			tx.execute(
				"UPDATE jobs SET job_capability_hash=?1 WHERE id=110",
				[110_i64.to_be_bytes().repeat(4)],
			)?;
			tx.execute(
				"UPDATE leads SET status='closed',disposition='rejected' WHERE lead_id=1",
				[],
			)?;
			assert!(admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1).is_err());
			assert!(finish_subject_intent(&scope(tx, 1), Subject::Lead(1), 101, 1).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn canonical_verification_intent_survives_generation_purge_and_lifecycle_block() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			finding(tx, 8, 1, 110)?;
			let initial = ensure_verification_intent(&scope(tx, 1), 8, 110, NORMAL, 0)?.unwrap();
			assert_eq!(initial.generation_id, Some(11));
			child(tx, 111, Some(Subject::Finding(8)), 110, false)?;
			admit_subject(&scope(tx, 1), Subject::Finding(8), 1, 111, 1)?;
			tx.execute("UPDATE jobs SET state='failed',job_capability_hash=NULL WHERE id=111", [])?;
			block_job_work(&scope(tx, 1), 111, BlockReason::ExecutionExhausted, 2)?;
			let blocked = get_subject(&scope(tx, 1), Subject::Finding(8))?.unwrap();
			assert_eq!(blocked.state, State::Blocked);
			assert_eq!(blocked.block_reason, Some(BlockReason::ExecutionExhausted));
			// Re-observing promotion cannot replace blocked canonical work.
			assert_eq!(
				ensure_verification_intent(&scope(tx, 1), 8, 110, NORMAL, 3)?,
				Some(blocked)
			);
			tx.execute("DELETE FROM review_generations WHERE generation_id=11", [])?;
			Ok(())
		})?;
		let retained = get_subject(&scope(conn, 1), Subject::Finding(8))?.unwrap();
		assert_eq!(retained.generation_id, None);
		assert_eq!(retained.source_commit_sha.expose(), SHA);
		assert_eq!(retained.originating_job_id, 110);
		assert_eq!(retained.admitted_job_id, Some(111));
		assert!(crate::findings::get(&scope(conn, 1), 8)?.is_some());
		Ok(())
	})
	.unwrap();
}

#[test]
fn finish_requires_matching_admitted_child_and_keeps_audit_identity() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1)?;
			assert!(finish_subject_intent(&scope(tx, 1), Subject::Lead(1), 110, 2).is_err());
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
			finish_subject_intent(&scope(tx, 1), Subject::Lead(1), 110, 2)?;
			let done = get_subject(&scope(tx, 1), Subject::Lead(1))?.unwrap();
			assert_eq!(done.state, State::Complete);
			assert_eq!(done.admitted_job_id, Some(110));
			assert!(continue_subject(
				&scope(tx, 1),
				Subject::Lead(1),
				110,
				ContinuationClass::SourceAnalysisRemaining,
				3
			)
			.is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn lifecycle_block_does_not_decode_broken_recipe_or_policy_after_revocation() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			admit_subject(&scope(tx, 1), Subject::Lead(1), 1, 110, 1)?;
			tx.execute(
				"UPDATE jobs SET state='failed',job_capability_hash=NULL,recipe='{' WHERE id=110",
				[],
			)?;
			tx.execute("UPDATE review_campaigns SET effective_policy='{' WHERE campaign_id=1", [])?;
			block_job_work(&scope(tx, 1), 110, BlockReason::CompatibilityPolicy, 2)
				.expect("lifecycle blocking must survive malformed untrusted metadata");
			assert_eq!(
				get_subject(&scope(tx, 1), Subject::Lead(1))?.unwrap().block_reason,
				Some(BlockReason::CompatibilityPolicy)
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn first_child_lease_is_live_at_expiry_equality() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx, 1)?;
				ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0)?;
				child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
				tx.execute("UPDATE jobs SET lease_expires_at=60 WHERE id=110", [])?;
				assert!(admit_subject(&scope(tx,1),Subject::Lead(1),1,110,60).is_ok(),
			"a first child lease remains live at its exact expiry, matching the authority issuer");
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn first_child_lease_rechecks_sql_types_before_admission() {
	let mut wrong = Vec::new();
	for (mutation, expected) in [
		("lease_expires_at=61", true),
		("lease_expires_at=x'01'", false),
		("lease_expires_at='not-an-integer'", false),
		("job_capability_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", false),
		("job_capability_hash=zeroblob(31)", false),
	] {
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					lead(tx, 1)?;
					child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
					let context = job_context(tx, 1, 110)?;
					// The helper must check live SQL facts, not trust the earlier context.
					tx.execute(&format!("UPDATE jobs SET {mutation} WHERE id=110"), [])?;
					if validate_child(tx, &context, 101, 60).is_ok() != expected {
						wrong.push(mutation);
					}
					Ok(())
				})
			})
			.unwrap();
	}
	assert!(wrong.is_empty(), "first child lease requires exact SQL scalar types: {wrong:?}");
}

#[test]
fn first_child_text_capability_is_not_a_live_lease() {
	fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
		lead(tx,1)?;
		ensure_drilldown_intent(&scope(tx,1),1,101,NORMAL,0)?;
		child(tx,110,Some(Subject::Lead(1)),101,false)?;
		tx.execute("UPDATE jobs SET job_capability_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=110",[])?;
		assert!(admit_subject(&scope(tx,1),Subject::Lead(1),1,110,60).is_err(),
			"TEXT capability must not admit a pending subject");
		assert_eq!(get_subject(&scope(tx,1),Subject::Lead(1))?.unwrap().state,State::Pending);
		Ok(())
	})).unwrap();
}

#[test]
fn frozen_profile_admission_keeps_source_canonical_bytes_and_digest_checks() {
	for mutation in [
		"generated_profile_source='db'",
		"generated_profile_source='worker'",
		"generated_profile_source='operator'",
		"generated_profile_source='unknown'",
		"generated_profile='{\"languages\": [\"rust\"]}'",
		"generated_profile_digest=zeroblob(32)",
		"generated_profile_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
	] {
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					lead(tx, 1)?;
					assert!(producer(tx, 1, 101).is_ok());
					tx.execute(
						&format!("UPDATE review_generations SET {mutation} WHERE generation_id=11"),
						[],
					)?;
					assert!(
						ensure_drilldown_intent(&scope(tx, 1), 1, 101, NORMAL, 0).is_err(),
						"{mutation}"
					);
					assert!(get_subject(&scope(tx, 1), Subject::Lead(1))?.is_none());
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn intent_metadata_is_db_typed_and_foreign_rows_are_filtered_before_decode() {
	fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
		lead(tx,1)?;
		let intent=ensure_drilldown_intent(&scope(tx,1),1,101,NORMAL,0)?.unwrap();
		let _: &ReviewCommit<loupe_provenance::Db>=&intent.source_commit_sha;
		let _: &ReviewDigest<loupe_provenance::Db>=&intent.profile_digest;
		assert_eq!(intent.source_commit_sha.expose(),SHA);
		assert!(!format!("{intent:?}").contains(SHA));
		tx.execute("UPDATE lead_drilldown_intents SET source_commit_sha='not-a-commit' WHERE lead_id=1",[])?;
		assert!(get_subject(&scope(tx,1),Subject::Lead(1)).is_err());
		assert!(get_subject(&scope(tx,2),Subject::Lead(1))?.is_none());
		assert!(list_subjects(&scope(tx,2),Subject::Lead(0),1,0,256)?.is_empty());
		tx.execute("UPDATE jobs SET recipe='{',head_sha=x'01' WHERE id=201",[])?;
		assert!(matches!(job_context(tx,1,201),Err(Error::NotFound(Entity::Job,201))));
		assert!(matches!(ensure_drilldown_intent(&scope(tx,1),1,201,NORMAL,0),Err(Error::NotFound(Entity::Job,201))));
		Ok(())
	})).unwrap();
}

#[test]
fn worker_repository_reads_do_not_grant_pending_work_mutation_authority() {
	let db = fixture();
	let hash = [17_u8; 32];
	db.with_conn(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,worker_id,attempts,lease_expires_at,job_capability_hash,enqueued_at) VALUES(301,1,'scan','leased',1,1,10000,?1,0)",[hash.as_slice()])?;
		Ok(())
	}).unwrap();
	crate::scope::with_active_lease(
		&db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity { job_id: 301, worker_id: 1, capability_hash: &hash },
			now: 1,
		},
		|lease| {
			let scope = lease.repo();
			assert!(matches!(
				ensure_drilldown_intent(scope, 1, 101, NORMAL, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				ensure_verification_intent(scope, 1, 101, NORMAL, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				admit_subject(scope, Subject::Lead(1), 1, 101, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				continue_subject(
					scope,
					Subject::Lead(1),
					101,
					ContinuationClass::ExternalDependency,
					0
				),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				finish_subject_intent(scope, Subject::Lead(1), 101, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				block_job_work(scope, 101, BlockReason::ExecutionExhausted, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				unit_holds::record_follow_up(
					scope,
					1,
					1,
					101,
					0,
					ContinuationClass::ExternalDependency,
					0
				),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				unit_holds::release_conclusive(scope, 1, 1, 101, 0, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				unit_holds::freeze_survey_batches(scope, 101, 0),
				Err(Error::ScopeDenied)
			));
			assert!(matches!(
				unit_holds::admit_exact_batch(scope, 1, 101, 0),
				Err(Error::ScopeDenied)
			));
			Ok(())
		},
	)
	.unwrap()
	.unwrap();
}
