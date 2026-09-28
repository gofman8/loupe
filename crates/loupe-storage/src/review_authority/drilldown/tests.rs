//! Storage-owned terminal transaction, replay and SQL readback controls.
use std::cell::Cell;

use loupe_provenance::Db as DbSource;

use super::*;
use crate::review_authority::with_phase_transaction;
use crate::review_intents::tests::{child, NORMAL, SHA};
use crate::test_support::{self as input, scope};
use crate::{jobs, transaction, Db};

const HASH: [u8; 32] = [9; 32];
fn identity() -> jobs::LeaseIdentity<'static> {
	jobs::LeaseIdentity { job_id: 110, worker_id: 1, capability_hash: &HASH }
}
fn payload(promote: bool) -> DrilldownTerminalV1<Agent> {
	let value = if promote {
		serde_json::json!({"version":1,"disposition":"promote","promotion":{
   "version":1,"severity":"high","title":"Retained boundary","description":"Attacker controls allocation",
   "identity_family":"allocation","identity_anchor":"entry",
   "evidence":{"version":1,"l2_argument":{"attacker_source":"request","control":"length","sink":"allocation","reachable_path":"entry to allocator","trust_boundary":"remote to memory"},
   "material_locations":[{"role":"sink","file":"src.rs"}],"counterevidence":"none","assumptions_gaps":"trace callers","confidence":"medium"}}})
	} else {
		serde_json::json!({"version":1,"disposition":"reject","counterargument":{"argument":"Checked bound","source_refs":[{"path":"src.rs"}]}})
	};
	input::agent(&value.to_string(), |raw, mark| DrilldownTerminalV1::from_json(mark, raw)).unwrap()
}
fn fixture() -> (Db, i64) {
	let db = crate::review_intents::tests::fixture();
	let lead = db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let payload = input::agent(r#"{"format":"loupe.lead_evidence","version":1,"identity_family":"allocation","identity_anchor":"entry","hypothesis":"Attacker controls length","source_refs":[{"path":"src.rs"}],"next_proof_step":"Inspect bound","counterevidence":"Caller validation","proof_gaps":"Check callers"}"#, |raw, mark| {
				loupe_core::review_payload::LeadEvidenceV1::from_json(mark, raw)
			}).unwrap();
			let commit = input::database(SHA, |raw, mark| loupe_core::text::BoundedText::new(mark, raw)).unwrap();
			let leads::Submitted::Created(lead) = leads::submit_evidence(
				&scope(tx, 1),
				&leads::NewLeadEvidence {
					generation_id: 11, created_by_job: 101, commit_sha: &commit,
					priority: crate::review_units::Priority::Normal, payload: &payload,
				},
				1,
			)? else { panic!("new lead") };
			let intent = review_intents::ensure_drilldown_intent(&scope(tx, 1), lead, 101, NORMAL, 1)?.unwrap();
			child(tx, 110, Some(Subject::Lead(lead)), 101, false)?;
			tx.execute(
				"UPDATE jobs SET job_capability_hash=?1,prepared_capability_hash=?1,recipe=?2 WHERE id=110",
				params![HASH.as_slice(), r#"{"version":1,"phase":"drilldown"}"#],
			)?;
			review_intents::admit_subject(&scope(tx, 1), Subject::Lead(lead), intent.revision, 110, 2)?;
			Ok(lead)
		})
	}).unwrap();
	(db, lead)
}
fn finish(db: &Db, value: &DrilldownTerminalV1<Agent>) -> Result<DrilldownFinalization> {
	with_phase_transaction(
		db,
		identity(),
		|| 100,
		|tx| tx.finalize_drilldown(value, |_| Ok(Some(PolicyDecision::Ordinary))),
	)
}
fn assert_unfinished(db: &Db, lead: i64) {
	db.with_conn(|conn| {
		for table in ["findings", "finding_review_details", "finding_verification_intents", "job_terminal_receipts", "job_terminal_payloads"] {
			assert_eq!(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get::<_, i64>(0))?, 0, "{table}");
		}
		let job = jobs::get(&scope(conn, 1), 110)?.unwrap();
		assert_eq!(job.state, loupe_core::JobState::Leased);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs WHERE id=110 AND job_capability_hash=?1 AND prepared_capability_hash=?1 AND prepared_attempt=attempts", [HASH.as_slice()], |row| row.get::<_, i64>(0))?, 1);
		assert_eq!(leads::get_metadata(&scope(conn, 1), lead)?.unwrap().status, leads::Status::Open);
		assert_eq!(review_intents::get_subject(&scope(conn, 1), Subject::Lead(lead))?.unwrap().state, IntentState::Admitted);
		Ok(())
	}).unwrap();
}
#[test]
fn bounded_callback_failure_rolls_back_promotion_handoff_identity_and_terminal() {
	let (db, lead) = fixture();
	let result: Result<()> = with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let receipt =
				tx.finalize_drilldown(&payload(true), |_| Ok(Some(PolicyDecision::Ordinary)))?;
			let mut bytes = [0u8; 1];
			assert!(serde_json::to_writer(bytes.as_mut_slice(), &receipt.summary).is_err());
			Err(Error::Conflict(Conflict::TerminalReceipt))
		},
	);
	assert!(result.is_err());
	assert_unfinished(&db, lead);
	let accepted = finish(&db, &payload(true)).unwrap();
	let _: &ReviewCommit<DbSource> = &accepted.commit;
	db.with_conn(|conn| {
		let (report, source): (Vec<u8>, String) = conn.query_row(
			"SELECT report_identity,source FROM findings", [], |row| Ok((row.get(0)?, row.get(1)?)),
		)?;
		assert_eq!(report.len(), crate::report_identity::BYTES);
		assert_ne!(report, [0; crate::report_identity::BYTES]);
		assert_eq!(source, "agent");
		assert_eq!(conn.query_row("SELECT worker_id FROM jobs WHERE id=110", [], |row| row.get::<_, i64>(0))?, 1);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs WHERE id=110 AND job_capability_hash IS NULL AND lease_expires_at IS NULL AND prepared_attempt IS NULL", [], |row| row.get::<_, i64>(0))?, 1);
		Ok(())
	}).unwrap();
}
#[test]
fn sealed_replay_and_conflict_do_not_decode_live_context_or_call_policy() {
	let (db, _) = fixture();
	let accepted = finish(&db, &payload(false)).unwrap();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE review_campaigns SET state='cancelled',effective_policy='malformed';DELETE FROM review_generations;")?;
		Ok(())
	}).unwrap();
	let called = Cell::new(false);
	let replay = with_phase_transaction(
		&db,
		identity(),
		|| 20000,
		|tx| {
			tx.finalize_drilldown(&payload(false), |_| {
				called.set(true);
				Err(Error::ScopeDenied)
			})
		},
	)
	.unwrap();
	assert_eq!(accepted, replay);
	let conflict = with_phase_transaction(
		&db,
		identity(),
		|| 20000,
		|tx| {
			tx.finalize_drilldown(&payload(true), |_| {
				called.set(true);
				Err(Error::ScopeDenied)
			})
		},
	);
	assert!(matches!(conflict, Err(Error::Conflict(Conflict::TerminalReceipt))));
	assert!(!called.get());
}
#[test]
fn required_sql_readback_rejects_corrupt_summary_audit_and_subject_before_commit() {
	for assignment in [
		"result_counts='{\"version\":99}'",
		"effective_recipe='broken'",
		"subject_digest=zeroblob(31)",
		"evidence_rung='L4'",
	] {
		let (db, lead) = fixture();
		db.with_conn(|conn| {
			conn.execute_batch(&format!("CREATE TRIGGER corrupt_receipt AFTER INSERT ON job_terminal_receipts BEGIN UPDATE job_terminal_receipts SET {assignment} WHERE job_id=NEW.job_id; END"))?;
			Ok(())
		}).unwrap();
		assert!(finish(&db, &payload(true)).is_err(), "{assignment}");
		assert_unfinished(&db, lead);
	}
}
