//! Owned report selection cannot become active until the exact transaction commits.
use loupe_core::review_payload::DrilldownTerminalV1;

use super::*;
use crate::review_authority::{drilldown, with_phase_transaction};
use crate::review_intents::tests::child;
use crate::test_support::{self as input, scope};
use crate::{jobs, Db as Database};

const HASH: [u8; 32] = [11; 32];
fn identity() -> jobs::LeaseIdentity<'static> {
	jobs::LeaseIdentity { job_id: 111, worker_id: 1, capability_hash: &HASH }
}
fn fixture() -> (Database, i64) {
	let (db, _) = drilldown::tests::fixture();
	let result = drilldown::tests::finish(&db, &drilldown::tests::payload(true)).unwrap();
	let finding = result.summary.promoted_finding_id.unwrap();
	db.with_conn(|conn| crate::transaction::immediate(conn, |conn|{
        child(conn,111,Some(Subject::Finding(finding)),110,false)?;
        conn.execute("UPDATE jobs SET job_capability_hash=?1,prepared_capability_hash=?1,recipe=?2 WHERE id=111",
            params![HASH.as_slice(),r#"{"version":1,"phase":"verify"}"#])?;
        let intent=review_intents::get_subject(&scope(conn,1),Subject::Finding(finding))?.unwrap();
        review_intents::admit_subject(&scope(conn,1),Subject::Finding(finding),intent.revision,111,101)?;
        conn.execute("UPDATE registered_repos SET reporting=?1", [r#"{"kind":"email","to":["reader@example.test"],"from":null,"subject_prefix":null}"#])?;
        Ok(())
    })).unwrap();
	(db, finding)
}
fn evidence() -> VerificationTerminalV1<Agent> {
	let DrilldownTerminalV1::Promote { promotion, .. } = drilldown::tests::payload(true) else {
		panic!("promote")
	};
	let value = serde_json::json!({"version":1,"verdict":"verified","established_rung":"L2",
        "e2e_applicability":"not_applicable","e2e_rationale":"Source contract","evidence":promotion.evidence});
	input::agent(&value.to_string(), |raw, mark| VerificationTerminalV1::from_json(mark, raw))
		.unwrap()
}
fn assert_unfinished(db: &Database, finding: i64) {
	db.with_conn(|conn|{
        assert_eq!(findings::get(&scope(conn,1),finding)?.unwrap().state,FindingState::Validating);
        for table in ["finding_verifications","verification_attempt_details"] {
            assert_eq!(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"),[],|row|row.get::<_,i64>(0))?,0);
        }
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_terminal_receipts WHERE job_id=111",[],|row|row.get::<_,i64>(0))?,0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_terminal_payloads WHERE job_id=111",[],|row|row.get::<_,i64>(0))?,0);
        assert!(conn.query_row("SELECT state='leased' AND job_capability_hash IS NOT NULL AND prepared_attempt=attempts FROM jobs WHERE id=111",[],|row|row.get::<_,bool>(0))?);
        assert_eq!(review_intents::get_subject(&scope(conn,1),Subject::Finding(finding))?.unwrap().state,review_intents::State::Admitted);
        Ok(())
    }).unwrap();
}
#[test]
fn callback_and_bounded_encoding_errors_leave_captured_preparation_inactive() {
	for encoding in [false, true] {
		let (db, finding) = fixture();
		let mut escaped = None;
		let result: Result<()> = with_phase_transaction(
			&db,
			identity(),
			|| 102,
			|tx| {
				let value = tx.finalize_verification(&evidence(), false, |_| {
					Ok(Some(PolicyDecision::Ordinary))
				})?;
				let reports::Preparation::Ready(batch) = value.reporting else {
					panic!("ready batch")
				};
				assert!(matches!(batch.check_committed(), Err(Error::ReportReceipt)));
				escaped = Some(batch);
				if encoding {
					let mut bytes = [0u8; 1];
					assert!(serde_json::to_writer(bytes.as_mut_slice(), &value.receipt.summary)
						.is_err());
				}
				Err(Error::ScopeDenied)
			},
		);
		assert!(result.is_err());
		assert!(matches!(escaped.unwrap().check_committed(), Err(Error::ReportReceipt)));
		assert_unfinished(&db, finding);
	}
}
#[test]
fn sql_commit_failure_leaves_captured_preparation_inactive() {
	let (db, finding) = fixture();
	db.with_conn(|conn|{
        conn.execute_batch("CREATE TABLE deferred_failure(job_id INTEGER REFERENCES jobs(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER fail_verification_commit AFTER INSERT ON verification_attempt_details BEGIN INSERT INTO deferred_failure VALUES(999999); END;")?;
        Ok(())
    }).unwrap();
	let mut escaped = None;
	let result: Result<()> = with_phase_transaction(
		&db,
		identity(),
		|| 102,
		|tx| {
			let value = tx.finalize_verification(&evidence(), false, |_| {
				Ok(Some(PolicyDecision::Ordinary))
			})?;
			let reports::Preparation::Ready(batch) = value.reporting else { panic!("ready batch") };
			escaped = Some(batch);
			Ok(())
		},
	);
	assert!(matches!(result, Err(Error::Sqlite(rusqlite::Error::SqliteFailure(..)))));
	assert!(matches!(escaped.unwrap().check_committed(), Err(Error::ReportReceipt)));
	assert_unfinished(&db, finding);
}
#[test]
fn successful_commit_activates_exact_batch_and_replay_does_not_select_reports() {
	let (db, finding) = fixture();
	let value = with_phase_transaction(
		&db,
		identity(),
		|| 102,
		|tx| {
			let value = tx.finalize_verification(&evidence(), false, |_| {
				Ok(Some(PolicyDecision::Ordinary))
			})?;
			let reports::Preparation::Ready(batch) = &value.reporting else {
				panic!("ready batch")
			};
			assert!(matches!(batch.check_committed(), Err(Error::ReportReceipt)));
			Ok::<_, Error>(value)
		},
	)
	.unwrap();
	let reports::Preparation::Ready(mut batch) = value.reporting else { panic!("ready batch") };
	batch.check_committed().unwrap();
	assert_eq!(batch.entries().len(), 1);
	assert_eq!(batch.entries()[0].id(), finding);
	db.with_conn(|conn|{
        conn.execute_batch("UPDATE registered_repos SET reporting='broken'; UPDATE review_campaigns SET state='cancelled'; DELETE FROM review_generations;")?;
        Ok(())
    }).unwrap();
	let replay = with_phase_transaction(
		&db,
		identity(),
		|| 20000,
		|tx| tx.finalize_verification(&evidence(), false, |_| panic!("replay policy")),
	)
	.unwrap();
	assert_eq!(replay.receipt, value.receipt);
	assert!(matches!(replay.reporting, reports::Preparation::NoReport));
	assert_eq!(batch.mark_one(&db, finding, 20000).unwrap(), 1);
}
