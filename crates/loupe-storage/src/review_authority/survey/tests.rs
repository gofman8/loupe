//! Storage-owned survey transaction boundary controls.
use std::cell::Cell;

use super::*;
use crate::review_authority::with_phase_transaction;
use crate::{jobs, terminal_payloads, test_support as input, Db};

const HASH: [u8; 32] = [0; 32];
fn identity() -> jobs::LeaseIdentity<'static> {
	jobs::LeaseIdentity { job_id: 101, worker_id: 1, capability_hash: &HASH }
}
fn payload() -> SurveyTerminalV1<Agent> {
	input::agent(
		r#"{"version":1,"terminal_reason":"partial","security_model_notes":"retained literal notes"}"#,
		|raw, mark| SurveyTerminalV1::from_json(mark, raw),
	)
	.unwrap()
}
fn fixture() -> Db {
	let db = crate::review_intents::tests::fixture();
	db.with_conn(|conn| {
        conn.execute("UPDATE jobs SET hard_deadline_at=10000,prepared_at=1,prepared_attempt=attempts,prepared_capability_hash=job_capability_hash,recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=101",[])?;
        Ok(())
    }).unwrap();
	db
}
fn finish(db: &Db) -> Result<SurveyFinalization> {
	with_phase_transaction(
		db,
		identity(),
		|| 100,
		|tx| tx.finalize_survey(&payload(), |_| Ok(Some(PolicyDecision::Ordinary))),
	)
}
fn assert_unfinished(db: &Db) {
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT state FROM jobs WHERE id=101", [], |row| row
				.get::<_, String>(0))?,
			"leased"
		);
		for table in
			["job_terminal_receipts", "job_terminal_payloads", "survey_continuation_batches"]
		{
			assert_eq!(
				conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
					.get::<_, i64>(0))?,
				0
			);
		}
		Ok(())
	})
	.unwrap();
}

#[test]
fn callback_encoding_failure_rolls_back_terminal_state_and_audit() {
	let db = fixture();
	let result: Result<()> = with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let receipt = tx.finalize_survey(&payload(), |_| Ok(Some(PolicyDecision::Ordinary)))?;
			let mut one_byte = [0u8; 1];
			assert!(
				serde_json::to_writer(one_byte.as_mut_slice(), &receipt.summary).is_err(),
				"exercise a real final response encoding failure"
			);
			Err(Error::Conflict(Conflict::TerminalReceipt))
		},
	);
	assert!(result.is_err());
	assert_unfinished(&db);
	let receipt = finish(&db).unwrap();
	assert_eq!(receipt.commit.expose(), crate::review_intents::tests::SHA);
	let _: &loupe_core::review_metadata::ReviewCommit<loupe_provenance::Db> = &receipt.commit;
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT source FROM job_terminal_payloads", [], |row| row
				.get::<_, String>(0))?,
			"agent"
		);
		let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Survey(stored)) =
			terminal_payloads::get(&input::scope(conn, 1), 101)?
		else {
			panic!("typed terminal audit")
		};
		assert_eq!(stored, payload());
		assert_eq!(
			conn.query_row("SELECT worker_id FROM jobs WHERE id=101", [], |row| row
				.get::<_, i64>(0))?,
			1
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn replay_and_conflict_do_not_call_live_policy_or_derived_readers() {
	let db = fixture();
	let first = finish(&db).unwrap();
	db.with_conn(|conn| {
		conn.execute(
			"UPDATE review_campaigns SET state='cancelled',effective_policy='malformed'",
			[],
		)?;
		conn.execute("DELETE FROM review_generations", [])?;
		Ok(())
	})
	.unwrap();
	let called = Cell::new(false);
	let replay = with_phase_transaction(
		&db,
		identity(),
		|| 20000,
		|tx| {
			tx.finalize_survey(&payload(), |_| {
				called.set(true);
				Err(Error::ScopeDenied)
			})
		},
	)
	.unwrap();
	assert_eq!(replay, first);
	let mut different = payload();
	different.terminal_reason = loupe_core::review_payload::SurveyTerminalReason::Deferred;
	let conflict = with_phase_transaction(
		&db,
		identity(),
		|| 20000,
		|tx| {
			tx.finalize_survey(&different, |_| {
				called.set(true);
				Err(Error::ScopeDenied)
			})
		},
	);
	assert!(matches!(conflict, Err(Error::Conflict(Conflict::TerminalReceipt))));
	assert!(!called.get());
}

#[test]
fn frozen_profile_and_numeric_policy_are_admitted_from_original_sql() {
	for sql in [
        "UPDATE review_generations SET generated_profile_source='db' WHERE generation_id=11",
        "UPDATE review_generations SET generated_profile_source='worker' WHERE generation_id=11",
        "UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11",
        "UPDATE review_generations SET generated_profile=' { \"languages\" : [\"rust\"] } ' WHERE generation_id=11",
        "UPDATE review_campaigns SET effective_policy_digest=zeroblob(32) WHERE campaign_id=1",
    ] {
        let db=fixture();
        db.with_conn(|conn|{conn.execute(sql,[])?;Ok(())}).unwrap();
        assert!(finish(&db).is_err(),"{sql}");
        assert_unfinished(&db);
    }
	finish(&fixture()).unwrap();
}

#[test]
fn foreign_malformed_state_is_not_admitted_for_an_owned_finalization() {
	let db = fixture();
	db.with_conn(|conn| {
        conn.execute("UPDATE review_generations SET generated_profile='malformed',generated_profile_source='worker' WHERE repo_id=2",[])?;
        conn.execute("UPDATE review_campaigns SET effective_policy='malformed' WHERE repo_id=2",[])?;
        Ok(())
    }).unwrap();
	finish(&db).unwrap();
}

#[test]
fn finalizer_requires_live_domain_readiness_but_includes_exact_lease_expiry() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET lease_expires_at=100 WHERE id=101", [])?;
		Ok(())
	})
	.unwrap();
	finish(&db).unwrap();
	for sql in [
        "UPDATE jobs SET lease_expires_at=99 WHERE id=101",
        "UPDATE jobs SET lease_expires_at=x'ff' WHERE id=101",
        "UPDATE jobs SET job_capability_hash=printf('%032d',0) WHERE id=101",
		"UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101",
        "UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL WHERE generation_id=11",
    ] {
        let db=fixture();
		db.with_conn(|conn|{conn.execute(sql,[])?;Ok(())}).unwrap_or_else(|error|panic!("fixture mutation failed: {sql}: {error}"));
        assert!(finish(&db).is_err(),"{sql}");
        assert_unfinished(&db);
    }
}

#[test]
fn composed_audit_keeps_payload_depth_bounds_and_rolls_back() {
	let db = fixture();
	let mut recipe = serde_json::json!("leaf");
	for _ in 0..15 {
		recipe = serde_json::json!({"nested":recipe});
	}
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET recipe=?1 WHERE id=101", [recipe.to_string()])?;
		Ok(())
	})
	.unwrap();
	// The test policy deliberately accepts this bounded stored recipe. The
	// extra audit nesting must still be checked through the durable SQL reader.
	assert!(finish(&db).is_err());
	assert_unfinished(&db);
}
