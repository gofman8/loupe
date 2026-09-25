//! Newly reserved phase state must participate in the upgrade admission gate.
use crate::{Db, Error};

fn fixture() -> Db {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		let policy = serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?1", [policy])?;
		conn.execute_batch("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
		VALUES(501,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0);
		INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity)
		VALUES(401,1,101,'review','high','title','description','key','confirmed',0,zeroblob(16));
		INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at)
		VALUES(601,11,'unit','title','objective','[]',0);
		INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,completed,assignment_epoch)
		VALUES(101,601,0,0,0);
		UPDATE jobs SET prepared_attempt=1,prepared_capability_hash=zeroblob(32),prepared_at=0 WHERE id=101;")?;
		for (table, subject, id) in [
			("lead_drilldown_intents", "lead_id", 501),
			("finding_verification_intents", "finding_id", 401),
		] {
			conn.execute(&format!("INSERT INTO {table}
			({subject},repo_id,generation_id,originating_job_id,originating_campaign_id,
			admission_campaign_id,source_commit_sha,profile_version,profile_digest,
			intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,
			priority_policy_version,created_at,updated_at)
			VALUES(?1,1,11,101,1,1,'base',1,zeroblob(32),1,'initial_handoff',0,'pending','normal',0,1,0,0)"),[id])?;
		}
		super::admission::validate(conn)
	}).unwrap();
	db
}

#[test]
fn v7_intent_revisions_are_admitted_from_stored_bytes() {
	let db = fixture();
	db.with_conn(|conn| {
		for table in ["lead_drilldown_intents", "finding_verification_intents"] {
			let sql = format!("UPDATE {table} SET source_commit_sha=?1");
			conn.execute(&sql, ["private-v7-revision\u{1b}"])?;
			let error = super::admission::validate(conn)
				.expect_err("new intent revision must not bypass stored text admission");
			let Error::Migration(failure) = &error else { panic!("closed migration error") };
			assert_eq!(failure.table, Some(table));
			assert_eq!(failure.column, Some("source_commit_sha"));
			assert!(!format!("{error} {error:?}").contains("private-v7-revision"));
			let raw: String =
				conn.query_row(&format!("SELECT source_commit_sha FROM {table}"), [], |row| {
					row.get(0)
				})?;
			assert_eq!(raw, "private-v7-revision\u{1b}", "refusal must preserve stored content");
			conn.execute(&sql, [" base cafe\u{301} "])?;
			super::admission::validate(conn)?;
			let raw: String =
				conn.query_row(&format!("SELECT source_commit_sha FROM {table}"), [], |row| {
					row.get(0)
				})?;
			assert_eq!(raw, " base cafe\u{301} ", "admission must not normalize revision bytes");
		}
		Ok(())
	})
	.unwrap();
}

#[test]
fn v7_preparation_and_assignment_scalars_are_admitted() {
	let db = fixture();
	db.with_conn(|conn| {
		for (table, column) in [
			("jobs", "prepared_attempt"),
			("jobs", "prepared_at"),
			("job_assigned_review_units", "assignment_epoch"),
		] {
			let tx = conn.transaction()?;
			let target = if table == "jobs" { "id=101" } else { "job_id=101" };
			tx.execute(
				&format!("UPDATE {table} SET {column}='private-v7-scalar' WHERE {target}"),
				[],
			)?;
			let error = super::admission::validate(&tx)
				.expect_err("new phase scalar must not bypass stored type admission");
			let Error::Migration(failure) = error else { panic!("closed migration error") };
			assert_eq!(failure.table, Some(table));
			assert_eq!(failure.column, Some(column));
			assert_eq!(failure.reason, super::MigrationReason::SqlType);
			tx.rollback()?;
		}
		super::admission::validate(conn)
	})
	.unwrap();
}
