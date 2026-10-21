use rusqlite::types::Value;

use super::*;
use crate::Db;

fn fixture() -> Db {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE jobs SET state='succeeded';
			UPDATE review_campaigns SET state='cancelled';
			UPDATE review_generations SET state='retired' WHERE generation_id=12;
			UPDATE review_generations SET generated_profile='malformed' WHERE generation_id=11;
			INSERT INTO workers VALUES(1,'admin','admin',x'01',0,0,NULL);
			INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,closure_criteria,created_at)
				VALUES(31,11,'old','title','objective','[]',printf('%03000d',0),0);")?;
		Ok(())
	}).unwrap();
	db
}

fn snapshot(db: &Db) -> Vec<Vec<Vec<Value>>> {
	db.with_conn(|conn| {
		["review_generations", "review_units", "jobs", "review_campaigns"]
			.iter()
			.map(|table| {
				let mut statement =
					conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
				let count = statement.column_count();
				Ok(statement
					.query_map([], |row| (0..count).map(|i| row.get(i)).collect())?
					.collect::<rusqlite::Result<_>>()?)
			})
			.collect()
	})
	.unwrap()
}

#[test]
fn reset_rechecks_current_operator_before_target_or_callback() {
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='worker' WHERE id=1",
		"DELETE FROM workers WHERE id=1",
	] {
		let db = fixture();
		let token = crate::test_support::operator_ingress();
		db.with_conn(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap();
		let before = snapshot(&db);
		for generation in [11, 999] {
			let error = reset(
				&db,
				&token,
				1,
				generation,
				|| 500,
				|_| -> Result<()> {
					panic!("unauthorized callback");
				},
			)
			.unwrap_err();
			assert!(matches!(error, Error::ScopeDenied));
			assert_eq!(snapshot(&db), before);
		}
	}
}

#[test]
fn reset_callback_error_rolls_back_and_success_retains_exact_tombstone() {
	let db = fixture();
	let before = snapshot(&db);
	let operator = crate::test_support::operator_ingress();
	let error = reset(
		&db,
		&operator,
		1,
		11,
		|| 500,
		|summary| {
			assert_eq!(summary.review_units_removed, 1);
			Err::<(), _>(Error::Conflict(Conflict::Checkpoint))
		},
	)
	.unwrap_err();
	assert!(matches!(error, Error::Conflict(Conflict::Checkpoint)));
	assert_eq!(snapshot(&db), before);
	let summary = reset(&db, &operator, 1, 11, || 501, Ok::<_, Error>).unwrap();
	assert_eq!(summary.review_units_removed, 1);
	db.with_conn(|conn| {
		let identity: (i64, String, i64, i64, i64) = conn.query_row(
			"SELECT generation_id,generation_commit_sha,workflow_contract_version,created_at,retired_at
			 FROM review_generations WHERE generation_id=11", [],
			|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
		)?;
		assert_eq!(identity, (11, "base".into(), 1, 0, 501));
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM review_units WHERE generation_id=11", [], |r| {
				r.get::<_, i64>(0)
			})?,
			0
		);
		Ok(())
	})
	.unwrap();
}
