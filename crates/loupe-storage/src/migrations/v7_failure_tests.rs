use std::panic::{catch_unwind, AssertUnwindSafe};

use super::fixtures::*;
use super::v3::Step;
use super::v7_tests::{populated_v6, Snapshot};
use super::*;

fn run_with_probe(conn: &mut Connection, probe: &mut Probe<'_>) -> crate::Result<()> {
	apply_with_finalizer(conn, MIGRATIONS, |_, _| Ok(()), probe)
}

#[test]
fn v7_precommit_failures_reopen_as_complete_v6_and_retry() {
	for step in [
		Step::PreCheck,
		Step::Tables,
		Step::Copy,
		Step::VerifyCopy,
		Step::Replace,
		Step::Indexes,
		Step::ForeignKeyCheck,
		Step::IntegrityCheck,
		Step::Commit,
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("v6.sqlite");
		let mut conn = open(&path);
		populated_v6(&mut conn);
		let before = Snapshot::take(&conn);
		let old_schema = schema(&conn);
		let error = run_with_probe(&mut conn, &mut |at, _| {
			if at == step {
				Err(rusqlite::Error::InvalidQuery)
			} else {
				Ok(())
			}
		})
		.expect_err("precommit failure must roll back v7");
		assert!(matches!(error, crate::Error::Migration(_)));
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (6, 6), "{step:?}");
		assert_eq!(schema(&conn), old_schema, "{step:?}");
		before.assert_unchanged(&conn);
		apply_migrations(&mut conn, &MIGRATIONS[..6]).unwrap();
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (7, 7));
		before.assert_unchanged(&conn);
	}
}

#[test]
fn v7_checks_exact_copies_and_foreign_key_and_integrity_validation() {
	for (at, sql, expected) in [
		(Step::VerifyCopy, "UPDATE generation_inventory_new SET path = 'src/bib.rs' WHERE inventory_entry_id = 11", MigrationReason::CopyMismatch),
		(Step::VerifyCopy, "UPDATE finding_review_details_new SET counterevidence = assumptions_gaps, assumptions_gaps = counterevidence WHERE finding_id = 11", MigrationReason::CopyMismatch),
		(Step::VerifyCopy, "UPDATE finding_review_details_new SET profile_digest = x'332211' WHERE finding_id = 11", MigrationReason::CopyMismatch),
		(Step::VerifyCopy, "UPDATE verification_attempt_details_new SET terminal_digest = x'ff2200' WHERE verification_id = 11", MigrationReason::CopyMismatch),
		(Step::ForeignKeyCheck, "UPDATE verification_attempt_details SET verification_proof_id = 12 WHERE verification_id = 11", MigrationReason::ForeignKeyViolation),
		(Step::IntegrityCheck, "PRAGMA ignore_check_constraints = ON; UPDATE generation_inventory SET disposition_revision = -1 WHERE inventory_entry_id = 11; PRAGMA ignore_check_constraints = OFF;", MigrationReason::IntegrityViolation),
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("v6.sqlite");
		let mut conn = open(&path);
		populated_v6(&mut conn);
		let old_schema = schema(&conn);
		let before = Snapshot::take(&conn);
		let error = run_with_probe(&mut conn, &mut |step, conn| {
			if step == at { conn.execute_batch(sql)?; }
			Ok(())
		}).expect_err("validation must detect injected corruption");
		let crate::Error::Migration(failure) = error else { panic!("closed migration failure") };
		assert_eq!(failure.reason, expected);
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (6, 6));
		assert_eq!(schema(&conn), old_schema);
		before.assert_unchanged(&conn);
		apply_pending(&mut conn).unwrap();
	}
}

#[test]
fn v7_refuses_leases_before_ddl_and_holds_the_write_lock() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v6.sqlite");
	let mut conn = open(&path);
	populated_v6(&mut conn);
	busy(&conn);
	let old_schema = schema(&conn);
	let before = Snapshot::take(&conn);
	let error = run_with_probe(&mut conn, &mut |step, _| {
		assert!(matches!(step, Step::PreCheck | Step::Restore), "DDL must not start");
		Ok(())
	})
	.unwrap_err();
	assert!(matches!(
		error,
		crate::Error::Migration(MigrationFailure {
			reason: MigrationReason::LeasedJobs,
			rowid: Some(9),
			..
		})
	));
	assert!(fk_enabled(&conn));
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (6, 6));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
	apply_migrations(&mut conn, &MIGRATIONS[..6]).unwrap();
	conn.execute("UPDATE jobs SET state = 'cancelled' WHERE id = 9", []).unwrap();
	let writer = open(&path);
	writer.busy_timeout(std::time::Duration::ZERO).unwrap();
	let mut checked = false;
	run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::PreCheck {
			let error =
				writer.execute("UPDATE jobs SET state = 'leased' WHERE id = 7", []).unwrap_err();
			assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
			checked = true;
		}
		Ok(())
	})
	.unwrap();
	assert!(checked);
	assert_eq!(markers(&conn), (7, 7));
}

#[test]
fn v7_restores_prior_foreign_keys_after_errors_panics_and_success() {
	for prior in [false, true] {
		for fail_at in [None, Some(Step::Copy), Some(Step::Restore)] {
			for panic in [false, true] {
				let mut conn = Connection::open_in_memory().unwrap();
				populated_v6(&mut conn);
				conn.pragma_update(None, "foreign_keys", prior).unwrap();
				let result = catch_unwind(AssertUnwindSafe(|| {
					run_with_probe(&mut conn, &mut |step, _| {
						if Some(step) == fail_at {
							assert!(!panic, "injected panic");
							return Err(rusqlite::Error::InvalidQuery);
						}
						Ok(())
					})
				}));
				if panic && fail_at.is_some() {
					assert!(result.is_err());
				} else {
					assert_eq!(result.unwrap().is_err(), fail_at.is_some());
				}
				assert!(conn.is_autocommit());
				assert_eq!(fk_enabled(&conn), prior);
				let expected = if fail_at.is_some() { 6 } else { 7 };
				assert_eq!(markers(&conn), (expected, expected));
			}
		}
	}
}

#[test]
fn v7_restoration_failure_rolls_back_before_commit() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v6.sqlite");
	let mut conn = open(&path);
	populated_v6(&mut conn);
	let before = Snapshot::take(&conn);
	let old_schema = schema(&conn);
	run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::Restore {
			Err(rusqlite::Error::InvalidQuery)
		} else {
			Ok(())
		}
	})
	.unwrap_err();
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (6, 6));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
	assert!(fk_enabled(&conn));
	apply_pending(&mut conn).unwrap();
	assert_eq!(markers(&conn), (7, 7));
}

#[test]
fn v7_real_commit_failure_rolls_back_to_v6() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v6.sqlite");
	let mut conn = open(&path);
	populated_v6(&mut conn);
	conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
	conn.busy_timeout(std::time::Duration::ZERO).unwrap();
	let reader = Connection::open(&path).unwrap();
	reader
		.pragma_update(None, "key", crate::secrets::MasterKey::for_tests().sqlcipher_key().expose())
		.unwrap();
	reader.execute_batch("BEGIN; SELECT * FROM jobs;").unwrap();
	let before = Snapshot::take(&conn);
	let old_schema = schema(&conn);
	let mut reached_commit = false;
	let error = run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::Commit {
			reached_commit = true;
		}
		Ok(())
	})
	.unwrap_err();
	assert!(reached_commit, "{error}");
	assert!(matches!(
		error,
		crate::Error::Migration(MigrationFailure {
			sqlite_code: Some(rusqlite::ffi::SQLITE_BUSY),
			stage: MigrationStage::Commit,
			..
		})
	));
	assert!(fk_enabled(&conn));
	assert!(conn.is_autocommit());
	drop(reader);
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (6, 6));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
	apply_pending(&mut conn).unwrap();
}
