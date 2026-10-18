use super::*;

fn refused_version_trigger(trigger: &str, stage: MigrationStage, reason: MigrationReason) {
	use super::fixtures::{open, rows, schema, settled};
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("version.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	apply_migrations(&mut conn, &MIGRATIONS[..3]).unwrap();
	conn.execute_batch(trigger).unwrap();
	let before_schema = schema(&conn);
	let tables: Vec<String> = conn
		.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
		.unwrap()
		.query_map([], |row| row.get(0))
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap();
	let snapshot = |conn: &Connection| {
		tables
			.iter()
			.map(|table| rows(conn, &format!("SELECT * FROM {table} ORDER BY 1")))
			.collect::<Vec<_>>()
	};
	let before_rows = snapshot(&conn);
	drop(conn);
	let error = match crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()) {
		Err(error) => error,
		Ok(_) => panic!("version-trigger inconsistency must refuse the whole upgrade"),
	};
	let crate::Error::Migration(failure) = error else { panic!("expected migration error") };
	assert_eq!(failure.stage, stage);
	assert_eq!(failure.reason, reason);
	assert_eq!((failure.source_version, failure.target_version), (Some(3), LATEST_SCHEMA_VERSION));
	assert!(!format!("{failure} {failure:?}").contains("private-trigger-input"));
	let conn = open(&path);
	assert_eq!(markers(&conn), (3, 3));
	assert_eq!(schema(&conn), before_schema);
	assert_eq!(snapshot(&conn), before_rows);
	conn.execute_batch("DROP TRIGGER private_version_trigger;").unwrap();
	drop(conn);
	let db = crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	drop(db);
	crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()).unwrap();
}

#[test]
fn suppressed_version_write_refuses_upgrade_without_changes() {
	refused_version_trigger(
		"CREATE TRIGGER private_version_trigger BEFORE UPDATE OF version ON schema_meta
		 BEGIN SELECT RAISE(IGNORE); END;",
		MigrationStage::WriteVersion,
		MigrationReason::InvalidVersion,
	);
}

#[test]
fn rewritten_version_marker_refuses_upgrade_without_changes() {
	refused_version_trigger(
		"CREATE TRIGGER private_version_trigger AFTER UPDATE OF version ON schema_meta
		 BEGIN UPDATE schema_meta SET version=3 WHERE id=1; END;",
		MigrationStage::WriteVersion,
		MigrationReason::InvalidVersion,
	);
}

#[test]
fn version_write_side_effects_are_validated_before_commit() {
	refused_version_trigger(
		"CREATE TRIGGER private_version_trigger AFTER UPDATE OF version ON schema_meta
		 BEGIN UPDATE jobs SET kind='private-trigger-input' WHERE id=1; END;",
		MigrationStage::Finalize,
		MigrationReason::UnknownJobKind,
	);
}

#[test]
fn atomic_upgrade_rolls_back_before_a_structural_failure() {
	fn fail(_conn: &Connection, _: &mut Probe<'_>) -> MigrationResult {
		Err(MigrationFailure::new(MigrationStage::PreCheck, MigrationReason::Database))
	}
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(&mut conn, &[FIRST, Migration::Structural { version: 2, run: fail }])
		.unwrap_err();
	assert_eq!(markers(&conn), (0, 0), "failed upgrade must retain both original markers");
	assert!(conn.prepare("SELECT * FROM jobs").is_err());
}

#[test]
fn atomic_upgrade_v1_refusal_preserves_all_legacy_rows() {
	use super::fixtures::{rows, schema, unknown_kind, v1, LEGACY_TABLES};
	let mut conn = Connection::open_in_memory().unwrap();
	v1(&mut conn);
	unknown_kind(&conn);
	let before = schema(&conn);
	let tables: Vec<_> = LEGACY_TABLES.iter().copied().chain(["jobs", "schema_meta"]).collect();
	let contents: Vec<_> =
		tables.iter().map(|t| rows(&conn, &format!("SELECT * FROM {t} ORDER BY id"))).collect();
	apply_pending(&mut conn).unwrap_err();
	assert_eq!(markers(&conn), (1, 1), "a refused v1 upgrade must remain v1");
	assert_eq!(schema(&conn), before);
	for (table, expected) in tables.into_iter().zip(contents) {
		assert_eq!(rows(&conn, &format!("SELECT * FROM {table} ORDER BY id")), expected);
	}
}

#[test]
fn atomic_upgrade_rejects_malformed_version_metadata() {
	for sql in [
		"CREATE TABLE schema_meta(id, version);",
		"CREATE TABLE schema_meta(id, version); INSERT INTO schema_meta VALUES (1, 'private-marker');",
		"CREATE TABLE schema_meta(id, version); INSERT INTO schema_meta VALUES (1, 1), (1, 2);",
	] {
		let conn = Connection::open_in_memory().unwrap();
		conn.execute_batch(sql).unwrap();
		assert!(current_schema_version(&conn).is_err(), "malformed metadata must not become version zero");
	}
}

#[test]
fn atomic_upgrade_restoration_failure_preserves_original_schema() {
	use super::fixtures::{schema, settled};
	let mut conn = Connection::open_in_memory().unwrap();
	settled(&mut conn);
	let before = schema(&conn);
	super::v3::run_with_probe(&mut conn, &mut |step, _| {
		if step == super::v3::Step::Restore {
			Err(rusqlite::Error::InvalidQuery)
		} else {
			Ok(())
		}
	})
	.unwrap_err();
	assert_eq!(markers(&conn), (2, 2), "FK restoration must succeed before committing");
	assert_eq!(schema(&conn), before);
}

const FIRST: Migration = Migration::Sql { version: 1, sql: V1_INITIAL };
const LAST: Migration =
	Migration::Sql { version: 3, sql: "CREATE TABLE after_structural (value INTEGER);" };

fn markers(conn: &Connection) -> (u32, u32) {
	(
		current_schema_version(conn).unwrap(),
		conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap(),
	)
}

fn structural(conn: &Connection, _: &mut Probe<'_>) -> MigrationResult {
	assert!(!conn.is_autocommit(), "structural migration must share the upgrade transaction");
	assert_eq!(
		conn.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0)).unwrap(),
		0
	);
	assert!(conn.prepare("SELECT * FROM after_structural").is_err());
	conn.execute_batch("CREATE TABLE structural (value INTEGER);")
		.map_err(|e| MigrationFailure::sqlite(MigrationStage::Tables, e))
}

#[test]
fn structural_migration_shares_the_sql_transaction() {
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(
		&mut conn,
		&[FIRST, Migration::Structural { version: 2, run: structural }, LAST],
	)
	.unwrap();
	assert_eq!(markers(&conn), (3, 3));
	conn.prepare("SELECT * FROM structural, after_structural").unwrap();
}

#[test]
fn structural_failure_rolls_back_the_prior_sql_batch() {
	fn fail(conn: &Connection, _: &mut Probe<'_>) -> MigrationResult {
		assert!(!conn.is_autocommit());
		conn.execute_batch("CREATE TABLE rolled_back (value INTEGER);").unwrap();
		Err(MigrationFailure::new(MigrationStage::Tables, MigrationReason::Database))
	}
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(&mut conn, &[FIRST, Migration::Structural { version: 2, run: fail }, LAST])
		.unwrap_err();
	assert_eq!(markers(&conn), (0, 0));
	assert!(conn.prepare("SELECT * FROM rolled_back").is_err());
	assert!(conn.prepare("SELECT * FROM after_structural").is_err());
}

#[test]
fn framework_records_the_structural_migration_version() {
	fn transform(conn: &Connection, _: &mut Probe<'_>) -> MigrationResult {
		conn.execute_batch("CREATE TABLE transformed (value INTEGER);")
			.map_err(|e| MigrationFailure::sqlite(MigrationStage::Tables, e))
	}
	let mut conn = Connection::open_in_memory().unwrap();
	let migrations = [FIRST, Migration::Structural { version: 2, run: transform }];
	apply_migrations(&mut conn, &migrations).unwrap();
	assert_eq!(markers(&conn), (2, 2));
	apply_migrations(&mut conn, &migrations).unwrap();
	conn.prepare("SELECT * FROM transformed").unwrap();
}

#[test]
fn consecutive_sql_migrations_roll_back_together() {
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(
		&mut conn,
		&[FIRST, Migration::Sql { version: 2, sql: "INSERT INTO missing VALUES (1);" }],
	)
	.unwrap_err();
	assert_eq!(markers(&conn), (0, 0));
	assert!(conn.prepare("SELECT * FROM jobs").is_err());
}

#[test]
fn sql_only_upgrade_and_stale_mirror_recovery() {
	let mut conn = Connection::open_in_memory().unwrap();
	let migrations = [FIRST, Migration::Sql { version: 2, sql: V2_JOB_CAPABILITIES }];
	apply_migrations(&mut conn, &migrations).unwrap();
	assert_eq!(markers(&conn), (2, 2));
	conn.prepare("SELECT job_capability_hash FROM jobs").unwrap();
	conn.pragma_update(None, "user_version", 0).unwrap();
	apply_migrations(&mut conn, &migrations).unwrap();
	assert_eq!(markers(&conn), (2, 2));
}

#[test]
fn failed_finalizer_rolls_back_all_versions_and_preserves_a_stale_mirror() {
	use super::fixtures::{rows, schema, settled};
	let mut conn = Connection::open_in_memory().unwrap();
	settled(&mut conn);
	conn.pragma_update(None, "user_version", 1).unwrap();
	let before = schema(&conn);
	let jobs = rows(&conn, "SELECT * FROM jobs ORDER BY id");
	let error = apply_pending_with_finalizer(&mut conn, |tx, upgrading| {
		assert!(upgrading);
		assert!(!tx.is_autocommit());
		crate::scheduler::ensure_state(tx)?;
		Err(rusqlite::Error::SqliteFailure(
			rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
			Some("private row payload".into()),
		)
		.into())
	})
	.unwrap_err();
	assert!(matches!(
		&error,
		crate::Error::Migration(MigrationFailure {
			source_version: Some(2),
			target_version: LATEST_SCHEMA_VERSION,
			stage: MigrationStage::Finalize,
			..
		})
	));
	assert!(!format!("{error} {error:?}").contains("private row payload"));
	assert!(std::error::Error::source(&error).is_none());
	assert_eq!(markers(&conn), (2, 1));
	assert_eq!(schema(&conn), before);
	assert_eq!(rows(&conn, "SELECT * FROM jobs ORDER BY id"), jobs);
	assert!(conn.prepare("SELECT * FROM temp.scheduler_clock").is_err());
	apply_pending_with_finalizer(&mut conn, |_, upgrading| {
		assert!(upgrading);
		Ok(())
	})
	.unwrap();
	apply_pending_with_finalizer(&mut conn, |_, upgrading| {
		assert!(!upgrading);
		Ok(())
	})
	.unwrap();
	assert_eq!(markers(&conn), (LATEST_SCHEMA_VERSION, LATEST_SCHEMA_VERSION));
}
