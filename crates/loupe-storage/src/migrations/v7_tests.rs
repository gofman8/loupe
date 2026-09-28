use rusqlite::params;
use rusqlite::types::Value;

use super::fixtures::*;
use super::*;

pub(super) fn populated_v3(conn: &mut Connection) {
	settled(conn);
	apply_migrations(conn, &MIGRATIONS[..3]).unwrap();
	super::ownership_tests::seed_two_projects(conn);
	conn.execute_batch(
		"UPDATE review_generations SET generated_profile = '{ \"old\": \"unchanged\" }',
             profile_version = 7, generated_profile_digest = x'123456', inventory_digest = x'abcdef'
         WHERE generation_id = 11;
         UPDATE finding_review_details SET profile_digest = x'001122',
             l2_argument = '{ \"verbatim\": true }', counterevidence = 'same', assumptions_gaps = 'size'
         WHERE finding_id = 11;
         UPDATE verification_attempt_details SET terminal_digest = x'0022ff' WHERE verification_id = 11;
         UPDATE review_unit_results SET produced_by_job_id = review_unit_id,
             corroborates_inventory_exclusion_id = review_unit_id;
         UPDATE review_units SET assignment_epoch = 9;
         UPDATE generation_inventory SET disposition = 'excluded', disposition_reason = 'old exclusion'
         WHERE inventory_entry_id = 11;",
	).unwrap();
	for (id, path, reason) in [
		(31, "src/%FF.rs".to_owned(), Some("unrepresentable-path")),
		(32, "src/%FE.rs".to_owned(), None),
		(33, "../outside".to_owned(), None),
		(34, "a".repeat(513), None),
		(35, "src/e\u{301}.rs".to_owned(), None),
		(36, "src/é.rs".to_owned(), None),
		(37, "src/control\0.rs".to_owned(), None),
		(38, "src/\u{202e}name.rs".to_owned(), None),
	] {
		conn.execute(
			"INSERT INTO generation_inventory (inventory_entry_id, generation_id, path,
                 entry_kind, disposition, disposition_reason, created_at)
             VALUES (?1, 11, ?2, 'tracked', 'excluded', ?3, 101)",
			params![id, path, reason],
		)
		.unwrap();
	}
}

pub(super) fn populated_v6(conn: &mut Connection) {
	populated_v3(conn);
	apply_migrations(conn, &MIGRATIONS[..6]).unwrap();
}

#[test]
fn v7_classifies_historical_profiles_without_rewriting_them() {
	let mut conn = Connection::open_in_memory().unwrap();
	populated_v6(&mut conn);
	let before = rows(&conn,"SELECT generation_id,generated_profile,generated_profile_digest,profile_version FROM review_generations ORDER BY generation_id");
	apply_pending(&mut conn).unwrap();
	let has_source:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('review_generations') WHERE name='generated_profile_source')",[],|row|row.get(0)).unwrap();
	assert!(has_source, "profiles need durable content-source metadata");
	assert_eq!(rows(&conn,"SELECT generation_id,generated_profile,generated_profile_digest,profile_version FROM review_generations ORDER BY generation_id"),before);
	let wrong: i64 = conn
		.query_row(
			"SELECT COUNT(*) FROM review_generations WHERE generated_profile_source<>'agent'",
			[],
			|row| row.get(0),
		)
		.unwrap();
	assert_eq!(
		wrong, 0,
		"historical source is a conservative content classification, not authorship"
	);
	apply_pending(&mut conn).unwrap();
	assert_eq!(rows(&conn,"SELECT generation_id,generated_profile,generated_profile_digest,profile_version FROM review_generations ORDER BY generation_id"),before);
}

pub(super) struct Snapshot(Vec<(String, Vec<Vec<Value>>)>);

impl Snapshot {
	pub(super) fn take(conn: &Connection) -> Self {
		// v5 identity backfill fires FTS maintenance and may merge internal
		// index pages. Preserve every canonical table and logical FTS result,
		// not a particular layout of the four derived shadow tables.
		let tables: Vec<String> = conn
			.prepare(
				"SELECT name FROM sqlite_master WHERE type = 'table'
			 AND name NOT IN ('schema_meta', 'findings_fts_config', 'findings_fts_data',
			                  'findings_fts_docsize', 'findings_fts_idx') ORDER BY name",
			)
			.unwrap()
			.query_map([], |r| r.get(0))
			.unwrap()
			.collect::<rusqlite::Result<_>>()
			.unwrap();
		let mut snapshot = Self(
			tables
				.into_iter()
				.map(|table| {
					let columns: Vec<String> = conn
						.prepare(&format!("PRAGMA table_info('{table}')"))
						.unwrap()
						.query_map([], |r| r.get(1))
						.unwrap()
						.collect::<rusqlite::Result<_>>()
						.unwrap();
					let columns = columns.join(", ");
					let query = format!("SELECT {columns} FROM {table} ORDER BY {columns}");
					let values = rows(conn, &query);
					(query, values)
				})
				.collect(),
		);
		let search = "SELECT rowid FROM findings_fts WHERE findings_fts MATCH 'sentinel OR canonical' ORDER BY rowid";
		snapshot.0.push((search.into(), rows(conn, search)));
		snapshot
	}

	pub(super) fn assert_unchanged(&self, conn: &Connection) {
		for (query, expected) in &self.0 {
			assert_eq!(&rows(conn, query), expected, "historical bytes changed: {query}");
		}
	}
}

#[test]
fn v7_preserves_all_populated_v6_bytes_and_unknown_raw_identity() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v6.sqlite");
	let mut conn = open(&path);
	populated_v6(&mut conn);
	conn.execute_batch("UPDATE finding_review_details SET source=CASE finding_id WHEN 11 THEN 'operator' ELSE 'agent' END;
		UPDATE verification_attempt_details SET source=CASE verification_id WHEN 11 THEN 'repo' ELSE 'worker' END;").unwrap();
	let before = Snapshot::take(&conn);
	apply_pending(&mut conn).unwrap();
	assert_eq!(markers(&conn), (7, 7));
	before.assert_unchanged(&conn);
	assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());
	assert_eq!(rows(&conn, "PRAGMA integrity_check"), vec![vec![Value::Text("ok".into())]]);
	assert_eq!(rows(&conn, "SELECT COUNT(*) FROM generation_inventory WHERE raw_path IS NOT NULL OR git_mode IS NOT NULL OR manifest_position IS NOT NULL OR disposition_revision <> 0"), vec![vec![0.into()]]);
	assert_eq!(rows(&conn, "SELECT COUNT(*) FROM jobs WHERE prepared_attempt IS NOT NULL OR prepared_capability_hash IS NOT NULL OR prepared_at IS NOT NULL"), vec![vec![0.into()]]);
	assert_eq!(
		rows(
			&conn,
			"SELECT COUNT(*) FROM job_assigned_review_units WHERE assignment_epoch IS NOT NULL"
		),
		vec![vec![0.into()]]
	);
	for id in [11, 12, 32, 35, 36] {
		assert_eq!(rows(&conn, &format!("SELECT source_path = path FROM generation_inventory WHERE inventory_entry_id = {id}")), vec![vec![1.into()]]);
	}
	for id in [31, 33, 34, 37, 38] {
		assert_eq!(rows(&conn, &format!("SELECT source_path IS NULL FROM generation_inventory WHERE inventory_entry_id = {id}")), vec![vec![1.into()]]);
	}
	for table in [
		"generation_manifests",
		"generation_inventory_units",
		"job_terminal_payloads",
		"lead_drilldown_intents",
		"finding_verification_intents",
		"survey_continuation_batches",
		"review_unit_holds",
		"campaign_admission_spending",
		"job_admission_charges",
	] {
		assert!(
			rows(&conn, &format!("SELECT * FROM {table}")).is_empty(),
			"migration invented {table}"
		);
	}
	drop(conn);
	let mut conn = open(&path);
	apply_pending(&mut conn).unwrap();
	before.assert_unchanged(&conn);
}

#[test]
fn v7_refuses_unsupported_source_without_relabeling_or_committing_either_marker() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("source.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
	super::ownership_tests::seed_two_projects(&conn);
	apply_migrations(&mut conn, &MIGRATIONS[..6]).unwrap();
	let policy = serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap();
	conn.execute("UPDATE review_campaigns SET effective_policy=?1", [policy]).unwrap();
	conn.execute("UPDATE finding_review_details SET source='operator' WHERE finding_id=11", [])
		.unwrap();
	let before = Snapshot::take(&conn);
	let old_schema = schema(&conn);
	drop(conn);
	let error = match crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()) {
		Err(error) => error,
		Ok(_) => {
			panic!("unsupported stored source must refuse the entire v7 upgrade, never relabel it")
		},
	};
	let crate::Error::Migration(failure) = error else { panic!("closed migration failure") };
	assert_eq!(failure.reason, MigrationReason::Source);
	assert_eq!(failure.table, Some("finding_review_details"));
	assert_eq!((failure.source_version, failure.target_version), (Some(6), 7));
	let conn = open(&path);
	assert_eq!(markers(&conn), (6, 6));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
}

#[test]
fn published_github_app_v4_receives_b4_storage_upgrade() {
	let mut conn = Connection::open_in_memory().unwrap();
	populated_v3(&mut conn);
	apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
	assert_eq!(markers(&conn), (4, 4), "start from the published GitHub App schema");
	conn.execute_batch(
		"UPDATE registered_repos SET reporting = '{\"kind\":\"github_issue\",\"target_owner\":\"owner\",\"target_repo\":\"tracker\"}' WHERE id = 1;
		 INSERT INTO secrets (kind, label, value, created_at)
		 VALUES ('github_app', 'server-app', x'0011ff', 123);",
	).unwrap();
	let before = Snapshot::take(&conn);
	apply_pending(&mut conn).unwrap();
	let installed: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='generation_manifests')",
		[], |row| row.get(0),
	).unwrap();
	assert!(installed, "B4 storage must be installed after published schema v4");
	assert_eq!(markers(&conn), (7, 7));
	before.assert_unchanged(&conn);
}

#[test]
fn b4_refusal_after_v3_rolls_back_every_pending_version_and_retries() {
	let mut conn = Connection::open_in_memory().unwrap();
	populated_v3(&mut conn);
	busy(&conn);
	let before = Snapshot::take(&conn);
	let error = apply_pending(&mut conn).expect_err("leased work must refuse B4 migration");
	assert_eq!(markers(&conn), (3, 3), "every pending version rolls back together");
	assert!(matches!(
		error,
		crate::Error::Migration(MigrationFailure { reason: MigrationReason::LeasedJobs, .. })
	));
	before.assert_unchanged(&conn);
	conn.execute("UPDATE jobs SET state = 'cancelled' WHERE id = 9", []).unwrap();
	apply_pending(&mut conn).unwrap();
	assert_eq!(markers(&conn), (7, 7));
}

#[test]
fn v7_installs_storage_contract_on_fresh_and_older_databases() {
	for initial in 0..=6 {
		let mut conn = Connection::open_in_memory().unwrap();
		conn.pragma_update(None, "foreign_keys", true).unwrap();
		if initial != 0 {
			apply_migrations(&mut conn, &MIGRATIONS[..initial]).unwrap();
		}
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (7, 7), "storage contract requires schema v7");
		for table in [
			"generation_manifests",
			"generation_inventory_units",
			"job_terminal_payloads",
			"lead_drilldown_intents",
			"finding_verification_intents",
			"review_unit_holds",
			"survey_continuation_batches",
			"campaign_admission_spending",
			"job_admission_charges",
		] {
			conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
		}
		assert!(fk_enabled(&conn));
		let before = schema(&conn);
		conn.pragma_update(None, "user_version", 0).unwrap();
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (7, 7));
		assert_eq!(schema(&conn), before);
	}
}
