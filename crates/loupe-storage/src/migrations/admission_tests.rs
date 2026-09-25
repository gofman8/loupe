use rusqlite::types::Value;
use rusqlite::Connection;

use super::{apply_migrations, fixtures, MIGRATIONS};
use crate::secrets::MasterKey;
use crate::{Db, Error};

const PRIVATE: &str = "private-upgrade-payload\u{1b}";

pub(super) fn snapshot(conn: &Connection) -> Vec<(String, Vec<Vec<Value>>)> {
	let names: Vec<String> = conn
		.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
		.unwrap()
		.query_map([], |r| r.get(0))
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap();
	names
		.into_iter()
		.map(|name| {
			let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
			let rows = fixtures::rows(conn, &sql);
			(name, rows)
		})
		.collect()
}

fn rich_v5(conn: &mut Connection) {
	fixtures::v1(conn);
	apply_migrations(conn, &MIGRATIONS[..5]).unwrap();
	conn.execute_batch(r#"
INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(11,1,'base','retired',1,0);
INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,created_at) VALUES(11,1,'bootstrap','manual','base',11,'finished','{}',zeroblob(32),0);
INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,entry_kind,created_at) VALUES(11,11,'src/lib.rs','tracked',0);
INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,status,source_refs,created_at) VALUES(11,11,'unit','title','objective','retired','[]',0);
INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,invalidated,created_at) VALUES(11,11,'base',1,'not_applicable','[]','{}',zeroblob(32),1,0);
INSERT INTO leads(lead_id,generation_id,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(11,11,'closed','stale','family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0);
INSERT INTO lead_observations(lead_observation_id,lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES(11,11,'{}',zeroblob(32),'base',0);
INSERT INTO job_checkpoints(job_checkpoint_id,job_id,client_key,operation,payload_digest,response,created_at) VALUES(11,1,'submit_lead:key','submit_lead',zeroblob(32),'{}',0);
INSERT INTO job_terminal_receipts(job_terminal_receipt_id,job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,created_at) VALUES(11,1,'scan','complete','base','{}',zeroblob(32),0);
INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at) VALUES(1,1,1,1,'base','family','anchor',zeroblob(32),'{}','counterevidence','assumptions','high','L2',0);
INSERT INTO verification_attempt_details(verification_id,workflow_contract_version,checkout_commit_sha,e2e_applicability,e2e_rationale,terminal_digest,created_at) VALUES(1,1,'base','not_applicable','rationale',zeroblob(32),0);
INSERT INTO proof_artifact_blobs(proof_artifact_blob_id,repo_id,sha256,byte_len,content,created_at) VALUES(11,1,zeroblob(32),1,x'61',0);
INSERT INTO proof_artifacts(proof_artifact_id,repo_id,proof_artifact_blob_id,artifact_role,media_type,original_name,sha256,byte_len,created_at) VALUES(11,1,11,'crafted_input','text/plain','sample.txt',zeroblob(32),1,0);
INSERT INTO staged_proof_artifacts(staged_proof_artifact_id,repo_id,job_id,proof_artifact_blob_id,artifact_role,media_type,original_name,created_at) VALUES(11,1,1,11,'crafted_input','text/plain','sample.txt',0);
INSERT INTO proof_executions(proof_execution_id,repo_id,produced_by_job_id,target_commit_sha,clean_tree,argv,working_dir,env_names,fixture_artifact_ids,network_policy,limits,timeout_seconds,started_at,duration_ms,created_at) VALUES(11,1,1,'base',1,'[]','.','[]','[11]','isolated','{}',1,0,1,0);
INSERT INTO verification_proofs(verification_proof_id,finding_id,verification_id,repo_id,rung,pinned_commit_sha,manifest,manifest_digest,created_at) VALUES(11,4,1,1,'L3','base','{}',zeroblob(32),0);
INSERT INTO secrets(id,kind,label,value,created_at) VALUES(11,'github_app','server',x'7b7d',0);
"#).unwrap();
	let policy = serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap();
	conn.execute("UPDATE review_campaigns SET effective_policy=?1", [policy]).unwrap();
	conn.execute(
		"UPDATE secrets SET value=?1 WHERE id=11",
		[br#"{"app_id":1,"slug":"application","private_key_pem":"opaque PEM"}"#.as_slice()],
	)
	.unwrap();
}

fn refuse(table: &'static str, column: &'static str, rowid: i64, bad: Value) {
	refuse_after(table, column, rowid, bad, |_| {});
}

fn refuse_cross_repo_job(table: &'static str, original_job: i64) {
	for version in [4, 5] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("upgrade.sqlite");
		let mut conn = fixtures::open(&path);
		fixtures::v1(&mut conn);
		apply_migrations(&mut conn, &MIGRATIONS[..version]).unwrap();
		conn.execute_batch("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(90,2,'scan','succeeded',0);").unwrap();
		let sql = format!("UPDATE {table} SET job_id=?1 WHERE id=1");
		conn.execute(&sql, [90]).unwrap();
		let schema = fixtures::schema(&conn);
		let before = snapshot(&conn);
		drop(conn);
		let error = match Db::open(&path, &MasterKey::for_tests()) {
			Err(error) => error,
			Ok(_) => panic!("upgrade must refuse cross-repository {table}.job_id"),
		};
		let Error::Migration(failure) = error else { panic!("expected migration failure") };
		assert_eq!(failure.table, Some(table));
		assert_eq!(failure.column, Some("job_id"));
		assert_eq!(failure.rowid, Some(1));
		assert_eq!(failure.stage, super::MigrationStage::Admission);
		assert_eq!(failure.reason, super::MigrationReason::ForeignKeyViolation);
		assert_eq!(failure.source_version, Some(u32::try_from(version).unwrap()));
		assert_eq!(failure.target_version, super::LATEST_SCHEMA_VERSION);
		let conn = fixtures::open(&path);
		assert_eq!(
			fixtures::markers(&conn),
			(u32::try_from(version).unwrap(), u32::try_from(version).unwrap())
		);
		assert_eq!(fixtures::schema(&conn), schema);
		assert_eq!(snapshot(&conn), before);
		conn.execute(&sql, [original_job]).unwrap();
		drop(conn);
		let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
		assert_eq!(db.schema_version().unwrap(), super::LATEST_SCHEMA_VERSION);
	}
}

#[test]
fn upgrade_admission_finding_job_owner() {
	refuse_cross_repo_job("findings", 1);
}

#[test]
fn upgrade_admission_verification_job_owner() {
	refuse_cross_repo_job("finding_verifications", 2);
}

#[test]
fn upgrade_admission_history_job_owner() {
	refuse_cross_repo_job("scan_history", 1);
}

#[test]
fn upgrade_admission_scanner_selected_text() {
	for document in [
		r#"{"include_extensions":["private-upgrade-payload\u001b"]}"#,
		r#"{"exclude_path_substrings":["some\npath"]}"#,
		r#"[null,null,null,["rs\u001b"]]"#,
		r#"{"max_file_bytes":false,"exclude_path_substrings":[42,"bad\n"]}"#,
	] {
		refuse("registered_repos", "scanner_config", 1, document.to_owned().into());
	}
}

#[test]
fn upgrade_admission_repository_cache_components() {
	for column in ["host", "owner", "repo"] {
		for value in ["", ".", "..", "bad/part", "bad\\part"] {
			refuse("registered_repos", column, 1, value.to_owned().into());
		}
	}
}

#[test]
fn upgrade_preserves_scanner_projection_compatibility() {
	for document in [
		"{malformed",
		"null",
		"42",
		r#"{"include_extensions":["bad\n"],"include_extensions":[" rs ","café"]}"#,
		r#"{"include_extensions":42,"exclude_path_substrings":[false," valid "]}"#,
		r#"{"unknown":"ignored\u001b","include_extensions":[]}"#,
		r#"[null,null,null,["rs"],[" file:*test* "],"ignored\n"]"#,
	] {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("scanner.sqlite");
		let mut conn = fixtures::open(&path);
		fixtures::v1(&mut conn);
		apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
		conn.execute("UPDATE registered_repos SET host='user@github.com',owner=' café ',scanner_config=?1 WHERE id=1", [document]).unwrap();
		drop(conn);
		let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
		db.with_conn(|conn| {
			let stored: (String, String, String) = conn.query_row(
				"SELECT host,owner,scanner_config FROM registered_repos WHERE id=1",
				[],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
			assert_eq!(stored, ("user@github.com".into(), " café ".into(), document.into()));
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn upgrade_admission_queued_scan_start_overflow() {
	refuse("jobs", "started_at", 7, i64::MIN.into());
}

#[test]
fn upgrade_admission_leased_scan_start_overflow() {
	refuse_after_upgrade(6, "jobs", "started_at", 7, i64::MAX.into(), |conn| {
		conn.execute_batch(
			"UPDATE jobs SET state='leased',worker_id=1,
		 lease_expires_at=9223372036854775807,job_capability_hash=zeroblob(32) WHERE id=7;",
		)
		.unwrap();
	});
}

#[test]
fn upgrade_admission_preserves_representable_scan_start() {
	for start in [-1, 0, 1, 1_800_000_000] {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("timestamps.sqlite");
		let mut conn = fixtures::open(&path);
		rich_v5(&mut conn);
		conn.execute("UPDATE jobs SET started_at=?1 WHERE id=7", [start]).unwrap();
		drop(conn);
		let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
		assert_eq!(db.schema_version().unwrap(), super::LATEST_SCHEMA_VERSION);
		let conn = fixtures::open(&path);
		assert_eq!(
			conn.query_row("SELECT started_at FROM jobs WHERE id=7", [], |row| row
				.get::<_, i64>(0))
				.unwrap(),
			start
		);
	}
}

#[test]
fn upgrade_admission_missing_builtin_kind() {
	for version in [4, 5] {
		for kind in ["scan", "verify", "survey", "drilldown"] {
			let dir = tempfile::tempdir().unwrap();
			let path = dir.path().join("upgrade.sqlite");
			let mut conn = fixtures::open(&path);
			apply_migrations(&mut conn, &MIGRATIONS[..version]).unwrap();
			let original: (i64, i64) = conn
				.query_row("SELECT rowid,legacy FROM job_kinds WHERE kind=?1", [kind], |r| {
					Ok((r.get(0)?, r.get(1)?))
				})
				.unwrap();
			assert_eq!(conn.execute("DELETE FROM job_kinds WHERE kind=?1", [kind]).unwrap(), 1);
			let schema = fixtures::schema(&conn);
			let before = snapshot(&conn);
			drop(conn);
			let error = match Db::open(&path, &MasterKey::for_tests()) {
				Err(error) => error,
				Ok(_) => panic!("upgrade must refuse missing built-in kind {kind}"),
			};
			let Error::Migration(failure) = error else { panic!("expected migration failure") };
			assert_eq!(failure.table, Some("job_kinds"));
			assert_eq!(failure.column, Some("kind"));
			assert_eq!(failure.rowid, None);
			assert_eq!(failure.stage, super::MigrationStage::Admission);
			assert_eq!(failure.reason, super::MigrationReason::MissingRequiredJobKind);
			assert_eq!(failure.field, Some(kind));
			assert_eq!(failure.source_version, Some(u32::try_from(version).unwrap()));
			assert_eq!(failure.target_version, super::LATEST_SCHEMA_VERSION);
			let conn = fixtures::open(&path);
			assert_eq!(
				fixtures::markers(&conn),
				(u32::try_from(version).unwrap(), u32::try_from(version).unwrap())
			);
			assert_eq!(fixtures::schema(&conn), schema);
			assert_eq!(snapshot(&conn), before);
			conn.execute(
				"INSERT INTO job_kinds(rowid,kind,legacy) VALUES(?1,?2,?3)",
				(original.0, kind, original.1),
			)
			.unwrap();
			drop(conn);
			assert_eq!(
				Db::open(&path, &MasterKey::for_tests()).unwrap().schema_version().unwrap(),
				super::LATEST_SCHEMA_VERSION
			);
		}
	}
}

fn refuse_after(
	table: &'static str, column: &'static str, rowid: i64, bad: Value,
	setup: impl FnOnce(&Connection),
) {
	refuse_after_upgrade(super::LATEST_SCHEMA_VERSION, table, column, rowid, bad, setup);
}

fn refuse_after_upgrade(
	target: u32, table: &'static str, column: &'static str, rowid: i64, bad: Value,
	setup: impl FnOnce(&Connection),
) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("upgrade.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	setup(&conn);
	let sql = format!("UPDATE {table} SET {column}=?1 WHERE rowid=?2");
	let original: Value = conn
		.query_row(&format!("SELECT {column} FROM {table} WHERE rowid=?1"), [rowid], |r| r.get(0))
		.unwrap();
	conn.execute(&sql, (&bad, rowid)).unwrap();
	let schema = fixtures::schema(&conn);
	let before = snapshot(&conn);
	drop(conn);
	let open = || {
		if target == super::LATEST_SCHEMA_VERSION {
			Db::open(&path, &MasterKey::for_tests())
		} else {
			// v7 requires an offline queue before admission. Keep the earlier
			// leased-row policy controls on the published v6 upgrade itself.
			assert_eq!(target, 6);
			Db::bootstrap_with_migration(
				Connection::open(&path).unwrap(),
				&MasterKey::for_tests(),
				|conn| {
					super::apply_with_finalizer(
						conn,
						&MIGRATIONS[..6],
						|conn, _| crate::jobs::validate_stored_rows(conn),
						&mut |_, _| Ok(()),
					)
				},
			)
		}
	};
	let error = match open() {
		Err(error) => error,
		Ok(_) => panic!("upgrade admission must reject invalid {table}.{column} row {rowid}"),
	};
	let Error::Migration(failure) = &error else {
		panic!("expected safe migration failure: {error}")
	};
	assert_eq!(failure.table, Some(table));
	assert_eq!(failure.column, Some(column));
	assert_eq!(failure.rowid, Some(rowid));
	assert_eq!(failure.stage, super::MigrationStage::Admission);
	assert_eq!(failure.source_version, Some(5));
	assert_eq!(failure.target_version, target);
	assert!(!format!("{error} {error:?} {error:#}").contains("private-upgrade-payload"));
	assert!(std::error::Error::source(&error).is_none());
	let conn = fixtures::open(&path);
	assert_eq!(fixtures::markers(&conn), (5, 5));
	assert_eq!(fixtures::schema(&conn), schema);
	assert_eq!(snapshot(&conn), before);
	conn.execute(&sql, (&original, rowid)).unwrap();
	drop(conn);
	let db = open().unwrap();
	assert_eq!(db.schema_version().unwrap(), target);
}

macro_rules! rejects {
	($name:ident, $table:literal, $column:literal, $id:expr, $bad:expr) => {
		#[test]
		fn $name() {
			refuse($table, $column, $id, $bad);
		}
	};
}
rejects!(
	upgrade_admission_disabled_repo,
	"registered_repos",
	"owner",
	3,
	PRIVATE.to_owned().into()
);
rejects!(upgrade_admission_revoked_worker, "workers", "name", 2, PRIVATE.to_owned().into());
rejects!(upgrade_admission_cancelled_job, "jobs", "error", 4, PRIVATE.to_owned().into());
rejects!(upgrade_admission_later_finding, "findings", "title", 6, PRIVATE.to_owned().into());
rejects!(upgrade_admission_verdict, "finding_verifications", "notes", 1, PRIVATE.to_owned().into());
rejects!(upgrade_admission_history, "scan_history", "head_sha", 1, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_campaign,
	"review_campaigns",
	"effective_policy",
	11,
	"{}".to_owned().into()
);
rejects!(
	upgrade_admission_retired_generation,
	"review_generations",
	"generated_profile",
	11,
	"[}".to_owned().into()
);
rejects!(
	upgrade_admission_inventory,
	"generation_inventory",
	"path",
	11,
	"../private-upgrade-payload".to_owned().into()
);
rejects!(upgrade_admission_retired_unit, "review_units", "title", 11, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_unit_refs,
	"review_units",
	"source_refs",
	11,
	r#"[{"path":"../private-upgrade-payload"}]"#.to_owned().into()
);
rejects!(
	upgrade_admission_invalidated_result,
	"review_unit_results",
	"result_payload",
	11,
	"[}".to_owned().into()
);
rejects!(upgrade_admission_closed_lead, "leads", "identity_family", 11, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_observation,
	"lead_observations",
	"observation_payload",
	11,
	"[}".to_owned().into()
);
rejects!(upgrade_admission_checkpoint, "job_checkpoints", "response", 11, "[}".to_owned().into());
rejects!(
	upgrade_admission_receipt,
	"job_terminal_receipts",
	"terminal_reason",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_review_details,
	"finding_review_details",
	"counterevidence",
	1,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_attempt_details,
	"verification_attempt_details",
	"blocker",
	1,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_artifact,
	"proof_artifacts",
	"original_name",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_staged_artifact,
	"staged_proof_artifacts",
	"media_type",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_execution,
	"proof_executions",
	"working_dir",
	11,
	"../private-upgrade-payload".to_owned().into()
);
rejects!(
	upgrade_admission_execution_fixtures,
	"proof_executions",
	"fixture_artifact_ids",
	11,
	"{}".to_owned().into()
);
rejects!(upgrade_admission_proof, "verification_proofs", "manifest", 11, "[}".to_owned().into());
rejects!(
	upgrade_admission_full_app,
	"secrets",
	"value",
	11,
	br#"{"app_id":1,"slug":"application","private_key_pem":12}"#.to_vec().into()
);
rejects!(
	upgrade_admission_blob_type,
	"jobs",
	"job_capability_hash",
	4,
	"private-upgrade-payload".to_owned().into()
);

rejects!(upgrade_admission_missing_verify_target, "jobs", "target_finding_id", 8, 999999.into());
rejects!(upgrade_admission_null_verify_target, "jobs", "target_finding_id", 8, Value::Null);
rejects!(upgrade_admission_negative_attempts, "jobs", "attempts", 7, (-1).into());
rejects!(upgrade_admission_overflow_attempts, "jobs", "attempts", 7, i64::MAX.into());
rejects!(
	upgrade_admission_exhausted_attempts_range,
	"jobs",
	"attempts",
	7,
	i64::from(u32::MAX).into()
);
rejects!(upgrade_admission_negative_line_start, "findings", "line_start", 6, (-1).into());
rejects!(upgrade_admission_negative_line_end, "findings", "line_end", 6, (-1).into());
rejects!(
	upgrade_admission_overflow_line_start,
	"findings",
	"line_start",
	6,
	(i64::from(u32::MAX) + 1).into()
);
rejects!(
	upgrade_admission_overflow_line_end,
	"findings",
	"line_end",
	6,
	(i64::from(u32::MAX) + 1).into()
);

#[test]
fn upgrade_admission_foreign_verify_target() {
	refuse_after("jobs", "target_finding_id", 8, 6.into(), |conn| {
		conn.execute_batch(
			"INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(90,2,'scan','succeeded',0);
UPDATE findings SET repo_id=2,job_id=90 WHERE id=6;",
		)
		.unwrap();
	});
}

#[test]
fn upgrade_admission_missing_leased_verify_target() {
	refuse_after_upgrade(6, "jobs", "target_finding_id", 8, 999999.into(), |conn| {
		conn.execute("UPDATE jobs SET state='leased' WHERE id=8", []).unwrap();
	});
}

fn scheduling_relations(conn: &Connection) {
	conn.execute_batch(r#"
INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(12,2,'other','retired',1,0),(13,1,'successor','retired',1,0);
INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,created_at) SELECT 12,2,recipe,trigger,'other',12,state,effective_policy,effective_policy_digest,created_at FROM review_campaigns WHERE campaign_id=11;
INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,created_at) SELECT 13,1,recipe,trigger,'successor',13,state,effective_policy,effective_policy_digest,created_at FROM review_campaigns WHERE campaign_id=11;
INSERT INTO leads(lead_id,generation_id,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) SELECT 12,12,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,'other',created_at FROM leads WHERE lead_id=11;
INSERT INTO leads(lead_id,generation_id,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) SELECT 13,13,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,'successor',created_at FROM leads WHERE lead_id=11;
INSERT INTO jobs(id,repo_id,kind,state,enqueued_at,campaign_id,generation_id) VALUES(11,1,'scan','succeeded',0,11,11),(12,2,'scan','succeeded',0,12,12),(13,1,'scan','succeeded',0,13,13);
UPDATE jobs SET campaign_id=11,generation_id=11,assigned_lead_id=11 WHERE id=7;
"#).unwrap();
}

macro_rules! rejects_scheduling_relation {
	($name:ident, $table:literal, $column:literal, $id:expr, $bad:expr) => {
		#[test]
		fn $name() {
			refuse_after($table, $column, $id, $bad.into(), scheduling_relations);
		}
	};
}
rejects_scheduling_relation!(
	upgrade_admission_foreign_job_generation,
	"jobs",
	"generation_id",
	7,
	12
);
rejects_scheduling_relation!(upgrade_admission_foreign_job_lead, "jobs", "assigned_lead_id", 7, 12);
rejects_scheduling_relation!(
	upgrade_admission_wrong_job_lead_generation,
	"jobs",
	"assigned_lead_id",
	7,
	13
);
rejects_scheduling_relation!(
	upgrade_admission_foreign_job_continuation,
	"jobs",
	"continuation_of_job_id",
	7,
	12
);
rejects_scheduling_relation!(
	upgrade_admission_wrong_job_continuation_campaign,
	"jobs",
	"continuation_of_job_id",
	7,
	13
);
rejects_scheduling_relation!(
	upgrade_admission_foreign_campaign_generation,
	"review_campaigns",
	"generation_id",
	11,
	12
);
rejects_scheduling_relation!(
	upgrade_admission_foreign_campaign_root,
	"review_campaigns",
	"root_campaign_id",
	11,
	12
);
rejects_scheduling_relation!(
	upgrade_admission_foreign_campaign_continuation,
	"review_campaigns",
	"continuation_of_campaign_id",
	11,
	12
);
rejects_scheduling_relation!(
	upgrade_admission_foreign_generation_predecessor,
	"review_generations",
	"predecessor_generation_id",
	11,
	12
);

#[test]
fn upgrade_preserves_terminal_targets_and_numeric_boundaries() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compatible.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	conn.execute_batch(
		"UPDATE jobs SET target_finding_id=NULL WHERE id=2;
UPDATE jobs SET target_finding_id=999999 WHERE id=4;
INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(90,2,'scan','succeeded',0);
UPDATE findings SET repo_id=2,job_id=90 WHERE id=6;
UPDATE jobs SET target_finding_id=6 WHERE id=6;",
	)
	.unwrap();
	conn.execute("UPDATE jobs SET attempts=?1 WHERE id=1", [u32::MAX]).unwrap();
	conn.execute("UPDATE jobs SET attempts=?1 WHERE id=7", [u32::MAX - 1]).unwrap();
	conn.execute("UPDATE findings SET line_start=0,line_end=?1 WHERE id=6", [u32::MAX]).unwrap();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		assert_eq!(crate::jobs::get_raw(conn, 1)?.unwrap().attempts, u32::MAX);
		let finding = crate::findings::get_raw(conn, 6)?.unwrap();
		assert_eq!(finding.line_start, Some(0));
		assert_eq!(finding.line_end, Some(u32::MAX));
		assert_eq!(crate::jobs::get_raw(conn, 2)?.unwrap().target_finding_id, None);
		assert_eq!(crate::jobs::get_raw(conn, 4)?.unwrap().target_finding_id, Some(999999));
		assert_eq!(crate::jobs::get_raw(conn, 6)?.unwrap().target_finding_id, Some(6));
		crate::transaction::immediate(conn, |tx| {
			let claimed = crate::scheduler::claim_raw(
				tx,
				&crate::scheduler::ClaimRequest {
					worker_id: 1,
					kinds: &[loupe_core::JobKind::<loupe_provenance::Db>::Scan],
					now: 1000,
					capability_hash: &[9; 32],
					legacy_lease_seconds: 600,
					policy: &crate::scheduler::ClaimPolicy::default(),
				},
			)?
			.unwrap();
			assert_eq!(claimed.job.id, 7);
			assert_eq!(claimed.job.attempts, u32::MAX);
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn upgrade_preserves_owned_scheduling_links_and_deleted_generations() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compatible.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	scheduling_relations(&conn);
	conn.execute_batch(
		"UPDATE review_generations SET predecessor_generation_id=13 WHERE generation_id=11;
UPDATE review_campaigns SET root_campaign_id=13,continuation_of_campaign_id=13 WHERE campaign_id=11;
UPDATE jobs SET continuation_of_job_id=11 WHERE id=7;
DELETE FROM review_generations WHERE generation_id=12;",
	)
	.unwrap();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		let job = crate::jobs::get_raw(conn, 7)?.unwrap();
		assert_eq!(job.generation_id, Some(11));
		assert_eq!(job.assigned_lead_id, Some(11));
		assert_eq!(job.continuation_of_job_id, Some(11));
		assert_eq!(crate::jobs::get_raw(conn, 12)?.unwrap().generation_id, None);
		assert_eq!(crate::campaigns::get_raw(conn, 12)?.unwrap().generation_id, None);
		let campaign = crate::campaigns::get_raw(conn, 11)?.unwrap();
		assert_eq!(campaign.root_campaign_id, Some(13));
		assert_eq!(campaign.continuation_of_campaign_id, Some(13));
		assert_eq!(
			crate::generations::get_raw(conn, 11)?.unwrap().predecessor_generation_id,
			Some(13)
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn upgrade_admission_every_historical_version_is_atomic() {
	for version in 1..=5 {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("upgrade.sqlite");
		let mut conn = fixtures::open(&path);
		fixtures::v1(&mut conn);
		apply_migrations(&mut conn, &MIGRATIONS[..version]).unwrap();
		conn.execute("UPDATE registered_repos SET owner=?1 WHERE id=3", [PRIVATE]).unwrap();
		if version == 1 {
			conn.execute("UPDATE jobs SET state='leased' WHERE id=3", []).unwrap();
		}
		let schema = fixtures::schema(&conn);
		let before = snapshot(&conn);
		drop(conn);
		assert!(
			Db::open(&path, &MasterKey::for_tests()).is_err(),
			"upgrade admission must reject invalid v{version} data"
		);
		let conn = fixtures::open(&path);
		assert_eq!(fixtures::markers(&conn), (version as u32, version as u32));
		assert_eq!(fixtures::schema(&conn), schema);
		assert_eq!(snapshot(&conn), before);
		conn.execute("UPDATE registered_repos SET owner='c' WHERE id=3", []).unwrap();
		drop(conn);
		assert_eq!(
			Db::open(&path, &MasterKey::for_tests()).unwrap().schema_version().unwrap(),
			super::LATEST_SCHEMA_VERSION
		);
	}
}

#[test]
fn upgrade_preserves_compatible_bytes_and_all_table_contents() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compatible.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	conn.execute(
		"UPDATE registered_repos SET owner=?1,scanner_config='{malformed' WHERE id=3",
		[" cafe\u{301}  "],
	)
	.unwrap();
	conn.execute(
		"UPDATE registered_repos SET reporting=?1 WHERE id=2",
		[r#"["email",["same","same"],null,""]"#],
	)
	.unwrap();
	conn.execute("UPDATE findings SET description=?1 WHERE id=6", ["one\r\ntwo cafe\u{301}  "])
		.unwrap();
	conn.execute_batch("UPDATE generation_inventory SET path='../display-alias',disposition='excluded',disposition_reason='unrepresentable-path';
INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(1,'initialize_survey_batch:ordinary','initialize_survey_batch',zeroblob(32),'{}',0);
INSERT INTO job_kinds VALUES('future.phase',0);
INSERT INTO jobs(repo_id,kind,state,enqueued_at) VALUES(1,'future.phase','succeeded',0);").unwrap();
	let before = snapshot(&conn);
	// Save historical projections so the new source metadata does not hide
	// any changes to old fields. Include derived FTS table contents as well.
	let projections: Vec<_> = before
		.iter()
		.map(|(table, _)| {
			let names: Vec<String> = conn
				.prepare(&format!("PRAGMA table_info({table})"))
				.unwrap()
				.query_map([], |r| r.get(1))
				.unwrap()
				.collect::<rusqlite::Result<_>>()
				.unwrap();
			(table.clone(), names.join(","))
		})
		.collect();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), super::LATEST_SCHEMA_VERSION);
	db.with_conn(|conn| {
		for ((table, expected), (_, columns)) in before.iter().zip(&projections) {
			if table != "schema_meta" {
				assert_eq!(
					&fixtures::rows(conn, &format!("SELECT {columns} FROM {table}")),
					expected,
					"old content changed in {table}"
				);
			}
		}
		// Generic write-only sources are valid classifications, and content
		// admission must not reinterpret them as Agent fields.
		for table in [
			"verification_attempt_details",
			"proof_artifacts",
			"staged_proof_artifacts",
			"proof_executions",
			"verification_proofs",
		] {
			conn.execute(&format!("UPDATE {table} SET source='config'"), [])?;
		}
		super::admission::validate(conn)?;
		Ok(())
	})
	.unwrap();
	drop(db);
	assert_eq!(
		Db::open(&path, &MasterKey::for_tests()).unwrap().schema_version().unwrap(),
		super::LATEST_SCHEMA_VERSION
	);
}
