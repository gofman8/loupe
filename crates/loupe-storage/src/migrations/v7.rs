//! Offline, lossless inventory and retained evidence upgrade.
//! Transaction, admission, markers and FK restoration belong to the framework.

use rusqlite::{Connection, OptionalExtension};

use super::v3::Step;
use super::{
	MigrationFailure as Failure, MigrationReason as Reason, MigrationResult,
	MigrationStage as Stage, Probe,
};

mod schema;

const COPIES: &[(&str, &str)] = &[
	("generation_inventory", "inventory_entry_id, generation_id, path, blob_sha, entry_kind, disposition, disposition_reason, highlighted, created_at"),
	("finding_review_details", "finding_id, repo_id, workflow_contract_version, profile_version, profile_digest, reviewed_commit_sha, identity_family, identity_anchor, identity_instance_key, identity_fingerprint, l2_argument, counterevidence, assumptions_gaps, confidence, submitted_rung, origin_lead_id, created_at, source"),
	("verification_attempt_details", "verification_id, workflow_contract_version, checkout_commit_sha, established_rung, e2e_applicability, e2e_rationale, blocker, retry_condition, verification_proof_id, terminal_digest, created_at, source"),
];

pub(super) fn run(conn: &Connection, probe: &mut Probe<'_>) -> MigrationResult {
	let mut stage = Stage::PreCheck;
	let result = (|| -> crate::Result<()> {
		probe(Step::PreCheck, conn)?;
		let leased: Option<i64> = conn
			.query_row("SELECT id FROM jobs WHERE state='leased' ORDER BY id LIMIT 1", [], |row| {
				row.get(0)
			})
			.optional()?;
		if let Some(rowid) = leased {
			return Err(Failure::new(stage, Reason::LeasedJobs)
				.at("jobs", "state", Some(rowid))
				.into());
		}
		stage = Stage::Tables;
		conn.execute_batch(schema::REBUILDS)?;
		probe(Step::Tables, conn)?;
		stage = Stage::Copy;
		for (table, columns) in COPIES {
			conn.execute_batch(&format!(
				"INSERT INTO {table}_new ({columns}) SELECT {columns} FROM {table};"
			))?;
		}
		// Display text is not raw identity. Validate the original SQL column
		// with the Db-marked path reader; never decode escapes or normalize.
		{
			let mut entries = conn.prepare(
				"SELECT inventory_entry_id, path FROM generation_inventory
				 WHERE disposition_reason IS NULL OR disposition_reason <> 'unrepresentable-path'",
			)?;
			let mut rows = entries.query([])?;
			let mut project = conn.prepare(
				"UPDATE generation_inventory_new SET source_path=?1 WHERE inventory_entry_id=?2",
			)?;
			while let Some(row) = rows.next()? {
				let id: i64 = row.get(0)?;
				// Malformed SQL types/UTF-8 refuse migration, as before. A valid
				// string that is not a RepoPath retains only its display value.
				let _: String = row.get(1)?;
				if let Ok(path) = crate::ingress::inventory_path(row, 1, true) {
					project.execute(rusqlite::params![path.expose(), id])?;
				}
			}
		}
		probe(Step::Copy, conn)?;
		stage = Stage::VerifyCopy;
		probe(Step::VerifyCopy, conn)?;
		for (table, columns) in COPIES {
			let equal: bool = conn.query_row(
				&format!(
				"SELECT (SELECT COUNT(*) FROM {table}) = (SELECT COUNT(*) FROM {table}_new)
				 AND NOT EXISTS (SELECT {columns} FROM {table} EXCEPT SELECT {columns} FROM {table}_new)
				 AND NOT EXISTS (SELECT {columns} FROM {table}_new EXCEPT SELECT {columns} FROM {table})"
			),
				[],
				|row| row.get(0),
			)?;
			if !equal {
				let mut failure = Failure::new(stage, Reason::CopyMismatch);
				failure.table = Some(table);
				return Err(failure.into());
			}
		}
		stage = Stage::Replace;
		for (table, _) in COPIES {
			conn.execute_batch(&format!(
				"DROP TABLE {table}; ALTER TABLE {table}_new RENAME TO {table};"
			))?;
		}
		probe(Step::Replace, conn)?;
		stage = Stage::Indexes;
		conn.execute_batch(schema::ADDITIONS)?;
		probe(Step::Indexes, conn)?;
		Ok(())
	})();
	result.map_err(|error| match error {
		crate::Error::Migration(failure) => failure,
		crate::Error::Sqlite(error) => Failure::sqlite(stage, error),
		_ => Failure::new(stage, Reason::InvalidData),
	})
}
