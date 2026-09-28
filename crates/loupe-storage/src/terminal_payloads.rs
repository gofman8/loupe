//! Job-owned canonical terminal audits. Lease authority and finalization remain
//! the caller's responsibility; insert the matching receipt in the same transaction.
use loupe_core::review_payload::{DrilldownTerminalV1, SurveyTerminalV1, VerificationTerminalV1};
use loupe_core::JobKind;
use loupe_provenance::{Agent, Db};
use rusqlite::{params, OptionalExtension};

use crate::review::classify;
use crate::{Conflict, Error, Result, StoredEvidence};

// debug-ok: terminal values delegate to redacted source-typed payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalPayload {
	Survey(SurveyTerminalV1<Agent>),
	Drilldown(DrilldownTerminalV1<Agent>),
	Verification(VerificationTerminalV1<Agent>),
}

impl TerminalPayload {
	pub fn phase(&self) -> JobKind<Db> {
		match self {
			Self::Survey(_) => JobKind::Survey,
			Self::Drilldown(_) => JobKind::Drilldown,
			Self::Verification(_) => JobKind::Verify,
		}
	}

	pub fn canonical_bytes(
		&self,
	) -> std::result::Result<Vec<u8>, loupe_core::review_payload::Error> {
		match self {
			Self::Survey(value) => value.canonical_bytes(),
			Self::Drilldown(value) => value.canonical_bytes(),
			Self::Verification(value) => value.canonical_bytes(),
		}
	}

	pub fn digest(&self) -> std::result::Result<[u8; 32], loupe_core::review_payload::Error> {
		Ok(loupe_core::canonical::digest(&self.canonical_bytes()?))
	}
}

/// Requires a receipt for this job with the same phase and canonical digest.
/// Propagate errors out of the caller's transaction to roll back its other writes.
pub fn insert(
	scope: &crate::scope::RepoScope<'_>, job_id: i64, payload: &TerminalPayload,
) -> Result<()> {
	scope.require_operator()?;
	insert_raw(scope.conn, scope.repo_id, job_id, payload)
}
pub(crate) fn insert_raw(
	tx: &rusqlite::Connection, repo: i64, job_id: i64, payload: &TerminalPayload,
) -> Result<()> {
	let bytes = payload.canonical_bytes()?;
	let digest = loupe_core::canonical::digest(&bytes);
	let matches: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM job_terminal_receipts r JOIN jobs j ON j.id=r.job_id
		 WHERE r.job_id=?1 AND r.phase=?2 AND j.kind=?2 AND j.campaign_id IS NOT NULL
		 AND r.result_digest=?3 AND j.repo_id=?4)",
		params![job_id, payload.phase().as_str(), digest.as_slice(), repo],
		|r| r.get(0),
	)?;
	if !matches {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	let raw = std::str::from_utf8(&bytes).map_err(|_| loupe_core::review_payload::Error::Json)?;
	tx.execute(
		"INSERT INTO job_terminal_payloads(job_id,phase,payload,source) VALUES (?1,?2,?3,'agent')",
		params![job_id, payload.phase().as_str(), raw],
	)
	.map_err(|error| classify(error, "job_terminal_payloads.job_id", Conflict::TerminalReceipt))?;
	Ok(())
}

const COLUMNS: &str = "job_id,phase,payload,source";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, TerminalPayload)> {
	crate::ingress::require_agent_source(r, 3)?;
	let phase = crate::ingress::job_kind(r, 1)?;
	let payload = match phase.as_str() {
		"survey" => TerminalPayload::Survey(crate::ingress::survey_terminal(r, 2)?),
		"drilldown" => TerminalPayload::Drilldown(crate::ingress::drilldown_terminal(r, 2)?),
		"verify" => TerminalPayload::Verification(crate::ingress::verification_terminal(r, 2)?),
		_ => {
			return Err(rusqlite::Error::FromSqlConversionFailure(
				1,
				rusqlite::types::Type::Text,
				Box::new(Error::Conflict(Conflict::TerminalReceipt)),
			))
		},
	};
	Ok((r.get(0)?, payload))
}
fn validate_binding(
	conn: &rusqlite::Connection, job: i64, payload: &TerminalPayload,
) -> Result<()> {
	let valid: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM job_terminal_receipts r JOIN jobs j ON j.id=r.job_id
		 WHERE r.job_id=?1 AND r.phase=?2 AND j.kind=?2 AND j.campaign_id IS NOT NULL
		 AND r.result_digest=?3)",
		params![job, payload.phase().as_str(), payload.digest()?.as_slice()],
		|r| r.get(0),
	)?;
	if !valid {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	Ok(())
}

/// Historical receipts remain distinct from canonical evidence.
pub fn get(
	scope: &crate::scope::RepoScope<'_>, job_id: i64,
) -> Result<StoredEvidence<TerminalPayload>> {
	scope.require_operator()?;
	let conn = scope.conn;
	let record = conn
		.query_row(
			&format!(
				"SELECT {COLUMNS} FROM job_terminal_payloads WHERE job_id=?1
		 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2)"
			),
			params![job_id, scope.repo_id],
			row,
		)
		.optional()?;
	let Some((job, payload)) = record else {
		let historical: bool = conn.query_row(
			"SELECT EXISTS(SELECT 1 FROM job_terminal_receipts r JOIN jobs j ON j.id=r.job_id WHERE r.job_id=?1 AND j.repo_id=?2)",
			params![job_id,scope.repo_id], |r| r.get(0))?;
		return Ok(if historical { StoredEvidence::Historical } else { StoredEvidence::Missing });
	};
	validate_binding(conn, job, &payload)?;
	Ok(StoredEvidence::Recorded(payload))
}

pub(crate) fn validate_stored_rows(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "job_terminal_payloads", COLUMNS, |r| {
		let (job, payload) = row(r)?;
		validate_binding(conn, job, &payload)
	})
}
