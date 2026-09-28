//! Private terminal composition and durable snapshots. Code-owned audit JSON
//! never acquires a fabricated mark; required receipt readback admits the actual
//! SQL TEXT through the existing Payload policy before the transaction commits.
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::{SurveyTerminalReason, Version1};
use loupe_provenance::Db;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::{
	DrilldownDisposition, DrilldownFinalization, DrilldownSummary, PhaseScope, PhaseTransaction,
};
use crate::terminal_receipt::EvidenceRung;
use crate::{terminal_payloads, Conflict, Error, Result};

// debug-ok: closed coverage state only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyCoverage {
	Complete,
	Partial,
}

// debug-ok: closed version/state and numeric counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveySummary {
	pub version: Version1,
	pub coverage: SurveyCoverage,
	pub corroboration_satisfied: bool,
	pub missing_results: u64,
	pub needs_follow_up: u64,
	pub unresolved_inventory: u64,
	pub follow_up_batches: u64,
	pub follow_up_units: u64,
}

// debug-ok: IDs and closed numeric states; content identifiers redact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyFinalization {
	pub receipt_id: i64,
	pub job_id: i64,
	pub commit: ReviewCommit<Db>,
	pub result_digest: ReviewDigest<Db>,
	pub terminal_reason: SurveyTerminalReason,
	pub summary: SurveySummary,
}

pub(super) fn incompatible() -> Error {
	Error::Conflict(Conflict::CheckpointEvidence)
}

pub(super) fn stored_error(error: Error) -> Error {
	match error {
		Error::ReviewPayload(_) | Error::Validation(_) => incompatible(),
		Error::Sqlite(
			rusqlite::Error::FromSqlConversionFailure(..) | rusqlite::Error::InvalidColumnType(..),
		) => incompatible(),
		other => other,
	}
}

pub(super) fn snapshot(tx: &PhaseTransaction<'_>) -> Result<SurveyFinalization> {
	tx.conn.query_row(
        "SELECT job_terminal_receipt_id,job_id,pinned_commit_sha,result_digest,terminal_reason,result_counts,effective_recipe
         FROM job_terminal_receipts WHERE job_id=?1 AND phase='survey'",
        [tx.job_id],
        |row| {
            // Both code-owned JSON documents must pass the same durable
            // Payload caps/normalization as operator-written receipts.
            let _audit=crate::ingress::db_payload(row,6)?;
            let counts=crate::ingress::db_payload(row,5)?;
            let summary:SurveySummary=serde_json::from_str(counts.expose())
                .map_err(|_|crate::review::invalid_scalar(5))?;
            let terminal_reason=match row.get_ref(4)?.as_str()? {
                "completed"=>SurveyTerminalReason::Completed,
                "partial"=>SurveyTerminalReason::Partial,
                "deferred"=>SurveyTerminalReason::Deferred,
                _=>return Err(crate::review::invalid_scalar(4)),
            };
            Ok(SurveyFinalization {
                receipt_id:row.get(0)?,job_id:row.get(1)?,
                commit:crate::ingress::profile::commit(row,2)?,
                result_digest:crate::ingress::profile::digest(row,3)?,
                terminal_reason,summary,
            })
        }
    ).optional()?.ok_or_else(incompatible)
}

pub(super) struct Audit {
	pub commit: ReviewCommit<Db>,
	pub recipe: String,
}
impl std::fmt::Debug for Audit {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("TerminalAudit([redacted])")
	}
}

pub(super) fn audit(scope: &PhaseScope<'_, '_>) -> Result<Audit> {
	let job = &scope.job;
	let generation = job.generation_id.ok_or(Error::ScopeDenied)?;
	let (commit,recipe,contract,profile,manifest_digest,manifest_entries,manifest_bytes,policy,policy_digest)=
        scope.transaction.conn.query_row(
            "SELECT j.head_sha,j.recipe,j.workflow_contract_version,
             g.profile_version,g.generated_profile,g.generated_profile_digest,g.generated_profile_source,
             m.expected_digest,m.expected_entry_count,m.received_canonical_bytes,
             c.effective_policy,c.effective_policy_digest
             FROM jobs j JOIN review_generations g ON g.generation_id=j.generation_id
             JOIN generation_manifests m ON m.generation_id=g.generation_id
             JOIN review_campaigns c ON c.campaign_id=j.campaign_id
             WHERE j.id=?1 AND j.repo_id=?2 AND g.repo_id=?2 AND c.repo_id=?2
             AND g.generation_id=?3 AND c.campaign_id=?4 AND c.generation_id=g.generation_id",
            params![job.id,job.repo_id,generation,job.campaign_id],|row|Ok((
                crate::ingress::profile::commit(row,0)?,
                crate::ingress::db_payload(row,1)?,
                row.get::<_,i64>(2)?,
                crate::ingress::profile::frozen_profile(row,3,4,5,6)?,
                crate::ingress::profile::digest(row,7)?,
                row.get::<_,u64>(8)?,
                row.get::<_,u64>(9)?,
                crate::ingress::admission_policy::policy(row,10,11)?,
                crate::ingress::profile::digest(row,11)?,
            ))
        ).optional()?.ok_or(Error::ScopeDenied)?;
	let profile = profile.ok_or(Error::ScopeDenied)?;
	// The recipe was admitted from its actual SQL column. Numeric policy
	// validation used its original TEXT and BLOB digest in that same row.
	let recipe_value: serde_json::Value =
		serde_json::from_str(recipe.expose()).map_err(|_| incompatible())?;
	let value = serde_json::json!({
		"version":1,"workflow_contract_version":contract,"recipe":recipe_value,
		"policy":policy,"policy_digest":policy_digest,
		"profile_version":profile.version,"profile_digest":profile.digest,
		"manifest_digest":manifest_digest,"manifest_entries":manifest_entries,
		"manifest_canonical_bytes":manifest_bytes,"generation_id":generation,
		"campaign_id":job.campaign_id,"repo_id":job.repo_id,"commit_sha":commit,
	});
	let bytes = loupe_core::canonical::canonical_bytes(&value);
	use loupe_core::text::policy::Payload;
	use loupe_core::text::JsonPolicy;
	if bytes.len() > Payload::MAX_BYTES {
		return Err(incompatible());
	}
	Ok(Audit { commit, recipe: String::from_utf8(bytes).map_err(|_| incompatible())? })
}

pub(super) fn succeed(scope: &PhaseScope<'_, '_>) -> Result<()> {
	crate::review::changed(
		scope.transaction.conn.execute(
			"UPDATE jobs SET state='succeeded',finished_at=?2,error=NULL,
         job_capability_hash=NULL,lease_expires_at=NULL,prepared_attempt=NULL,
         prepared_capability_hash=NULL,prepared_at=NULL
         WHERE id=?1 AND repo_id=?3 AND state='leased'",
			params![scope.job.id, scope.transaction.now, scope.job.repo_id],
		)?,
		Conflict::TerminalReceipt,
	)
}

pub(super) fn seal(
	scope: &PhaseScope<'_, '_>, audit: &Audit, payload: &terminal_payloads::TerminalPayload,
	summary: &SurveySummary,
) -> Result<SurveyFinalization> {
	let terminal_payloads::TerminalPayload::Survey(value) = payload else {
		return Err(incompatible());
	};
	let reason = match value.terminal_reason {
		SurveyTerminalReason::Completed => "completed",
		SurveyTerminalReason::Partial => "partial",
		SurveyTerminalReason::Deferred => "deferred",
	};
	write_receipt(scope, audit, payload, summary, None, None, reason)?;
	snapshot(scope.transaction)
}

pub(super) fn seal_drilldown(
	scope: &PhaseScope<'_, '_>, audit: &Audit, payload: &terminal_payloads::TerminalPayload,
	summary: &DrilldownSummary, subject_digest: &[u8; 32],
) -> Result<DrilldownFinalization> {
	if !matches!(payload, terminal_payloads::TerminalPayload::Drilldown(_)) {
		return Err(incompatible());
	}
	write_receipt(
		scope,
		audit,
		payload,
		summary,
		Some(subject_digest),
		summary.promoted_finding_id.map(|_| EvidenceRung::L2),
		summary.disposition.as_str(),
	)?;
	drilldown_snapshot(scope.transaction)
}

/// Shared private SQL writer. Public callers cannot supply arbitrary audit JSON,
/// phase, content provenance, or finishing identity.
fn write_receipt(
	scope: &PhaseScope<'_, '_>, audit: &Audit, payload: &terminal_payloads::TerminalPayload,
	summary: &impl Serialize, subject_digest: Option<&[u8; 32]>, rung: Option<EvidenceRung>,
	reason: &'static str,
) -> Result<()> {
	let hash = scope.transaction.capability_hash.ok_or(Error::ScopeDenied)?;
	let counts = loupe_core::canonical::canonical_bytes(
		&serde_json::to_value(summary).map_err(|_| incompatible())?,
	);
	let counts = std::str::from_utf8(&counts).map_err(|_| incompatible())?;
	scope.transaction.conn.execute(
		"INSERT INTO job_terminal_receipts(job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,result_counts,finishing_capability_hash,created_at,subject_digest,evidence_rung)
		 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
		params![scope.job.id, payload.phase().as_str(), reason, audit.commit.expose(), audit.recipe,
			payload.digest()?.as_slice(), counts, hash.as_slice(), scope.transaction.now,
			subject_digest.map(|v| v.as_slice()), rung.map(EvidenceRung::as_str)],
	).map_err(|error| {
		if crate::review::is_unique(&error, "job_terminal_receipts.job_id")
			|| crate::review::is_unique(&error, "job_terminal_receipts.job_id, job_terminal_receipts.phase")
		{
			Error::Conflict(Conflict::TerminalReceipt)
		} else {
			error.into()
		}
	})?;
	terminal_payloads::insert_raw(scope.transaction.conn, scope.job.repo_id, scope.job.id, payload)
}

pub(super) fn drilldown_snapshot(tx: &PhaseTransaction<'_>) -> Result<DrilldownFinalization> {
	tx.conn.query_row(
		"SELECT job_terminal_receipt_id,job_id,pinned_commit_sha,result_digest,terminal_reason,result_counts,effective_recipe,evidence_rung,subject_digest
		 FROM job_terminal_receipts WHERE job_id=?1 AND phase='drilldown'",
		[tx.job_id],
		|row| {
			let _audit = crate::ingress::db_payload(row, 6)?;
			let counts = crate::ingress::db_payload(row, 5)?;
			let summary: DrilldownSummary = serde_json::from_str(counts.expose())
				.map_err(|_| crate::review::invalid_scalar(5))?;
			summary.validate().map_err(|_| crate::review::invalid_scalar(5))?;
			if row.get_ref(4)?.as_str()? != summary.disposition.as_str() {
				return Err(crate::review::invalid_scalar(4));
			}
			let expected_rung = if summary.disposition == DrilldownDisposition::Promoted {
				rusqlite::types::ValueRef::Text(b"L2")
			} else {
				rusqlite::types::ValueRef::Null
			};
			if row.get_ref(7)? != expected_rung || row.get_ref(8)?.as_blob()?.len() != 32 {
				return Err(crate::review::invalid_scalar(7));
			}
			let receipt_id: i64 = row.get(0)?;
			let job_id: i64 = row.get(1)?;
			if receipt_id <= 0 || job_id <= 0 {
				return Err(crate::review::invalid_scalar(0));
			}
			Ok(DrilldownFinalization {
				receipt_id, job_id, commit: crate::ingress::profile::commit(row, 2)?,
				result_digest: crate::ingress::profile::digest(row, 3)?, summary,
			})
		},
	).optional()?.ok_or_else(incompatible)
}
