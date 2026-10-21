//! Assigned-finding verification seals independent Agent evidence before delivery.
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::{VerificationTerminalV1, Version1};
use loupe_core::text::SourceRef;
use loupe_core::{FindingState, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::{Agent, Db};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::terminal::{self, stored_error};
use super::{
	Access, Context, ContinuationSummary, Phase, PhaseScope, PhaseTransaction, PolicyDecision,
};
use crate::review_intents::Subject;
use crate::terminal_payloads::TerminalPayload;
use crate::terminal_receipt::{Reject, Replayed};
use crate::{
	finding_details, findings, inventory, reports, review_intents, Conflict, Error, Result,
	StoredEvidence,
};

// debug-ok: closed verdict only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
	Verified,
	Rejected,
	Inconclusive,
}
impl VerificationVerdict {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Self::Verified => "verified",
			Self::Rejected => "rejected",
			Self::Inconclusive => "inconclusive",
		}
	}
}
// debug-ok: closed states and numeric identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
	pub version: Version1,
	pub finding_id: i64,
	pub verification_id: i64,
	pub verdict: VerificationVerdict,
	pub finding_state: FindingState,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<ContinuationSummary>,
}
impl VerificationSummary {
	pub(super) fn validate(&self) -> Result<()> {
		if self.finding_id <= 0
			|| self.verification_id <= 0
			|| (self.verdict == VerificationVerdict::Inconclusive) != self.continuation.is_some()
			|| matches!(self.finding_state, FindingState::Pending | FindingState::Reported)
		{
			return Err(incompatible());
		}
		if let Some(value) = &self.continuation {
			terminal::validate_continuation(value)?;
		}
		Ok(())
	}
}
// debug-ok: identifiers redact; summary contains closed and numeric fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReceipt {
	pub receipt_id: i64,
	pub job_id: i64,
	pub commit: ReviewCommit<Db>,
	pub result_digest: ReviewDigest<Db>,
	pub summary: VerificationSummary,
}
/// The report capability stays inactive until the enclosing transaction commits.
pub struct VerificationFinalization {
	pub receipt: VerificationReceipt,
	pub reporting: reports::Preparation,
	pub finalized_at: i64,
}
fn incompatible() -> Error {
	Error::Conflict(Conflict::IncompatibleReviewState)
}

impl PhaseTransaction<'_> {
	/// Replay reads only sealed identity/evidence and cannot prepare delivery.
	pub fn finalize_verification(
		&mut self, payload: &VerificationTerminalV1<Agent>, require_approval_default: bool,
		policy: impl FnOnce(&Context) -> Result<Option<PolicyDecision>>,
	) -> Result<VerificationFinalization> {
		let payload = TerminalPayload::Verification(payload.clone());
		match self.replay_terminal(Phase::Verify, &payload)? {
			Replayed::Receipt(_) => {
				return Ok(VerificationFinalization {
					receipt: terminal::verification_snapshot(self).map_err(stored_error)?,
					reporting: reports::Preparation::NoReport,
					finalized_at: self.now,
				})
			},
			Replayed::Reject(Reject::WrongDigest) => {
				return Err(Error::Conflict(Conflict::TerminalReceipt))
			},
			Replayed::Reject(Reject::Denied) => {},
		}
		let scope =
			self.authorize(Phase::Verify, Access::Domain, policy)?.ok_or(Error::ScopeDenied)?;
		finalize(&scope, &payload, require_approval_default).map_err(stored_error)
	}
}
/// The original producer survives purged derived generations and origin leads.
fn original(scope: &PhaseScope<'_, '_>, finding: i64) -> Result<finding_details::ReviewEvidence> {
	let StoredEvidence::Recorded(details) = finding_details::read_review_evidence_raw(
		scope.transaction.conn,
		scope.job.repo_id,
		finding,
	)?
	else {
		return Err(incompatible());
	};
	if details.repo_id != scope.job.repo_id
		|| details.workflow_contract_version != WORKFLOW_CONTRACT_VERSION
		|| details.profile_version <= 0
		|| details.profile_digest.is_none()
		|| !loupe_core::inventory_manifest::is_git_oid(details.reviewed_commit_sha.expose())
	{
		return Err(incompatible());
	}
	let valid: bool = scope.transaction.conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings f JOIN jobs j ON j.id=f.job_id
         WHERE f.id=?1 AND f.repo_id=?2 AND j.repo_id=?2 AND j.kind='drilldown'
         AND j.campaign_id IS NOT NULL AND j.workflow_contract_version=?4 AND j.head_sha=?3)",
		params![
			finding,
			scope.job.repo_id,
			details.reviewed_commit_sha.expose(),
			WORKFLOW_CONTRACT_VERSION
		],
		|row| row.get(0),
	)?;
	if !valid {
		return Err(incompatible());
	}
	Ok(details)
}
fn validate_sources(
	scope: &PhaseScope<'_, '_>, generation: i64, original_sha: &str, current_sha: &str,
	evidence: &VerificationTerminalV1<Agent>,
) -> Result<()> {
	let conn = scope.transaction.conn;
	let repo = scope.job.repo_id;
	let revalidation = match evidence {
		VerificationTerminalV1::Verified { evidence, revalidation, .. } => {
			let refs: Vec<_> = evidence
				.material_locations
				.iter()
				.map(|location| SourceRef { path: location.file.clone(), symbol: None })
				.collect();
			inventory::verify_refs_raw(conn, repo, generation, &refs)?;
			revalidation
		},
		VerificationTerminalV1::Rejected { counterargument, revalidation, .. } => {
			inventory::verify_refs_raw(conn, repo, generation, &counterargument.source_refs)?;
			revalidation
		},
		VerificationTerminalV1::Inconclusive { partial_evidence, revalidation, .. } => {
			if let Some(value) = partial_evidence {
				inventory::verify_refs_raw(conn, repo, generation, &value.source_refs)?;
			}
			revalidation
		},
	};
	if original_sha != current_sha && revalidation.is_none() {
		return Err(Error::Conflict(Conflict::RevalidationRequired));
	}
	if let Some(value) = revalidation {
		inventory::verify_refs_raw(conn, repo, generation, &value.current_source_refs)?;
	}
	Ok(())
}
fn finalize(
	scope: &PhaseScope<'_, '_>, payload: &TerminalPayload, approval_default: bool,
) -> Result<VerificationFinalization> {
	if scope.access != Access::Domain || scope.job.phase != Phase::Verify {
		return Err(Error::ScopeDenied);
	}
	let TerminalPayload::Verification(evidence) = payload else {
		return Err(incompatible());
	};
	let conn = scope.transaction.conn;
	let repo = scope.job.repo_id;
	let job = scope.job.id;
	let now = scope.transaction.now;
	let finding = scope.job.target_finding_id.ok_or(Error::ScopeDenied)?;
	let generation = scope.job.generation_id.ok_or(Error::ScopeDenied)?;
	let row = findings::get_selected(conn, repo, finding)?.ok_or(Error::ScopeDenied)?;
	if row.state != FindingState::Validating || !row.verification_required {
		return Err(incompatible());
	}
	let original = original(scope, finding)?;
	let audit = terminal::audit(scope)?;
	let (_, context) = terminal::admitted_subject(scope, Subject::Finding(finding), &audit)?;
	validate_sources(
		scope,
		generation,
		original.reviewed_commit_sha.expose(),
		audit.commit.expose(),
		evidence,
	)?;
	let (verdict, stored_verdict) = match evidence {
		VerificationTerminalV1::Verified { .. } => (VerificationVerdict::Verified, "confirmed"),
		VerificationTerminalV1::Rejected { .. } => (VerificationVerdict::Rejected, "dismissed"),
		VerificationTerminalV1::Inconclusive { .. } => {
			(VerificationVerdict::Inconclusive, "inconclusive")
		},
	};
	let require_approval = crate::repos::get_raw(conn, repo)?
		.ok_or(Error::ScopeDenied)?
		.effective_require_approval(approval_default);
	conn.execute(
		"INSERT INTO finding_verifications(finding_id,job_id,verdict,notes,created_at)
        VALUES(?1,?2,?3,NULL,?4)",
		params![finding, job, stored_verdict, now],
	)?;
	let verification = conn.last_insert_rowid();
	finding_details::insert_attempt_evidence_raw(
		conn,
		repo,
		&finding_details::NewAttemptEvidence {
			verification_id: verification,
			workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
			checkout_commit_sha: context.job.head_sha.as_ref().ok_or_else(incompatible)?,
			evidence,
		},
		now,
	)?;
	// Only independently accepted verdicts settle a finding. Exhaustion and
	// continuation blockers never synthesize a dismissed security verdict.
	let transition =
		findings::roll_up_verdicts_for_finding(conn, repo, finding, false, require_approval, now)?;
	let finding_state = transition.unwrap_or(row.state);
	terminal::succeed(scope)?;
	let continuation = if let VerificationTerminalV1::Inconclusive { continuation, .. } = evidence {
		Some(terminal::continuation(&review_intents::continue_subject_raw(
			conn,
			repo,
			Subject::Finding(finding),
			job,
			*continuation,
			now,
		)?)?)
	} else {
		review_intents::finish_subject_intent_raw(conn, repo, Subject::Finding(finding), job, now)?;
		None
	};
	let summary = VerificationSummary {
		version: Version1,
		finding_id: finding,
		verification_id: verification,
		verdict,
		finding_state,
		continuation,
	};
	summary.validate()?;
	let subject_digest = original.evidence.digest()?;
	let receipt = terminal::seal_verification(scope, &audit, payload, &summary, &subject_digest)?;
	let reporting = if transition == Some(FindingState::Confirmed) {
		reports::prepare_verification(
			conn,
			repo,
			finding,
			scope.transaction.identity,
			scope.transaction.committed,
		)?
	} else {
		reports::Preparation::NoReport
	};
	Ok(VerificationFinalization { receipt, reporting, finalized_at: now })
}

#[cfg(test)]
mod tests;
