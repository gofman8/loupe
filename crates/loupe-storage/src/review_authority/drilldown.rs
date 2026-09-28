//! Assigned-lead finalization owns every domain mutation in the phase transaction.
//! ```compile_fail,E0603
//! let _ = loupe_storage::review_findings::insert_raw;
//! ```
//! ```compile_fail,E0603
//! let _ = loupe_storage::leads::defer_for_continuation_raw;
//! ```
use loupe_core::review_candidates::CandidateKind;
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::{DrilldownTerminalV1, DuplicateTarget, Version1};
use loupe_core::text::SourceRef;
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
	inventory, leads, review_findings, review_intents, Conflict, Error, Result, StoredEvidence,
};

// debug-ok: closed terminal disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrilldownDisposition {
	Promoted,
	Rejected,
	Duplicate,
	Hardening,
	Deferred,
}
impl DrilldownDisposition {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Self::Promoted => "promoted",
			Self::Rejected => "rejected",
			Self::Duplicate => "duplicate",
			Self::Hardening => "hardening",
			Self::Deferred => "deferred",
		}
	}
}
// debug-ok: closed terminal decisions and numeric identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrilldownSummary {
	pub version: Version1,
	pub lead_id: i64,
	pub disposition: DrilldownDisposition,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub promoted_finding_id: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<ContinuationSummary>,
}
impl DrilldownSummary {
	pub(super) fn validate(&self) -> Result<()> {
		if self.lead_id <= 0
			|| self.promoted_finding_id.is_some_and(|id| id <= 0)
			|| (self.disposition == DrilldownDisposition::Promoted)
				!= self.promoted_finding_id.is_some()
			|| (self.disposition == DrilldownDisposition::Deferred) != self.continuation.is_some()
		{
			return Err(incompatible());
		}
		if let Some(value) = &self.continuation {
			terminal::validate_continuation(value)?;
		}
		Ok(())
	}
}
// debug-ok: metadata identifiers redact and the summary contains closed/numeric fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrilldownFinalization {
	pub receipt_id: i64,
	pub job_id: i64,
	pub commit: ReviewCommit<Db>,
	pub result_digest: ReviewDigest<Db>,
	pub summary: DrilldownSummary,
}
fn incompatible() -> Error {
	Error::Conflict(Conflict::IncompatibleReviewState)
}

impl PhaseTransaction<'_> {
	/// Finishing identity authenticates receipt replay before live context or policy.
	/// The enclosing callback must render its bounded response before committing.
	pub fn finalize_drilldown(
		&mut self, payload: &DrilldownTerminalV1<Agent>,
		policy: impl FnOnce(&Context) -> Result<Option<PolicyDecision>>,
	) -> Result<DrilldownFinalization> {
		let payload = TerminalPayload::Drilldown(payload.clone());
		match self.replay_terminal(Phase::Drilldown, &payload)? {
			Replayed::Receipt(_) => {
				return terminal::drilldown_snapshot(self).map_err(stored_error)
			},
			Replayed::Reject(Reject::WrongDigest) => {
				return Err(Error::Conflict(Conflict::TerminalReceipt))
			},
			Replayed::Reject(Reject::Denied) => {},
		}
		let scope =
			self.authorize(Phase::Drilldown, Access::Domain, policy)?.ok_or(Error::ScopeDenied)?;
		finalize(&scope, &payload).map_err(stored_error)
	}
}

/// Original evidence may belong to an earlier checkout whose generation was
/// purged. Its retained producer and SHA are checked without relabelling it.
fn original_digest(scope: &PhaseScope<'_, '_>, lead: &leads::Metadata) -> Result<[u8; 32]> {
	let producer = lead.created_by_job.filter(|id| *id > 0).ok_or_else(incompatible)?;
	if !loupe_core::inventory_manifest::is_git_oid(lead.commit_sha.expose()) {
		return Err(incompatible());
	}
	let valid: bool = scope.transaction.conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND kind IN('survey','drilldown') AND workflow_contract_version=?4 AND head_sha=?3)",
		params![producer, scope.job.repo_id, lead.commit_sha.expose(), loupe_core::WORKFLOW_CONTRACT_VERSION],
		|row| row.get(0),
	)?;
	if !valid {
		return Err(incompatible());
	}
	let StoredEvidence::Recorded(payload) =
		leads::get_evidence_raw(scope.transaction.conn, scope.job.repo_id, lead.lead_id)?
	else {
		return Err(incompatible());
	};
	payload.digest().map_err(|_| incompatible())
}
fn validate_sources(
	scope: &PhaseScope<'_, '_>, generation: i64, lead: &leads::Metadata, sha: &ReviewCommit<Db>,
	payload: &DrilldownTerminalV1<Agent>,
) -> Result<()> {
	let conn = scope.transaction.conn;
	let repo = scope.job.repo_id;
	let revalidation = match payload {
		DrilldownTerminalV1::Promote { promotion, revalidation, .. } => {
			let refs: Vec<_> = promotion
				.evidence
				.material_locations
				.iter()
				.map(|location| SourceRef { path: location.file.clone(), symbol: None })
				.collect();
			inventory::verify_refs_raw(conn, repo, generation, &refs)?;
			revalidation
		},
		DrilldownTerminalV1::Reject { counterargument, revalidation, .. } => {
			inventory::verify_refs_raw(conn, repo, generation, &counterargument.source_refs)?;
			revalidation
		},
		DrilldownTerminalV1::Hardening { explanation, revalidation, .. } => {
			inventory::verify_refs_raw(conn, repo, generation, &explanation.source_refs)?;
			revalidation
		},
		DrilldownTerminalV1::Duplicate { revalidation, .. }
		| DrilldownTerminalV1::Defer { revalidation, .. } => revalidation,
	};
	if (lead.needs_revalidation || lead.commit_sha.expose() != sha.expose())
		&& revalidation.is_none()
	{
		return Err(Error::Conflict(Conflict::RevalidationRequired));
	}
	if let Some(value) = revalidation {
		inventory::verify_refs_raw(conn, repo, generation, &value.current_source_refs)?;
	}
	Ok(())
}
fn finalize(
	scope: &PhaseScope<'_, '_>, payload: &TerminalPayload,
) -> Result<DrilldownFinalization> {
	if scope.access != Access::Domain || scope.job.phase != Phase::Drilldown {
		return Err(Error::ScopeDenied);
	}
	let TerminalPayload::Drilldown(terminal_payload) = payload else {
		return Err(incompatible());
	};
	let conn = scope.transaction.conn;
	let repo = scope.job.repo_id;
	let job = scope.job.id;
	let now = scope.transaction.now;
	let generation = scope.job.generation_id.ok_or(Error::ScopeDenied)?;
	let lead_id = scope.job.assigned_lead_id.ok_or(Error::ScopeDenied)?;
	let lead = leads::get_metadata_raw(conn, repo, lead_id)?.ok_or(Error::ScopeDenied)?;
	if lead.generation_id != generation || lead.status != leads::Status::Open {
		return Err(incompatible());
	}
	let original = original_digest(scope, &lead)?;
	let audit = terminal::audit(scope)?;
	let (intent, context) = terminal::admitted_subject(scope, Subject::Lead(lead_id), &audit)?;
	validate_sources(scope, generation, &lead, &audit.commit, terminal_payload)?;
	let mut summary = DrilldownSummary {
		version: Version1,
		lead_id,
		disposition: DrilldownDisposition::Deferred,
		promoted_finding_id: None,
		continuation: None,
	};
	match terminal_payload {
		DrilldownTerminalV1::Promote { promotion, .. } => {
			let finding = review_findings::insert_raw(
				conn,
				repo,
				&review_findings::NewFinding {
					job_id: job,
					origin_lead_id: lead_id,
					profile_version: i64::from(context.profile.version.get()),
					profile_digest: context.profile.profile.digest(),
					reviewed_commit_sha: context.job.head_sha.as_ref().ok_or_else(incompatible)?,
					promotion,
				},
				now,
			)?;
			leads::close_raw(conn, repo, lead_id, &leads::Closure::Promoted { finding }, now)?;
			review_intents::ensure_verification_intent_raw(
				conn,
				repo,
				finding,
				job,
				intent.priority,
				now,
			)?
			.ok_or_else(incompatible)?;
			summary.disposition = DrilldownDisposition::Promoted;
			summary.promoted_finding_id = Some(finding);
		},
		DrilldownTerminalV1::Reject { .. } => {
			leads::close_raw(conn, repo, lead_id, &leads::Closure::Rejected, now)?;
			summary.disposition = DrilldownDisposition::Rejected;
		},
		DrilldownTerminalV1::Duplicate { target, .. } => {
			let (kind, id, closure) = match target {
				DuplicateTarget::Lead { id } if *id != lead_id => (
					CandidateKind::Lead,
					*id,
					leads::Closure::Duplicate { lead: Some(*id), finding: None },
				),
				DuplicateTarget::Finding { id } => (
					CandidateKind::Finding,
					*id,
					leads::Closure::Duplicate { lead: None, finding: Some(*id) },
				),
				_ => return Err(Error::ScopeDenied),
			};
			if !scope.issued_candidate_target(kind, id)? {
				return Err(Error::ScopeDenied);
			}
			leads::close_raw(conn, repo, lead_id, &closure, now)?;
			summary.disposition = DrilldownDisposition::Duplicate;
		},
		DrilldownTerminalV1::Hardening { .. } => {
			leads::close_raw(conn, repo, lead_id, &leads::Closure::Hardening, now)?;
			summary.disposition = DrilldownDisposition::Hardening;
		},
		DrilldownTerminalV1::Defer { continuation, .. } => {
			leads::defer_for_continuation_raw(conn, repo, lead_id, *continuation)?
		},
	}
	terminal::succeed(scope)?;
	if let DrilldownTerminalV1::Defer { continuation: class, .. } = terminal_payload {
		summary.continuation =
			Some(terminal::continuation(&review_intents::continue_subject_raw(
				conn,
				repo,
				Subject::Lead(lead_id),
				job,
				*class,
				now,
			)?)?);
	} else {
		review_intents::finish_subject_intent_raw(conn, repo, Subject::Lead(lead_id), job, now)?;
	}
	summary.validate()?;
	terminal::seal_drilldown(scope, &audit, payload, &summary, &original)
}

#[cfg(test)]
pub(in crate::review_authority) mod tests;
