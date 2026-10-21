//! Typed evidence checkpoints stay inside live, purpose-bound phase authority.
//! ```compile_fail,E0603
//! let _ = loupe_storage::leads::submit_evidence_raw;
//! ```
//! ```compile_fail,E0603
//! let _ = loupe_storage::lead_observations::accepted_evidence_for_unit;
//! ```
use loupe_core::review_candidates::CandidateKind;
use loupe_core::review_payload::{LeadEvidenceV1, UnitResultDisposition, UnitResultPayloadV1};
use loupe_core::text::policy::{ClientKey, RevisionText};
use loupe_core::text::{BoundedText, Identifier};
use loupe_provenance::{Agent, Db, Worker};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::{Access, Phase, PhaseScope};
use crate::admission_policy::{self, AcceptedPriority};
use crate::checkpoints::{self, Operation, Replay, Stored};
use crate::scheduler::Band;
use crate::{
	admission, inventory, lead_observations, leads, review_intents, review_unit_results,
	review_units, unit_holds, Conflict, Error, Result, StoredEvidence,
};

pub struct LeadCheckpoint<'a> {
	pub key: &'a Identifier<ClientKey, Worker>,
	pub digest: &'a [u8; 32],
	pub evidence: &'a LeadEvidenceV1<Agent>,
}
pub struct UnitResultCheckpoint<'a> {
	pub key: &'a Identifier<ClientKey, Worker>,
	pub digest: &'a [u8; 32],
	pub result: &'a UnitResultPayloadV1<Agent>,
}
// debug-ok: closed checkpoint outcome with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadCheckpointOutcome {
	Created,
	Attached,
	ClosedExists,
}
// debug-ok: numeric identifiers and accepted numeric/closed rank only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeadCheckpointReceipt {
	pub lead_id: i64,
	pub outcome: LeadCheckpointOutcome,
	pub observation_id: Option<i64>,
	pub accepted_priority: AcceptedPriority,
}
// debug-ok: numeric identifiers and closed disposition only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitResultCheckpointReceipt {
	pub result_id: i64,
	pub review_unit_id: i64,
	pub assignment_epoch: u64,
	pub disposition: UnitResultDisposition,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptBand {
	Urgent,
	High,
	Normal,
	Background,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPriority {
	band: ReceiptBand,
	score: u32,
}
impl From<AcceptedPriority> for StoredPriority {
	fn from(value: AcceptedPriority) -> Self {
		Self {
			band: match value.band {
				Band::Urgent => ReceiptBand::Urgent,
				Band::High => ReceiptBand::High,
				Band::Normal => ReceiptBand::Normal,
				Band::Background => ReceiptBand::Background,
			},
			score: value.score,
		}
	}
}
impl From<StoredPriority> for AcceptedPriority {
	fn from(value: StoredPriority) -> Self {
		Self {
			band: match value.band {
				ReceiptBand::Urgent => Band::Urgent,
				ReceiptBand::High => Band::High,
				ReceiptBand::Normal => Band::Normal,
				ReceiptBand::Background => Band::Background,
			},
			score: value.score,
		}
	}
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLeadReceipt {
	protocol_version: u16,
	lead_id: i64,
	outcome: LeadCheckpointOutcome,
	observation_id: Option<i64>,
	accepted_priority: StoredPriority,
}
impl StoredLeadReceipt {
	fn receipt(self) -> Result<LeadCheckpointReceipt> {
		if self.protocol_version != 3
			|| self.lead_id <= 0
			|| self.observation_id.is_some_and(|id| id <= 0)
			|| (self.outcome == LeadCheckpointOutcome::Created) != self.observation_id.is_none()
		{
			return Err(Error::Conflict(Conflict::Checkpoint));
		}
		Ok(LeadCheckpointReceipt {
			lead_id: self.lead_id,
			outcome: self.outcome,
			observation_id: self.observation_id,
			accepted_priority: self.accepted_priority.into(),
		})
	}
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResultReceipt {
	protocol_version: u16,
	result_id: i64,
	review_unit_id: i64,
	assignment_epoch: u64,
	disposition: UnitResultDisposition,
}
impl StoredResultReceipt {
	fn receipt(self) -> Result<UnitResultCheckpointReceipt> {
		if self.protocol_version != 3
			|| self.result_id <= 0
			|| self.review_unit_id <= 0
			|| self.assignment_epoch > i64::MAX as u64
		{
			return Err(Error::Conflict(Conflict::Checkpoint));
		}
		Ok(UnitResultCheckpointReceipt {
			result_id: self.result_id,
			review_unit_id: self.review_unit_id,
			assignment_epoch: self.assignment_epoch,
			disposition: self.disposition,
		})
	}
}

impl PhaseScope<'_, '_> {
	pub fn submit_lead_checkpoint(
		&self, request: &LeadCheckpoint<'_>,
	) -> Result<LeadCheckpointReceipt> {
		self.submit_lead_for(Phase::Survey, request)
	}
	pub fn submit_sibling_lead_checkpoint(
		&self, request: &LeadCheckpoint<'_>,
	) -> Result<LeadCheckpointReceipt> {
		self.submit_lead_for(Phase::Drilldown, request)
	}
	fn submit_lead_for(
		&self, phase: Phase, request: &LeadCheckpoint<'_>,
	) -> Result<LeadCheckpointReceipt> {
		if self.access != Access::Domain || self.job.phase != phase {
			return Err(Error::ScopeDenied);
		}
		let operation = if phase == Phase::Survey {
			Operation::SubmitLead
		} else {
			Operation::SubmitSiblingLead
		};
		if let Some(receipt) =
			self.evidence_replay::<StoredLeadReceipt>(operation, request.key, request.digest)?
		{
			return receipt.receipt();
		}
		let conn = self.transaction.conn;
		let job = &self.job;
		let generation = job.generation_id.ok_or(Error::ScopeDenied)?;
		let policy = admission::load_policy_raw(conn, job.repo_id, job.campaign_id)?;
		let limit = if phase == Phase::Survey {
			policy.max_leads_per_survey
		} else {
			policy.max_sibling_leads_per_drilldown
		};
		if checkpoints::accepted_count_raw(conn, job.repo_id, job.id, operation)?
			>= i64::from(limit)
		{
			return Err(Error::Conflict(Conflict::CheckpointLimit));
		}
		let evidence = request.evidence;
		if phase == Phase::Survey {
			if let (Some(unit), Some(epoch)) = (evidence.review_unit_id, evidence.assignment_epoch)
				&& !self.survey_unit_reference(unit, epoch)?
			{
				return Err(Error::ScopeDenied);
			}
		} else {
			let assigned = job.assigned_lead_id.ok_or(Error::ScopeDenied)?;
			if !self.assigned_lead(assigned)? {
				return Err(Error::ScopeDenied);
			}
			let lead =
				leads::get_metadata_raw(conn, job.repo_id, assigned)?.ok_or(Error::ScopeDenied)?;
			if let (Some(unit), Some(epoch)) = (evidence.review_unit_id, evidence.assignment_epoch)
			{
				if lead.unit_id != Some(unit) {
					return Err(Error::ScopeDenied);
				}
				let belongs:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND u.assignment_epoch=?3 AND g.repo_id=?4)",params![unit,generation,epoch,job.repo_id],|row|row.get(0))?;
				if !belongs {
					return Err(Error::ScopeDenied);
				}
			}
		}
		if let Some(hint) = &evidence.duplicate_hint
			&& !self.issued_candidate_target(CandidateKind::Lead, hint.lead_id)?
		{
			return Err(Error::ScopeDenied);
		}
		validate_refs(conn, job.repo_id, generation, evidence)?;
		let proposed = classify(evidence);
		let (commit, _) = generation_metadata(conn, job.repo_id, generation)?;
		let submitted = leads::submit_evidence_raw(
			conn,
			job.repo_id,
			&leads::NewLeadEvidence {
				generation_id: generation,
				created_by_job: job.id,
				commit_sha: &commit,
				priority: unit_priority(proposed.band),
				payload: evidence,
			},
			self.transaction.now,
		)?;
		let (lead_id, outcome) = match submitted {
			leads::Submitted::Created(id) => (id, LeadCheckpointOutcome::Created),
			leads::Submitted::Attached { lead_id, .. } => {
				(lead_id, LeadCheckpointOutcome::Attached)
			},
			leads::Submitted::ClosedExists { lead_id, .. } => {
				(lead_id, LeadCheckpointOutcome::ClosedExists)
			},
		};
		let observation_id = if outcome == LeadCheckpointOutcome::Created {
			None
		} else {
			Some(
				lead_observations::latest_evidence_for_job(conn, job.repo_id, lead_id, job.id)?
					.ok_or(Error::ScopeDenied)?
					.observation_id,
			)
		};
		// Attachment is evidence, not a new owner or authority to raise prior rank.
		let accepted = if let Some(intent) = review_intents::get_subject_raw(
			conn,
			job.repo_id,
			review_intents::Subject::Lead(lead_id),
		)? {
			intent.priority
		} else {
			let original =
				leads::get_metadata_raw(conn, job.repo_id, lead_id)?.ok_or(Error::ScopeDenied)?;
			let StoredEvidence::Recorded(payload) =
				leads::get_evidence_raw(conn, job.repo_id, lead_id)?
			else {
				return Err(Error::Conflict(Conflict::IncompatibleReviewState));
			};
			validate_refs(conn, job.repo_id, generation, &payload)?;
			let accepted = classify(&payload);
			if unit_priority(accepted.band) != original.priority {
				return Err(Error::Conflict(Conflict::IncompatibleReviewState));
			}
			accepted
		};
		let accepted = review_intents::ensure_drilldown_intent_raw(
			conn,
			job.repo_id,
			lead_id,
			job.id,
			accepted,
			self.transaction.now,
		)?
		.map_or(accepted, |intent| intent.priority);
		let receipt = StoredLeadReceipt {
			protocol_version: 3,
			lead_id,
			outcome,
			observation_id,
			accepted_priority: accepted.into(),
		};
		self.record_evidence(operation, request.key, request.digest, &receipt)?;
		receipt.receipt()
	}

	pub fn submit_unit_result_checkpoint(
		&self, request: &UnitResultCheckpoint<'_>,
	) -> Result<UnitResultCheckpointReceipt> {
		if self.access != Access::Domain || self.job.phase != Phase::Survey {
			return Err(Error::ScopeDenied);
		}
		let operation = Operation::SubmitUnitResult;
		if let Some(receipt) =
			self.evidence_replay::<StoredResultReceipt>(operation, request.key, request.digest)?
		{
			return receipt.receipt();
		}
		let conn = self.transaction.conn;
		let job = &self.job;
		let result = request.result;
		if !self.survey_unit(result.review_unit_id, result.assignment_epoch)? {
			return Err(Error::ScopeDenied);
		}
		if conn.query_row("SELECT EXISTS(SELECT 1 FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id JOIN review_generations g ON g.generation_id=u.generation_id WHERE r.review_unit_id=?1 AND r.produced_by_job_id=?2 AND g.repo_id=?3)",params![result.review_unit_id,job.id,job.repo_id],|row|row.get::<_,bool>(0))? {
   return Err(Error::Conflict(Conflict::UnitResultExists));
  }
		let generation = job.generation_id.ok_or(Error::ScopeDenied)?;
		for lead in &result.created_lead_ids {
			if !accepted_for_unit(
				conn,
				job.repo_id,
				*lead,
				job.id,
				generation,
				result.review_unit_id,
				result.assignment_epoch,
			)? {
				return Err(Error::ScopeDenied);
			}
		}
		inventory::verify_refs_raw(conn, job.repo_id, generation, &result.inspected_refs)?;
		let (commit, profile_version) = generation_metadata(conn, job.repo_id, generation)?;
		let id = review_unit_results::insert_evidence_raw(
			conn,
			job.repo_id,
			&review_unit_results::NewResultEvidence {
				generation_id: generation,
				produced_by_job: job.id,
				commit_sha: &commit,
				profile_version,
				payload: result,
			},
			self.transaction.now,
		)?;
		let owner = unit_holds::ResultOwner {
			unit: result.review_unit_id,
			result: id,
			job: job.id,
			epoch: result.assignment_epoch,
		};
		if let Some(class) = result.continuation {
			unit_holds::record_follow_up_raw(
				conn,
				job.repo_id,
				owner,
				class,
				self.transaction.now,
			)?;
		} else {
			unit_holds::release_conclusive_raw(conn, job.repo_id, owner, self.transaction.now)?;
		}
		let receipt = StoredResultReceipt {
			protocol_version: 3,
			result_id: id,
			review_unit_id: result.review_unit_id,
			assignment_epoch: result
				.assignment_epoch
				.try_into()
				.map_err(|_| Error::Conflict(Conflict::CheckpointEvidence))?,
			disposition: result.disposition,
		};
		self.record_evidence(operation, request.key, request.digest, &receipt)?;
		receipt.receipt()
	}

	fn evidence_replay<T: serde::de::DeserializeOwned>(
		&self, operation: Operation, key: &Identifier<ClientKey, Worker>, digest: &[u8; 32],
	) -> Result<Option<T>> {
		let qualified = format!("{}:{}", operation.as_str(), key.expose());
		self.transaction.conn.query_row(
   "SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key=?2 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3)",
   params![self.job.id,qualified,self.job.repo_id],|row| {
    let stored=Stored {operation:row.get_ref(0)?.as_str()?,digest:row.get_ref(1)?.as_blob()?};
    if checkpoints::replay_decision(Some(&stored),operation,digest)!=Replay::Hit {return Ok(Err(Error::Conflict(Conflict::Checkpoint)));}
    let raw=row.get_ref(2)?.as_str()?;
    if raw.len()>1024 {return Ok(Err(Error::Conflict(Conflict::Checkpoint)));}
    // This fixed receipt is closed scalars only, not carried Agent content.
    Ok(serde_json::from_str(raw).map_err(|_|Error::Conflict(Conflict::Checkpoint)))
   }).optional()?.transpose()
	}
	fn record_evidence(
		&self, operation: Operation, key: &Identifier<ClientKey, Worker>, digest: &[u8; 32],
		receipt: &impl Serialize,
	) -> Result<()> {
		let value =
			serde_json::to_value(receipt).map_err(|_| Error::Conflict(Conflict::Checkpoint))?;
		let response = String::from_utf8(crate::canonical::canonical_bytes(&value))
			.map_err(|_| Error::Conflict(Conflict::Checkpoint))?;
		let qualified = format!("{}:{}", operation.as_str(), key.expose());
		crate::review::changed(self.transaction.conn.execute(
   "INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?7)",
   params![self.job.id,qualified,operation.as_str(),digest.as_slice(),response,self.transaction.now,self.job.repo_id]
  )?,Conflict::Checkpoint)
	}
}

fn generation_metadata(
	conn: &Connection, repo: i64, generation: i64,
) -> Result<(BoundedText<RevisionText, Db>, i64)> {
	conn.query_row("SELECT generation_commit_sha,profile_version FROM review_generations WHERE generation_id=?1 AND repo_id=?2",
  params![generation,repo],|row|Ok((crate::ingress::revision(row,0)?,row.get(1)?))).optional()?.ok_or(Error::ScopeDenied)
}
fn validate_refs(
	conn: &Connection, repo: i64, generation: i64, evidence: &LeadEvidenceV1<Agent>,
) -> Result<()> {
	inventory::verify_refs_raw(conn, repo, generation, &evidence.source_refs)?;
	if let Some(proposal) = &evidence.priority_proposal {
		inventory::verify_refs_raw(conn, repo, generation, &proposal.boundary_refs)?;
	}
	Ok(())
}
fn classify(evidence: &LeadEvidenceV1<Agent>) -> AcceptedPriority {
	evidence.priority_proposal.as_ref().map_or(
		AcceptedPriority { band: Band::Normal, score: 0 },
		|p| {
			admission_policy::classify_priority(
				p.impact,
				p.access,
				p.reachability,
				evidence.invariant_or_boundary.is_some() && !p.boundary_refs.is_empty(),
				true,
			)
		},
	)
}
fn unit_priority(band: Band) -> review_units::Priority {
	match band {
		Band::Urgent => review_units::Priority::Urgent,
		Band::High => review_units::Priority::High,
		Band::Normal => review_units::Priority::Normal,
		Band::Background => review_units::Priority::Background,
	}
}
/// Scope and successful receipt membership precede all evidence inspection.
fn accepted_for_unit(
	conn: &Connection, repo: i64, lead: i64, job: i64, generation: i64, unit: i64, epoch: i64,
) -> Result<bool> {
	let matches = |payload: &LeadEvidenceV1<Agent>| {
		payload.review_unit_id == Some(unit) && payload.assignment_epoch == Some(epoch)
	};
	let original_owned:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1 AND l.generation_id=?2 AND l.created_by_job_id=?3 AND g.repo_id=?4)",params![lead,generation,job,repo],|row|row.get(0))?;
	if original_owned
		&& accepted_receipt(conn, repo, job, lead)?
		&& let StoredEvidence::Recorded(payload) = leads::get_evidence_raw(conn, repo, lead)?
		&& matches(&payload)
	{
		return Ok(true);
	}
	if let Some(observation) = lead_observations::accepted_evidence_for_unit(
		conn, repo, lead, job, generation, unit, epoch,
	)? && let StoredEvidence::Recorded(payload) = observation.payload
		&& matches(&payload)
	{
		return Ok(true);
	}
	Ok(false)
}
fn accepted_receipt(conn: &Connection, repo: i64, job: i64, lead: i64) -> Result<bool> {
	Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM job_checkpoints c JOIN jobs j ON j.id=c.job_id WHERE c.job_id=?1 AND j.repo_id=?3 AND c.operation='submit_lead' AND json_extract(c.response,'$.lead_id')=?2 AND json_extract(c.response,'$.observation_id') IS NULL)",params![job,lead,repo],|row|row.get(0))?)
}

#[cfg(test)]
mod tests;
