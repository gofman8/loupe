//! Idempotent survey proposals create scopes, not assignment or rank authority.
use loupe_core::text::policy::{Argument, ClientKey, Objective, Payload, Reason, Title};
use loupe_core::text::{BoundedText, Identifier, JsonPolicy, SourceRef};
use loupe_provenance::{Agent, Worker};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::{Access, Phase, PhaseScope};
use crate::checkpoints::{self, Operation, Replay, Stored};
use crate::review_units::{self, AdmittedUnit, Priority};
use crate::source_refs::UnitRefs;
use crate::{admission, inventory, Conflict, Error, Result};

/// Borrowed evidence cannot choose repository, generation or assignment owner.
pub struct UnitProposal<'a> {
	pub key: &'a Identifier<ClientKey, Worker>,
	pub digest: &'a [u8; 32],
	pub title: &'a BoundedText<Title, Agent>,
	pub objective: &'a BoundedText<Objective, Agent>,
	pub priority_band: Priority,
	pub priority_rationale: Option<&'a BoundedText<Reason, Agent>>,
	pub source_refs: &'a [SourceRef<Agent>],
	pub dependencies: &'a [i64],
	pub closure_criteria: Option<&'a BoundedText<Reason, Agent>>,
	pub semantic_context: Option<&'a BoundedText<Argument, Agent>>,
}
// debug-ok: numeric unit identity and epoch only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitProposalReceipt {
	pub review_unit_id: i64,
	pub assignment_epoch: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
	protocol_version: u16,
	review_unit_id: i64,
	assignment_epoch: u64,
	accepted_priority_band: Normal,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Normal {
	Normal,
}
impl StoredReceipt {
	fn receipt(self) -> Result<UnitProposalReceipt> {
		if self.protocol_version != 3 || self.review_unit_id <= 0 || self.assignment_epoch != 0 {
			return Err(Error::Conflict(Conflict::Checkpoint));
		}
		Ok(UnitProposalReceipt { review_unit_id: self.review_unit_id, assignment_epoch: 0 })
	}
}

impl PhaseScope<'_, '_> {
	pub fn submit_review_unit(&self, request: &UnitProposal<'_>) -> Result<UnitProposalReceipt> {
		if self.access != Access::Domain || self.job.phase != Phase::Survey {
			return Err(Error::ScopeDenied);
		}
		let conn = self.transaction.conn;
		let job = &self.job;
		let operation = Operation::SubmitReviewUnit;
		let key = format!("{}:{}", operation.as_str(), request.key.expose());
		let replay = conn.query_row(
			"SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key=?2 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3)",
			params![job.id,key,job.repo_id], |row| {
				let stored = Stored { operation: row.get_ref(0)?.as_str()?, digest: row.get_ref(1)?.as_blob()? };
				if checkpoints::replay_decision(Some(&stored), operation, request.digest) != Replay::Hit {
					return Ok(Err(Error::Conflict(Conflict::Checkpoint)));
				}
				let raw = row.get_ref(2)?.as_str()?;
				if raw.len() > 1024 { return Ok(Err(Error::Conflict(Conflict::Checkpoint))); }
				Ok(serde_json::from_str::<StoredReceipt>(raw)
					.map_err(|_| Error::Conflict(Conflict::Checkpoint)).and_then(StoredReceipt::receipt))
			}).optional()?.transpose()?;
		if let Some(receipt) = replay {
			return Ok(receipt);
		}
		let generation = job.generation_id.ok_or(Error::ScopeDenied)?;
		let mut seen = std::collections::HashSet::new();
		if request.dependencies.len() > 8
			|| request.source_refs.is_empty()
			|| request.dependencies.iter().any(|id| *id <= 0 || !seen.insert(*id))
		{
			return Err(Error::Conflict(Conflict::Assignment));
		}
		for id in request.dependencies {
			let epoch = conn.query_row(
				"SELECT u.assignment_epoch FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND g.repo_id=?5 AND ((?4 AND u.created_by_job_id=?3) OR EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?3 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=u.assignment_epoch))",
				params![id,generation,job.id,self.bootstrap,job.repo_id], |row|row.get::<_,i64>(0)
			).optional()?;
			if !match epoch {
				Some(epoch) => self.survey_unit_reference(*id, epoch)?,
				None => false,
			} {
				return Err(Error::ScopeDenied);
			}
		}
		let policy = admission::load_policy_raw(conn, job.repo_id, job.campaign_id)?;
		if checkpoints::accepted_count_raw(conn, job.repo_id, job.id, operation)?
			>= i64::from(policy.max_units_per_survey)
		{
			return Err(Error::Conflict(Conflict::CheckpointLimit));
		}
		let refs = UnitRefs::from_refs(request.source_refs.to_vec())?;
		inventory::verify_refs_raw(conn, job.repo_id, generation, refs.as_slice())?;
		let key_digest: String = crate::canonical::digest(request.key.expose().as_bytes())
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		let storage_key = format!("j{}.{key_digest}", job.id);
		let proposal = projection(
			&serde_json::json!({"band":request.priority_band.as_str(),"rationale":request.priority_rationale}),
		)?;
		let dependencies = projection(request.dependencies)?;
		let context = request.semantic_context.map(projection).transpose()?;
		let id = review_units::insert_admitted(
			conn,
			job.repo_id,
			&AdmittedUnit {
				generation,
				key: &storage_key,
				title: request.title,
				objective: request.objective,
				priority: Priority::Normal,
				proposal: Some(&proposal),
				refs: &refs,
				dependencies: Some(&dependencies),
				closure: request.closure_criteria.map(BoundedText::expose),
				context: context.as_deref(),
				carry_depth: 0,
				carried_from: None,
				created_by_job: Some(job.id),
			},
			self.transaction.now,
		)?;
		let receipt = StoredReceipt {
			protocol_version: 3,
			review_unit_id: id,
			assignment_epoch: 0,
			accepted_priority_band: Normal::Normal,
		};
		let response =
			serde_json::to_string(&receipt).map_err(|_| Error::Conflict(Conflict::Checkpoint))?;
		crate::review::changed(conn.execute(
			"INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?7)",
			params![job.id,key,operation.as_str(),request.digest.as_slice(),response,self.transaction.now,job.repo_id]
		)?,Conflict::Checkpoint)?;
		receipt.receipt()
	}
}

/// Closed metadata and already-admitted semantic values only; paths never pass
/// through generic prose JSON or acquire a new source from this projection.
fn projection<T: Serialize + ?Sized>(value: &T) -> Result<String> {
	let value = serde_json::to_value(value).map_err(loupe_core::review_payload::Error::from)?;
	let bytes = crate::canonical::canonical_bytes(&value);
	if bytes.len() > Payload::MAX_BYTES {
		return Err(
			loupe_core::text::Error::new(Payload::FIELD, loupe_core::text::Rule::Bytes).into()
		);
	}
	String::from_utf8(bytes).map_err(|_| Error::Conflict(Conflict::UnitState))
}
