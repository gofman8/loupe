//! Validated worker delivery owns one complete admission transaction.
//! No raw SQL or unvalidated claim-and-commit API escapes this owner.
//!
//! The public facade intersects advertised kinds with runtime gates and owns
//! the IMMEDIATE transaction through complete bounded delivery. Its private
//! materialization leaf never commits or grants standalone delivery authority.
//!
//! Before calling the leaf, validation rejects a ready ordinary execution
//! retry whose assignment rows and InitializeSurveyBatch checkpoint are both
//! missing. Otherwise initialization would conceal the lost history by selecting
//! new work. Unpinned/bootstrap attempts require the consumer's explicit recipe
//! exception; the storage leaf does not maintain a second recipe parser.

use loupe_core::{JobState, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::{Db as DbSource, Ingress, Source, Worker};
type JobKind = loupe_core::JobKind<DbSource>;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::admission::{self, CapacityRefusal, Charged, Selection, WorkClass};
use crate::admission_candidates::{self, Candidate, CandidateKind, Request};
#[cfg(test)]
use crate::admission_policy::CampaignPolicyV2;
#[cfg(test)]
use crate::admission_preparation::create_preparation;
use crate::admission_preparation::{frozen_policy, insert_job, NewJob};
use crate::admission_quarantine::{self as quarantine, Source as AdmissionSource};
use crate::review_authority::{Context, Phase, RecipeText};
use crate::review_intents::{self, IntentKind, Subject};
use crate::scheduler::{self, Band, Claimed};
use crate::{campaigns, jobs, unit_holds, Conflict, Entity, Error, Result};

mod delivery;
pub(crate) mod validation;
pub use delivery::{DeliverySnapshot, PhaseDelivery, PhaseSubject};
pub use quarantine::Reason as Incompatibility;

#[cfg(test)]
mod validation_tests;

pub const MAX_REPAIRS: u32 = 32;

// debug-ok: recipes are closed host policy categories without model text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipeDecision {
	Bootstrap,
	Coverage,
	Incremental,
	Drilldown,
	Verify,
}
impl RecipeDecision {
	pub fn phase(self) -> Phase {
		match self {
			Self::Bootstrap | Self::Coverage | Self::Incremental => Phase::Survey,
			Self::Drilldown => Phase::Drilldown,
			Self::Verify => Phase::Verify,
		}
	}
}

/// Stored input retains its original SQL mark; planned input is host-owned.
pub enum RecipeInput<'a> {
	Stored(Option<&'a loupe_core::text::BoundedText<RecipeText, DbSource>>),
	Planned(RecipeDecision),
}

/// Only explicit permanent incompatibility permits quarantine. Unexpected
/// callback failures abort the entire transaction, including earlier repairs.
pub enum CallbackError<E> {
	Incompatible(Incompatibility),
	Unexpected(E),
}
impl<E> std::fmt::Debug for CallbackError<E> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Incompatible(reason) => f.debug_tuple("Incompatible").field(reason).finish(),
			Self::Unexpected(_) => f.write_str("Unexpected([redacted])"),
		}
	}
}

pub struct DeliveryRequest<'a> {
	pub worker_id: i64,
	pub legacy_kinds: &'a [loupe_core::JobKind<Worker>],
	pub phase_kinds: &'a [loupe_core::JobKind<Worker>],
	pub policy: &'a scheduler::ClaimPolicy,
	pub capability_hash: &'a [u8; 32],
	pub legacy_lease_seconds: i64,
}

/// Clock, active actor, ranking, validation and bounded delivery all execute
/// under the same IMMEDIATE lock. Only owned callback output can escape.
pub fn claim_with_delivery<T, E: From<Error>>(
	db: &crate::Db, _worker: &Ingress<Worker>, request: &DeliveryRequest<'_>,
	clock: impl FnOnce() -> i64, repairs_left: &mut u32,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
	deliver: &mut impl FnMut(DeliverySnapshot) -> std::result::Result<T, CallbackError<E>>,
) -> std::result::Result<Option<T>, E> {
	if *repairs_left > MAX_REPAIRS {
		return Err(Error::Conflict(Conflict::CampaignPolicy).into());
	}
	let mut remaining = *repairs_left;
	let output = db
		.with_conn(|conn| {
			let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
			let now = clock();
			let legacy: Vec<_> = request
				.legacy_kinds
				.iter()
				.filter(|kind| {
					jobs::RUNTIME_KINDS
						.iter()
						.any(|allowed| kind.is_known() && kind.as_str() == allowed.as_str())
				})
				.cloned()
				.collect();
			let phases: Vec<_> = request
				.phase_kinds
				.iter()
				.filter(|kind| {
					jobs::RUNTIME_KINDS
						.iter()
						.any(|allowed| kind.is_known() && kind.as_str() == allowed.as_str())
						&& scheduler::PHASE_RUNTIME_KINDS
							.iter()
							.any(|allowed| kind.as_str() == allowed.as_str())
				})
				.cloned()
				.collect();
			let req = Request {
				worker_id: request.worker_id,
				legacy_kinds: &legacy,
				phase_kinds: &phases,
				now,
				policy: request.policy,
				limit: 1,
			};
			let result = claim_in_transaction(
				&tx,
				&req,
				request.capability_hash,
				request.legacy_lease_seconds,
				&mut remaining,
				policy,
				deliver,
			);
			match result {
				Ok(value) => {
					tx.commit()?;
					Ok(Ok(value))
				},
				Err(error) => Ok(Err(error)),
			}
		})
		.map_err(E::from)??;
	*repairs_left = remaining;
	Ok(output)
}

fn claim_in_transaction<T, E: From<Error>, S: Source>(
	tx: &Transaction<'_>, req: &Request<'_, S>, hash: &[u8; 32], legacy_seconds: i64,
	repairs_left: &mut u32,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
	deliver: &mut impl FnMut(DeliverySnapshot) -> std::result::Result<T, CallbackError<E>>,
) -> std::result::Result<Option<T>, E> {
	let active = tx.query_row("SELECT EXISTS(SELECT 1 FROM workers WHERE id=?1 AND kind='worker' AND revoked_at IS NULL)", [req.worker_id], |row| row.get::<_, bool>(0)).map_err(Error::from)?;
	if !active || req.now < 0 {
		return Err(conflict().into());
	}
	while *repairs_left > 0 {
		let Some(candidate) =
			admission_candidates::ranked_raw(tx, &Request { limit: 1, ..*req })?.into_iter().next()
		else {
			return Ok(None);
		};
		let source = validation::source(&candidate);
		tx.execute_batch("SAVEPOINT review_candidate").map_err(Error::from)?;
		let attempt = (|| -> validation::Result<Option<T>, E> {
			validation::validate_source(tx, candidate.repo_id, source, policy)?;
			let selected = match materialize(tx, &candidate, req, hash, legacy_seconds)? {
				Outcome::Uncommitted(selected) => selected,
				Outcome::Stale => return Ok(None),
				Outcome::CapacityRefused(_reason) => return Ok(None),
			};
			let snapshot = delivery::snapshot(tx, &selected.job, policy)?;
			Ok(Some(deliver(snapshot).map_err(validation::Failure::from)?))
		})();
		let (target, reason) = match attempt {
			Ok(Some(value)) => {
				tx.execute_batch("RELEASE review_candidate").map_err(Error::from)?;
				return Ok(Some(value));
			},
			Ok(None) => {
				tx.execute_batch("ROLLBACK TO review_candidate; RELEASE review_candidate")
					.map_err(Error::from)?;
				return Ok(None);
			},
			Err(validation::Failure::Unexpected(error)) => return Err(error),
			Err(validation::Failure::Defect(reason)) => (source, reason),
			Err(validation::Failure::Unit(id, reason)) => {
				if let AdmissionSource::Ordinary(generation) = source {
					let owned = tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND g.repo_id=?3)", params![id,generation,candidate.repo_id], |row| row.get::<_,bool>(0)).map_err(Error::from)?;
					if !owned {
						return Err(Error::ScopeDenied.into());
					}
					(AdmissionSource::Unit(id), reason)
				} else {
					(source, reason)
				}
			},
		};
		tx.execute_batch("ROLLBACK TO review_candidate; RELEASE review_candidate")
			.map_err(Error::from)?;
		if !quarantine::hold(tx, candidate.repo_id, target, reason, req.now)? {
			return Err(conflict().into());
		}
		*repairs_left -= 1;
	}
	Ok(None)
}

// debug-ok: typed job owners redact content; other alternatives are closed metadata.
#[derive(Debug)]
pub(crate) enum Outcome {
	/// Tentative database effects only; caller still owns validation and commit.
	Uncommitted(Box<Claimed>),
	/// No writes: the supplied candidate is no longer the first ranked source.
	Stale,
	/// No writes: validated frozen spending cannot fund this work class.
	CapacityRefused(CapacityRefusal),
}

fn conflict() -> Error {
	Error::Conflict(Conflict::JobState)
}

/// Rechecks the single global selector, then joins creation, first lease,
/// assignment/intent CAS, charge and fairness in the caller's transaction.
pub(crate) fn materialize<S: Source>(
	tx: &Transaction<'_>, candidate: &Candidate, req: &Request<'_, S>, capability_hash: &[u8; 32],
	legacy_lease_seconds: i64,
) -> Result<Outcome> {
	let active_worker: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM workers WHERE id=?1 AND kind='worker' AND revoked_at IS NULL)",
		[req.worker_id],
		|r| r.get(0),
	)?;
	if !active_worker {
		return Err(conflict());
	}
	let checked = Request { limit: 1, ..*req };
	if admission_candidates::ranked_raw(tx, &checked)?.first() != Some(candidate) {
		return Ok(Outcome::Stale);
	}
	let Some(campaign_id) = candidate.campaign_id else {
		if candidate.source != CandidateKind::QueuedJob || legacy_lease_seconds <= 0 {
			return Err(conflict());
		}
		let expiry = req.now.checked_add(legacy_lease_seconds).ok_or_else(conflict)?;
		lease(tx, candidate.repo_id, candidate.id, req, capability_hash, expiry, None)?;
		return Ok(Outcome::Uncommitted(Box::new(Claimed {
			job: get_job(tx, candidate.repo_id, candidate.id)?,
			assigned_units: Vec::new(),
			resumed: false,
		})));
	};
	let campaign = campaigns::get_scoped_raw(tx, candidate.repo_id, campaign_id)?
		.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	if campaign.repo_id != candidate.repo_id
		|| campaign.generation_id != candidate.generation_id
		|| campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|d| d <= req.now)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let policy = frozen_policy(tx, &campaign)?;
	let band = candidate.stored_band.ok_or_else(conflict)?;
	let score = candidate.stored_score.filter(|s| (0..=550).contains(s)).ok_or_else(conflict)?;
	let class = work_class(&candidate.kind, band)?;
	let spent = admission::get_spending_raw(tx, candidate.repo_id, campaign_id)?
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let selection = admission::choose_pool(&policy, spent, class)?;
	let fresh = candidate.source != CandidateKind::QueuedJob;
	if fresh && let Selection::Refused(reason) = selection {
		return Ok(Outcome::CapacityRefused(reason));
	}
	let phase = policy.phase(&candidate.kind)?;
	if req.policy.lease_seconds <= 0 || req.policy.lease_report_grace_seconds <= 0 {
		return Err(conflict());
	}
	let hard = req.now.checked_add(phase.deadline_seconds).ok_or_else(conflict)?;
	let hard = campaign.deadline_at.map_or(hard, |d| d.min(hard));
	let submit = hard.checked_sub(phase.submit_margin_seconds).ok_or_else(conflict)?;
	let expiry = req
		.now
		.checked_add(req.policy.lease_seconds)
		.ok_or_else(conflict)?
		.min(hard.checked_add(req.policy.lease_report_grace_seconds).ok_or_else(conflict)?);
	let job_id = if fresh {
		let (parent, continuation, lead, finding) = match candidate.source {
			CandidateKind::LeadIntent | CandidateKind::FindingIntent => {
				let subject = subject(candidate)?;
				let intent = review_intents::get_subject_raw(tx, candidate.repo_id, subject)?
					.ok_or_else(conflict)?;
				if Some(intent.revision) != candidate.intent_revision
					|| intent.priority.band != band
					|| i64::from(intent.priority.score) != score
					|| intent.repo_id != candidate.repo_id
					|| intent.admission_campaign_id != campaign_id
					|| intent.generation_id != candidate.generation_id
				{
					return Err(conflict());
				}
				validate_parent(tx, &intent, &candidate.kind)?;
				(
					Some(intent.originating_job_id),
					(intent.kind == IntentKind::LogicalContinuation)
						.then_some(intent.originating_job_id),
					match subject {
						Subject::Lead(id) => Some(id),
						_ => None,
					},
					match subject {
						Subject::Finding(id) => Some(id),
						_ => None,
					},
				)
			},
			CandidateKind::ExactSurveyBatch => {
				let batch = unit_holds::get_batch_raw(tx, candidate.repo_id, candidate.id)?
					.ok_or_else(conflict)?;
				if batch.repo_id != candidate.repo_id
					|| batch.campaign_id != campaign_id
					|| Some(batch.generation_id) != candidate.generation_id
					|| batch.priority.band != band
					|| i64::from(batch.priority.score) != score
				{
					return Err(conflict());
				}
				(Some(batch.producer_job_id), Some(batch.producer_job_id), None, None)
			},
			CandidateKind::OrdinarySurvey => {
				let parent=tx.query_row("SELECT id FROM jobs WHERE repo_id=?1 AND campaign_id=?2 AND generation_id=?3 AND kind='survey' AND state='succeeded' ORDER BY id DESC LIMIT 1",params![candidate.repo_id,campaign_id,candidate.generation_id],|r|r.get(0)).optional()?;
				(parent, None, None, None)
			},
			CandidateKind::QueuedJob => unreachable!(),
		};
		insert_job(
			tx,
			&campaign,
			&policy,
			&NewJob {
				kind: &candidate.kind,
				band,
				score,
				parent,
				continuation,
				lead,
				finding,
				survey_recipe: "coverage",
			},
			req.now,
		)?
	} else {
		let job = get_job(tx, candidate.repo_id, candidate.id)?;
		validate_planned_scope(tx, &job, &campaign)?;
		if job.attempts >= policy.max_attempts
			|| job.token_budget != phase.token_budget
			|| job.workflow_contract_version != Some(WORKFLOW_CONTRACT_VERSION)
			|| job.scheduling_band != Some(band)
			|| job.effective_priority != Some(score)
		{
			return Err(conflict());
		}
		let charged: bool = tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM job_admission_charges WHERE job_id=?1 AND campaign_id=?2)",
			params![job.id, campaign_id],
			|r| r.get(0),
		)?;
		if !charged {
			return Err(Error::Conflict(Conflict::CampaignPolicy));
		}
		validate_retry_subject(tx, &job)?;
		job.id
	};
	lease(tx, candidate.repo_id, job_id, req, capability_hash, expiry, Some((hard, submit)))?;
	let mut assigned_units = Vec::new();
	let mut resumed = false;
	match candidate.source {
		CandidateKind::LeadIntent | CandidateKind::FindingIntent => {
			review_intents::admit_subject_raw(
				tx,
				candidate.repo_id,
				subject(candidate)?,
				candidate.intent_revision.ok_or_else(conflict)?,
				job_id,
				req.now,
			)?;
		},
		CandidateKind::ExactSurveyBatch => {
			assigned_units = unit_holds::admit_exact_batch_raw(
				tx,
				candidate.repo_id,
				candidate.id,
				job_id,
				req.now,
			)?
			.into_iter()
			.filter(|a| !a.completed)
			.map(|a| a.unit_id)
			.collect();
		},
		CandidateKind::OrdinarySurvey => {
			review_intents::job_context(tx, candidate.repo_id, job_id)?;
			let batch = scheduler::initialize_ordinary_batch(tx, job_id, req.now)?;
			assigned_units = batch.units;
			resumed = batch.resumed;
		},
		CandidateKind::QueuedJob => {
			let job = get_job(tx, candidate.repo_id, job_id)?;
			if job.kind == JobKind::Survey && job.generation_id.is_some() {
				let batch = scheduler::initialize_ordinary_batch(tx, job_id, req.now)?;
				assigned_units = batch.units;
				resumed = batch.resumed;
			}
		},
	}
	match (fresh, admission::charge_raw(tx, candidate.repo_id, job_id, class, req.now)?) {
		(true, Charged::Fresh(_)) | (false, Charged::Replayed(_)) => {},
		_ => return Err(Error::Conflict(Conflict::CampaignPolicy)),
	}
	fairness(tx, candidate, req)?;
	Ok(Outcome::Uncommitted(Box::new(Claimed {
		job: get_job(tx, candidate.repo_id, job_id)?,
		assigned_units,
		resumed,
	})))
}

fn get_job(tx: &Connection, repo: i64, id: i64) -> Result<jobs::JobRow> {
	jobs::get_scoped_raw(tx, repo, id)?.ok_or(Error::NotFound(Entity::Job, id))
}
fn subject(c: &Candidate) -> Result<Subject> {
	match c.source {
		CandidateKind::LeadIntent => Ok(Subject::Lead(c.id)),
		CandidateKind::FindingIntent => Ok(Subject::Finding(c.id)),
		_ => Err(conflict()),
	}
}
fn work_class(kind: &JobKind, band: Band) -> Result<WorkClass> {
	match (kind, band) {
		(JobKind::Survey, _) => Ok(WorkClass::Survey),
		(JobKind::Drilldown, Band::Urgent) => Ok(WorkClass::UrgentDrilldown),
		(JobKind::Drilldown, _) => Ok(WorkClass::Drilldown),
		(JobKind::Verify, Band::Urgent) => Ok(WorkClass::UrgentVerification),
		(JobKind::Verify, _) => Ok(WorkClass::Verification),
		_ => Err(conflict()),
	}
}

fn validate_parent(
	tx: &Transaction<'_>, intent: &review_intents::Intent, kind: &JobKind,
) -> Result<()> {
	let parent = get_job(tx, intent.repo_id, intent.originating_job_id)?;
	if parent.repo_id != intent.repo_id
		|| parent.campaign_id != Some(intent.originating_campaign_id)
		|| parent.generation_id != intent.generation_id
	{
		return Err(conflict());
	}
	let valid = if intent.kind == IntentKind::LogicalContinuation {
		parent.kind == *kind
			&& matches!(parent.state, JobState::Succeeded | JobState::Failed | JobState::Cancelled)
			&& match intent.subject {
				Subject::Lead(id) => parent.assigned_lead_id == Some(id),
				Subject::Finding(id) => parent.target_finding_id == Some(id),
			}
	} else {
		match kind {
			JobKind::Drilldown => matches!(parent.kind, JobKind::Survey | JobKind::Drilldown),
			JobKind::Verify => parent.kind == JobKind::Drilldown,
			_ => false,
		}
	};
	if !valid {
		return Err(conflict());
	}
	Ok(())
}

fn validate_retry_subject(tx: &Transaction<'_>, job: &jobs::JobRow) -> Result<()> {
	let subject = match job.kind {
		JobKind::Drilldown if job.target_finding_id.is_none() => {
			Subject::Lead(job.assigned_lead_id.ok_or_else(conflict)?)
		},
		JobKind::Verify if job.assigned_lead_id.is_none() => {
			Subject::Finding(job.target_finding_id.ok_or_else(conflict)?)
		},
		JobKind::Survey if job.assigned_lead_id.is_none() && job.target_finding_id.is_none() => {
			return Ok(())
		},
		_ => return Err(conflict()),
	};
	let intent = review_intents::get_subject_raw(tx, job.repo_id, subject)?.ok_or_else(conflict)?;
	let context = review_intents::job_context(tx, job.repo_id, job.id)?;
	if intent.state != review_intents::State::Admitted
		|| intent.admitted_job_id != Some(job.id)
		|| intent.repo_id != job.repo_id
		|| Some(intent.admission_campaign_id) != job.campaign_id
		|| intent.generation_id != job.generation_id
		|| job.parent_job_id != Some(intent.originating_job_id)
		|| job.continuation_of_job_id
			!= (intent.kind == IntentKind::LogicalContinuation).then_some(intent.originating_job_id)
		|| job.scheduling_band != Some(intent.priority.band)
		|| job.effective_priority != Some(i64::from(intent.priority.score))
	{
		return Err(conflict());
	}
	if context.sha != intent.source_commit_sha
		|| i64::from(context.profile.version.get()) != intent.profile_version
		|| context.profile.digest != intent.profile_digest
	{
		return Err(conflict());
	}
	validate_parent(tx, &intent, &job.kind)?;
	let eligible:bool=match subject {
		Subject::Lead(id)=>tx.query_row("SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2 AND status='open')",params![id,job.generation_id],|r|r.get(0))?,
		Subject::Finding(id)=>tx.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2 AND state='validating')",params![id,job.repo_id],|r|r.get(0))?,
	};
	if !eligible {
		return Err(conflict());
	}
	Ok(())
}

fn validate_planned_scope(
	tx: &Transaction<'_>, job: &jobs::JobRow, campaign: &campaigns::Campaign,
) -> Result<()> {
	if job.repo_id != campaign.repo_id
		|| job.campaign_id != Some(campaign.campaign_id)
		|| job.generation_id != campaign.generation_id
		|| job.head_sha.as_ref().is_some_and(|s| s.expose() != campaign.target_commit_sha.expose())
	{
		return Err(conflict());
	}
	if let Some(generation) = job.generation_id {
		let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND generation_commit_sha=?3 AND workflow_contract_version=?4)",params![generation,campaign.repo_id,campaign.target_commit_sha.expose(),WORKFLOW_CONTRACT_VERSION],|r|r.get(0))?;
		if !valid {
			return Err(Error::Conflict(Conflict::GenerationState));
		}
	} else if job.head_sha.is_some() {
		return Err(conflict());
	}
	Ok(())
}

fn lease<S: Source>(
	tx: &Transaction<'_>, repo: i64, id: i64, req: &Request<'_, S>, hash: &[u8; 32], expiry: i64,
	phase_deadlines: Option<(i64, i64)>,
) -> Result<()> {
	let (hard, submit) = phase_deadlines.unzip();
	let attempts = get_job(tx, repo, id)?.attempts.checked_add(1).ok_or_else(conflict)?;
	let changed=tx.execute("UPDATE jobs SET state='leased',worker_id=?2,lease_expires_at=?3,attempts=?4,started_at=COALESCE(started_at,?5),job_capability_hash=?6,hard_deadline_at=?7,soft_deadline_at=?8,submit_by=?8,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1 AND state='queued'",params![id,req.worker_id,expiry,attempts,req.now,hash.as_slice(),hard,submit])?;
	if changed != 1 {
		return Err(conflict());
	}
	Ok(())
}

fn fairness<S: Source>(
	tx: &Transaction<'_>, candidate: &Candidate, req: &Request<'_, S>,
) -> Result<()> {
	let seq: i64 =
		tx.query_row("SELECT seq FROM scheduler_clock WHERE singleton=1", [], |r| r.get(0))?;
	let seq = seq.checked_add(1).filter(|n| *n > 0).ok_or_else(conflict)?;
	tx.execute("UPDATE scheduler_clock SET seq=?1 WHERE singleton=1", [seq])?;
	tx.execute("INSERT INTO scheduler_repo_state(repo_id,last_claim_seq,burst) VALUES(?1,?2,CASE WHEN ?3='survey' THEN 0 ELSE 1 END) ON CONFLICT(repo_id) DO UPDATE SET last_claim_seq=excluded.last_claim_seq,burst=CASE WHEN ?3='survey' OR scheduler_repo_state.burst>=?4 THEN 0 ELSE scheduler_repo_state.burst+1 END",params![candidate.repo_id,seq,candidate.kind.as_str(),req.policy.urgency_burst_length])?;
	Ok(())
}

#[cfg(test)]
mod tests;
