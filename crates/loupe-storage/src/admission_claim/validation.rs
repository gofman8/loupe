//! Read-only validation of original sources, before initialization or admission.
use loupe_core::{JobKind, WORKFLOW_CONTRACT_VERSION};
use rusqlite::types::ValueRef;
use rusqlite::{params, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use super::{CallbackError, RecipeDecision, RecipeInput};
#[cfg(test)]
use crate::admission_quarantine as quarantine;
use crate::admission_quarantine::{Reason, Source};
use crate::review_authority::{Context, Generation, Phase};
use crate::{admission, jobs, review_intents, Conflict, Error};

pub(crate) enum Failure<E> {
	Defect(Reason),
	Unit(i64, Reason),
	Unexpected(E),
}
impl<E> std::fmt::Debug for Failure<E> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Defect(reason) => f.debug_tuple("Defect").field(reason).finish(),
			Self::Unit(id, reason) => f.debug_tuple("Unit").field(id).field(reason).finish(),
			Self::Unexpected(_) => f.write_str("Unexpected([redacted])"),
		}
	}
}
pub(crate) type Result<T, E> = std::result::Result<T, Failure<E>>;
pub(crate) fn invalid<E>() -> Failure<E> {
	Failure::Defect(Reason::InvalidData)
}
impl<E: From<Error>> From<Error> for Failure<E> {
	fn from(error: Error) -> Self {
		match error {
			Error::Validation(_)
			| Error::ReviewPayload(_)
			| Error::UnknownPaths(_)
			| Error::Ownership(_)
			| Error::NotFound(_, _) => invalid(),
			Error::Conflict(
				Conflict::CampaignPolicy
				| Conflict::GenerationState
				| Conflict::Assignment
				| Conflict::Checkpoint
				| Conflict::CheckpointEvidence
				| Conflict::FindingDetails
				| Conflict::LeadState
				| Conflict::JobState,
			) => invalid(),
			Error::Sqlite(
				rusqlite::Error::FromSqlConversionFailure(..)
				| rusqlite::Error::InvalidColumnType(..)
				| rusqlite::Error::IntegralValueOutOfRange(..)
				| rusqlite::Error::QueryReturnedNoRows
				| rusqlite::Error::Utf8Error(_),
			) => invalid(),
			other => Self::Unexpected(other.into()),
		}
	}
}
impl<E: From<Error>> From<rusqlite::Error> for Failure<E> {
	fn from(error: rusqlite::Error) -> Self {
		Error::from(error).into()
	}
}
impl<E> From<CallbackError<E>> for Failure<E> {
	fn from(error: CallbackError<E>) -> Self {
		match error {
			CallbackError::Incompatible(reason) => Self::Defect(reason),
			CallbackError::Unexpected(error) => Self::Unexpected(error),
		}
	}
}

pub(crate) fn source(candidate: &crate::admission_candidates::Candidate) -> Source {
	use crate::admission_candidates::CandidateKind as K;
	match candidate.source {
		K::QueuedJob => Source::Job(candidate.id),
		K::LeadIntent => Source::Lead(candidate.id),
		K::FindingIntent => Source::Finding(candidate.id),
		K::ExactSurveyBatch => Source::Batch(candidate.id),
		K::OrdinarySurvey => Source::Ordinary(candidate.id),
	}
}
pub(super) struct Planned {
	pub repo: i64,
	pub campaign: i64,
	pub generation: Option<i64>,
	pub phase: Phase,
	pub recipe: RecipeDecision,
	pub context: Context,
}

/// Recipes and commits are admitted from their actual scoped SQL columns;
/// the host policy receives a closed variant for a not-yet-created job.
pub(super) fn planned<E: From<Error>>(
	tx: &Transaction<'_>, repo: i64, source: Source,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
) -> Result<Option<Planned>, E> {
	let (campaign, generation, phase, recipe, head, attempts) = match source {
		Source::Job(id) => {
			let (campaign,generation,kind,recipe,head,attempts) = tx.query_row(
				"SELECT campaign_id,generation_id,kind,recipe,head_sha,attempts FROM jobs WHERE id=?1 AND repo_id=?2",
				params![id,repo], |r| Ok((r.get::<_,Option<i64>>(0)?,r.get::<_,Option<i64>>(1)?,crate::ingress::job_kind(r,2)?,crate::ingress::review_authority::optional_recipe(r,3)?,crate::ingress::optional_revision(r,4)?,r.get::<_,u32>(5)?)))?;
			let Some(campaign) = campaign else {
				if jobs::targets_phase_finding(tx, repo, id)? {
					return Err(Failure::Defect(Reason::CompatibilityPolicy));
				}
				return Ok(None);
			};
			let phase = match kind {
				JobKind::Survey => Phase::Survey,
				JobKind::Drilldown => Phase::Drilldown,
				JobKind::Verify => Phase::Verify,
				_ => return Err(invalid()),
			};
			(campaign, generation, phase, recipe, head, attempts)
		},
		Source::Lead(id) | Source::Finding(id) => {
			let subject = if matches!(source, Source::Lead(_)) {
				review_intents::Subject::Lead(id)
			} else {
				review_intents::Subject::Finding(id)
			};
			let intent = review_intents::get_subject_raw(tx, repo, subject)?.ok_or_else(invalid)?;
			(
				intent.admission_campaign_id,
				intent.generation_id,
				if matches!(source, Source::Lead(_)) { Phase::Drilldown } else { Phase::Verify },
				None,
				None,
				0,
			)
		},
		Source::Batch(id) => {
			let batch = crate::unit_holds::get_batch_raw(tx, repo, id)?.ok_or_else(invalid)?;
			(batch.campaign_id, Some(batch.generation_id), Phase::Survey, None, None, 0)
		},
		Source::Ordinary(id) | Source::Unit(id) => {
			let sql = if matches!(source, Source::Unit(_)) {
				"SELECT c.campaign_id,c.generation_id FROM review_campaigns c JOIN review_units u ON u.generation_id=c.generation_id WHERE u.review_unit_id=?1 AND c.repo_id=?2 AND c.state='active'"
			} else {
				"SELECT campaign_id,generation_id FROM review_campaigns WHERE generation_id=?1 AND repo_id=?2 AND state='active'"
			};
			let (campaign, generation) =
				tx.query_row(sql, params![id, repo], |r| Ok((r.get(0)?, r.get(1)?)))?;
			(campaign, generation, Phase::Survey, None, None, 0)
		},
	};
	let (campaign_recipe,target,campaign_generation,old_policy) = tx.query_row(
		"SELECT recipe,target_commit_sha,generation_id,effective_policy FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
		params![campaign,repo], |r| Ok((crate::review::parsed(r,0)?,crate::ingress::revision(r,1)?,r.get::<_,Option<i64>>(2)?,crate::ingress::admission_policy::is_v1(r,3)?)))?;
	if old_policy {
		return Err(Failure::Defect(Reason::CompatibilityPolicy));
	}
	let frozen = admission::load_policy_raw(tx, repo, campaign)?;
	let spent = admission::get_spending_raw(tx, repo, campaign)?.ok_or_else(invalid)?;
	admission::choose_pool(&frozen, spent, admission::WorkClass::Preparation)?;
	if generation != campaign_generation {
		return Err(invalid());
	}
	let generation_context = generation.map(|id| tx.query_row(
		"SELECT predecessor_generation_id,generation_commit_sha,state FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND workflow_contract_version=?3",
		params![id,repo,WORKFLOW_CONTRACT_VERSION], |r| Ok(Generation { id,predecessor:r.get(0)?,commit:crate::ingress::revision(r,1)?,state:crate::review::parsed(r,2)? }))).transpose()?;
	let context = Context {
		campaign_recipe,
		target_commit: target,
		generation: generation_context,
		head_sha: head,
		recipe,
	};
	if context.head_sha.as_ref().is_some_and(|sha| sha != &context.target_commit)
		|| context.generation.as_ref().is_some_and(|g| g.commit != context.target_commit)
	{
		return Err(invalid());
	}
	let input = if matches!(source, Source::Job(_)) {
		RecipeInput::Stored(context.recipe.as_ref())
	} else {
		RecipeInput::Planned(match phase {
			Phase::Survey => RecipeDecision::Coverage,
			Phase::Drilldown => RecipeDecision::Drilldown,
			Phase::Verify => RecipeDecision::Verify,
		})
	};
	let recipe = policy(phase, &context, input).map_err(Failure::from)?;
	if recipe.phase() != phase {
		return Err(invalid());
	}
	if let Source::Job(id) = source {
		let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND workflow_contract_version=?3 AND EXISTS(SELECT 1 FROM job_admission_charges c WHERE c.job_id=jobs.id AND c.campaign_id=jobs.campaign_id))",params![id,repo,WORKFLOW_CONTRACT_VERSION],|r|r.get(0))?;
		if !valid {
			return Err(invalid());
		}
		if attempts > 0
			&& generation.is_some()
			&& phase == Phase::Survey
			&& recipe != RecipeDecision::Bootstrap
			&& !has_retry_history(tx, repo, id)?
		{
			return Err(invalid());
		}
	}
	if let Some(id) = generation {
		let profile = super::delivery::profile_snapshot(tx, repo, id)?;
		if recipe != RecipeDecision::Bootstrap {
			let ready:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM generation_manifests m JOIN review_generations g ON g.generation_id=m.generation_id WHERE m.generation_id=?1 AND g.repo_id=?2 AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count)",params![id,repo],|r|r.get(0))?;
			if !ready || profile.is_none() {
				return Err(invalid());
			}
		}
	}
	Ok(Some(Planned { repo, campaign, generation, phase, recipe, context }))
}

fn has_retry_history(tx: &Transaction<'_>, repo: i64, job: i64) -> crate::Result<bool> {
	let assigned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.job_id=?1 AND j.repo_id=?2)",params![job,repo],|r|r.get(0))?;
	if assigned {
		return Ok(true);
	}
	let marker = tx
		.query_row(
			"SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key='initialize_survey_batch:ordinary' AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2)",
			params![job, repo],
			|row| {
				Ok(matches!(row.get_ref(0)?, ValueRef::Text(b"initialize_survey_batch"))
					&& matches!(row.get_ref(1)?, ValueRef::Blob(digest) if digest == Sha256::digest(b"{}").as_slice())
					&& matches!(row.get_ref(2)?, ValueRef::Text(b"{}")))
			},
		)
		.optional()?;
	Ok(marker == Some(true))
}

pub(crate) fn validate_source<E: From<Error>>(
	tx: &Transaction<'_>, repo: i64, source: Source,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
) -> Result<(), E> {
	let Some(plan) = planned(tx, repo, source, policy)? else {
		return Ok(());
	};
	match source {
		Source::Lead(id) => {
			validate_pending_subject(tx, review_intents::Subject::Lead(id), &plan)?;
			super::delivery::lead_snapshot::<E>(tx, id, &plan)?;
		},
		Source::Finding(id) => {
			validate_pending_subject(tx, review_intents::Subject::Finding(id), &plan)?;
			super::delivery::finding_snapshot::<E>(tx, id, &plan)?;
		},
		Source::Unit(id) => {
			super::delivery::unit_snapshot::<E>(
				tx,
				repo,
				id,
				plan.generation.ok_or_else(invalid)?,
				None,
			)?;
		},
		Source::Job(id) => {
			let job = jobs::get_scoped_raw(tx, repo, id)?.ok_or_else(invalid)?;
			if job.scheduling_band.is_none()
				|| job.effective_priority.is_none_or(|n| !(0..=550).contains(&n))
			{
				return Err(invalid());
			}
			super::validate_retry_subject(tx, &job)?;
			match plan.phase {
				Phase::Drilldown => {
					super::delivery::lead_snapshot::<E>(
						tx,
						job.assigned_lead_id.ok_or_else(invalid)?,
						&plan,
					)?;
				},
				Phase::Verify => {
					super::delivery::finding_snapshot::<E>(
						tx,
						job.target_finding_id.ok_or_else(invalid)?,
						&plan,
					)?;
				},
				Phase::Survey
					if plan.generation.is_some() && plan.recipe != RecipeDecision::Bootstrap =>
				{
					super::delivery::assignment_snapshot::<E>(
						tx,
						repo,
						id,
						plan.generation.ok_or_else(invalid)?,
					)?;
				},
				Phase::Survey => {},
			}
		},
		Source::Batch(id) => {
			let batch = crate::unit_holds::get_batch_raw(tx, repo, id)?.ok_or_else(invalid)?;
			for hold in crate::unit_holds::batch_holds_raw(tx, repo, id)? {
				if !matches!(
					crate::review_unit_results::get_evidence_raw(
						tx,
						repo,
						hold.producing_result_id
					)?,
					crate::StoredEvidence::Recorded(_)
				) {
					return Err(Failure::Defect(Reason::CompatibilityPolicy));
				}
				super::delivery::unit_snapshot::<E>(
					tx,
					repo,
					hold.unit_id,
					batch.generation_id,
					None,
				)?;
			}
			crate::unit_holds::validate_pending_batch(tx, repo, id)?;
		},
		Source::Ordinary(_) => {},
	}
	Ok(())
}
fn validate_pending_subject<E: From<Error>>(
	tx: &Transaction<'_>, subject: review_intents::Subject, plan: &Planned,
) -> Result<(), E> {
	let intent = review_intents::get_subject_raw(tx, plan.repo, subject)?.ok_or_else(invalid)?;
	super::validate_parent(tx, &intent, &plan.phase.job_kind())?;
	let profile =
		super::delivery::profile_snapshot(tx, plan.repo, plan.generation.ok_or_else(invalid)?)?
			.ok_or_else(invalid)?;
	if intent.state != review_intents::State::Pending
		|| !review_intents::pending_subject_eligible(tx, &intent)?
		|| intent.admitted_job_id.is_some()
		|| intent.block_reason.is_some()
		|| (intent.kind == review_intents::IntentKind::LogicalContinuation
			&& intent.not_before.is_none())
		|| intent.priority.score > 550
		|| intent.source_commit_sha.expose() != plan.context.target_commit.expose()
		|| intent.profile_version != i64::from(profile.version.get())
		|| intent.profile_digest != profile.digest
	{
		return Err(invalid());
	}
	Ok(())
}

#[cfg(test)]
pub(crate) struct MaintenanceProgress {
	pub inspected: u32,
	pub repaired: u32,
	pub next: Option<quarantine::Cursor>,
	pub scan_complete: bool,
}
#[cfg(test)]
pub(crate) fn maintain_campaign<E: From<Error>>(
	tx: &Transaction<'_>, campaign_scope: (i64, i64), now: i64, cursor: Option<quarantine::Cursor>,
	max_rows: u32, max_repairs: u32,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
) -> std::result::Result<MaintenanceProgress, E> {
	if !(1..=32).contains(&max_repairs) {
		return Err(Error::Conflict(Conflict::CampaignPolicy).into());
	}
	let (repo, campaign) = campaign_scope;
	let page = quarantine::page(tx, repo, campaign, cursor, max_rows)?;
	let mut out =
		MaintenanceProgress { inspected: 0, repaired: 0, next: None, scan_complete: false };
	for source in &page {
		out.inspected += 1;
		out.next = Some(quarantine::Cursor::after(*source)?);
		match validate_source(tx, repo, *source, policy) {
			Ok(()) => {},
			Err(Failure::Defect(reason) | Failure::Unit(_, reason)) => {
				if quarantine::hold(tx, repo, *source, reason, now)? {
					out.repaired += 1;
				}
			},
			Err(Failure::Unexpected(error)) => return Err(error),
		}
		if out.repaired == max_repairs {
			return Ok(out);
		}
	}
	if page.len() < max_rows as usize {
		out.next = None;
		out.scan_complete = true;
	}
	Ok(out)
}
