//! Payload-independent execution control. Raw workflow leaves stay private;
//! workers enter through LeaseControl and operators through repository scope.
use loupe_core::text::policy::Reason;
use loupe_core::text::BoundedText;
use loupe_provenance::Source;
use rusqlite::{params, Connection, OptionalExtension};

use crate::ingress::lifecycle::RetryLimits;
use crate::review::changed;
use crate::review_intents::{self, BlockReason};
use crate::scheduler::{FailureReason, RetryOutcome};
use crate::{Conflict, Entity, Error, Result};

struct RetryContext {
	leased_phase: bool,
	attempt: Option<u32>,
	campaign_active: Option<bool>,
	deadline: Option<i64>,
	policy: Option<RetryLimits>,
	compatible_payload: bool,
	expired: bool,
}
pub(crate) fn retry_or_fail<S: Source>(
	tx: &Connection, repo: i64, job: i64, now: i64, error: FailureReason<'_, S>,
) -> Result<RetryOutcome> {
	let row = tx.query_row(
		"SELECT j.state='leased' AND j.kind IN('survey','drilldown','verify') AND j.campaign_id IS NOT NULL,
		 j.attempts,c.state='active',c.deadline_at,c.effective_policy,c.effective_policy_digest,
		 j.recipe,g.generated_profile,typeof(j.lease_expires_at)='integer' AND j.lease_expires_at<?3
		 FROM jobs j LEFT JOIN review_campaigns c ON c.campaign_id=j.campaign_id AND c.repo_id=j.repo_id
		 LEFT JOIN review_generations g ON g.generation_id=j.generation_id AND g.repo_id=j.repo_id
		 WHERE j.id=?1 AND j.repo_id=?2", params![job,repo,now], |r| {
			let attempt=u32::try_from(r.get::<_,i64>(1)?).ok().filter(|n| *n>0);
			Ok(RetryContext { leased_phase:r.get(0)?,attempt,campaign_active:r.get(2)?,deadline:r.get(3)?,
				policy: match attempt { Some(attempt)=>crate::ingress::lifecycle::retry_policy(r,4,5,attempt)?,None=>None },
				compatible_payload:crate::ingress::lifecycle::recipe(r,6)? && crate::ingress::lifecycle::profile(r,7)?,
				expired:r.get::<_,Option<bool>>(8)?.unwrap_or(false), })
		}).optional()?.ok_or(Error::NotFound(Entity::Job,job))?;
	if !row.leased_phase || matches!(error, FailureReason::LeaseExpired) && !row.expired {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let (reason, message) = if row.campaign_active != Some(true) {
		(BlockReason::CampaignCancelled, "campaign inactive")
	} else if row.deadline.is_some_and(|at| at <= now) {
		(BlockReason::CampaignDeadline, "campaign deadline")
	} else if !row.compatible_payload {
		(BlockReason::CompatibilityPolicy, "incompatible stored review payload")
	} else if let (Some(attempt), Some(policy)) = (row.attempt, row.policy) {
		if attempt >= policy.maximum {
			(BlockReason::ExecutionExhausted, error.expose())
		} else if let Some(eligible) = now.checked_add(policy.delay) {
			changed(tx.execute("UPDATE jobs SET state='queued',worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL,eligible_at=?2,hard_deadline_at=NULL,soft_deadline_at=NULL,submit_by=NULL,error=?3 WHERE id=?1 AND repo_id=?4 AND state='leased'",params![job,eligible,error.expose(),repo])?,Conflict::JobState)?;
			return Ok(RetryOutcome::Requeued { eligible_at: eligible });
		} else {
			(BlockReason::CompatibilityPolicy, "retry timestamp overflow")
		}
	} else {
		(BlockReason::CompatibilityPolicy, "incompatible CampaignPolicy")
	};
	terminalize(tx, repo, job, now, "failed", message, reason)?;
	Ok(RetryOutcome::Failed)
}

fn terminalize(
	tx: &Connection, repo: i64, job: i64, now: i64, state: &str, message: &str, reason: BlockReason,
) -> Result<()> {
	changed(tx.execute("UPDATE jobs SET state=?2,error=?3,finished_at=?4,worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL,hard_deadline_at=NULL,soft_deadline_at=NULL,submit_by=NULL WHERE id=?1 AND repo_id=?5 AND campaign_id IS NOT NULL AND kind IN('survey','drilldown','verify') AND state IN('queued','leased')",params![job,state,message,now,repo])?,Conflict::JobState)?;
	review_intents::block_job_work_raw(tx, repo, job, reason, now)
}

/// Cancel one phase job without decoding domain payloads. False means an
/// existing in-scope non-phase job, for the separate legacy operator path.
pub fn cancel(scope: &crate::scope::RepoScope<'_>, job: i64, now: i64) -> Result<bool> {
	scope.require_operator()?;
	let phase:bool=scope.conn.query_row("SELECT campaign_id IS NOT NULL AND kind IN('survey','drilldown','verify') FROM jobs WHERE id=?1 AND repo_id=?2",params![job,scope.repo_id],|r|r.get(0)).optional()?.ok_or(Error::NotFound(Entity::Job,job))?;
	if !phase {
		return Ok(false);
	}
	terminalize(
		scope.conn,
		scope.repo_id,
		job,
		now,
		"cancelled",
		crate::jobs::JOB_CANCELLED_BY_ADMIN_ERROR,
		BlockReason::CampaignCancelled,
	)?;
	Ok(true)
}

pub(crate) fn cancel_queued<S: Source>(
	tx: &Connection, repo: i64, campaign: i64, now: i64, error: &BoundedText<Reason, S>,
) -> Result<usize> {
	let deadline: Option<i64> = tx
		.query_row(
			"SELECT deadline_at FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
			params![campaign, repo],
			|r| r.get(0),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Campaign, campaign))?;
	let reason = if deadline.is_some_and(|at| at <= now) {
		BlockReason::CampaignDeadline
	} else {
		BlockReason::CampaignCancelled
	};
	cancel_queued_reason(tx, repo, campaign, now, error.expose(), reason)
}
pub(crate) fn cancel_queued_reason(
	tx: &Connection, repo: i64, campaign: i64, now: i64, error: &str, reason: BlockReason,
) -> Result<usize> {
	let ids:Vec<i64>=tx.prepare("SELECT id FROM jobs WHERE campaign_id=?1 AND repo_id=?2 AND state='queued' AND kind IN('survey','drilldown','verify')")?.query_map(params![campaign,repo],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
	for job in &ids {
		terminalize(tx, repo, *job, now, "cancelled", error, reason)?;
	}
	Ok(ids.len())
}

pub(crate) fn heartbeat(
	tx: &Connection, repo: i64, job: i64, now: i64, lease_seconds: i64, grace_seconds: i64,
) -> Result<i64> {
	if lease_seconds <= 0 || grace_seconds <= 0 || grace_seconds > lease_seconds {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	let deadline:Option<i64>=tx.query_row("SELECT hard_deadline_at FROM jobs WHERE id=?1 AND repo_id=?3 AND campaign_id IS NOT NULL AND state='leased' AND typeof(lease_expires_at)='integer' AND lease_expires_at>=?2",params![job,now,repo],|r|r.get(0)).optional()?.ok_or(Error::Conflict(Conflict::JobState))?;
	let until = now
		.checked_add(lease_seconds)
		.zip(deadline.and_then(|at| at.checked_add(grace_seconds)))
		.map(|(lease, hard)| lease.min(hard))
		.filter(|until| *until > now)
		.ok_or(Error::Conflict(Conflict::JobState))?;
	changed(
		tx.execute(
			"UPDATE jobs SET lease_expires_at=?2 WHERE id=?1 AND repo_id=?3 AND state='leased'",
			params![job, until, repo],
		)?,
		Conflict::JobState,
	)?;
	Ok(until)
}
