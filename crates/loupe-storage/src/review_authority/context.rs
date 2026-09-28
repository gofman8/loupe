//! Numeric limits and issued duplicate context remain inside phase authority.
//! ```compile_fail,E0603
//! use loupe_core::review_candidates::CandidateQuery;
//! use loupe_provenance::Worker;
//! fn raw(conn: &rusqlite::Connection, query: &CandidateQuery<Worker>) {
//!     let _ = loupe_storage::duplicate_candidates::issue(conn, 1, 1, query, 0);
//! }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::review_candidates::CandidateQuery;
//! use loupe_provenance::Agent;
//! use loupe_storage::review_authority::PhaseScope;
//! fn relabel(scope: &PhaseScope<'_, '_>, query: &CandidateQuery<Agent>) {
//!     let _ = scope.issue_candidates(query);
//! }
//! ```
use loupe_core::review_candidates::{Candidate, CandidateKind, CandidateQuery};
use loupe_provenance::{Agent, Db, Worker};
use rusqlite::params;

use super::{Access, Phase, PhaseScope};
use crate::checkpoints::Operation;
use crate::{admission, checkpoints, duplicate_candidates, Conflict, Error, Result};

// debug-ok: only closed numeric capacity values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacitySnapshot {
	pub limit: u32,
	pub remaining: u32,
}

// debug-ok: only numeric limits, counters and timestamps, without supplied content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitsSnapshot {
	pub soft_deadline_at: i64,
	pub submit_by: i64,
	pub hard_deadline_at: i64,
	pub remaining_seconds: u64,
	pub new_units: CapacitySnapshot,
	pub leads: CapacitySnapshot,
	pub siblings: CapacitySnapshot,
	pub candidate_queries: CapacitySnapshot,
	pub campaign_jobs_limit: u64,
	pub campaign_jobs_admitted: u64,
	pub campaign_general_remaining: u64,
	pub campaign_urgent_remaining: u64,
	pub campaign_verification_remaining: u64,
	pub token_budget: Option<u64>,
}

impl PhaseScope<'_, '_> {
	pub fn limits_snapshot(&self) -> Result<LimitsSnapshot> {
		if self.access != Access::Checkout {
			return Err(Error::ScopeDenied);
		}
		let conn = self.transaction.conn;
		let job = &self.job;
		let policy = admission::load_policy_raw(conn, job.repo_id, job.campaign_id)?;
		let spend = admission::get_spending_raw(conn, job.repo_id, job.campaign_id)?
			.ok_or(Error::Conflict(Conflict::CompatibilityPolicy))?;
		admission::choose_pool(&policy, spend, admission::WorkClass::Survey)?;
		let (soft, submit, hard, tokens, campaign_deadline) = conn.query_row(
			"SELECT j.soft_deadline_at,j.submit_by,j.hard_deadline_at,j.token_budget,c.deadline_at
			 FROM jobs j JOIN review_campaigns c ON c.campaign_id=j.campaign_id
			 WHERE j.id=?1 AND j.repo_id=?2 AND c.repo_id=?2 AND c.campaign_id=?3",
			params![job.id, job.repo_id, job.campaign_id],
			|row| {
				Ok((
					row.get::<_, i64>(0)?,
					row.get::<_, i64>(1)?,
					row.get::<_, i64>(2)?,
					row.get::<_, Option<i64>>(3)?,
					row.get::<_, Option<i64>>(4)?,
				))
			},
		)?;
		if soft > submit || submit > hard || tokens.is_some_and(|value| value <= 0) {
			return Err(Error::Conflict(Conflict::Limits));
		}
		let hard = campaign_deadline.map_or(hard, |deadline| deadline.min(hard));
		let submit = submit.min(hard);
		let soft = soft.min(submit);
		let capacity = |operation, limit: u32| -> Result<CapacitySnapshot> {
			let used = checkpoints::accepted_count_raw(conn, job.repo_id, job.id, operation)?;
			Ok(CapacitySnapshot { limit, remaining: (i64::from(limit) - used).max(0) as u32 })
		};
		Ok(LimitsSnapshot {
			soft_deadline_at: soft,
			submit_by: submit,
			hard_deadline_at: hard,
			remaining_seconds: hard.saturating_sub(self.transaction.now).max(0) as u64,
			new_units: capacity(
				Operation::SubmitReviewUnit,
				if job.phase == Phase::Survey { policy.max_units_per_survey } else { 0 },
			)?,
			leads: capacity(
				Operation::SubmitLead,
				if job.phase == Phase::Survey { policy.max_leads_per_survey } else { 0 },
			)?,
			siblings: capacity(
				Operation::SubmitSiblingLead,
				if job.phase == Phase::Drilldown {
					policy.max_sibling_leads_per_drilldown
				} else {
					0
				},
			)?,
			candidate_queries: capacity(
				Operation::IssueDuplicateCandidates,
				if job.phase == Phase::Verify {
					0
				} else {
					duplicate_candidates::QUERY_LIMIT as u32
				},
			)?,
			campaign_jobs_limit: policy.campaign_max_jobs as u64,
			campaign_jobs_admitted: spend.total()? as u64,
			campaign_general_remaining: (policy.general_capacity()? - spend.general) as u64,
			campaign_urgent_remaining: (policy.campaign_urgent_reserve - spend.urgent) as u64,
			campaign_verification_remaining: (policy.campaign_verification_reserve
				- spend.verification) as u64,
			token_budget: tokens.map(|limit| limit as u64),
		})
	}

	pub fn issue_candidates(
		&self, query: &CandidateQuery<Worker>,
	) -> Result<Vec<Candidate<Agent, Db>>> {
		if self.access != Access::Domain || self.job.phase == Phase::Verify {
			return Err(Error::ScopeDenied);
		}
		duplicate_candidates::issue(
			self.transaction.conn,
			self.job.id,
			self.job.repo_id,
			query,
			self.transaction.now,
		)
	}

	pub fn issued_candidate_target(&self, kind: CandidateKind, id: i64) -> Result<bool> {
		if self.access != Access::Domain || self.job.phase == Phase::Verify {
			return Ok(false);
		}
		duplicate_candidates::issued_target(
			self.transaction.conn,
			self.job.id,
			self.job.repo_id,
			kind,
			id,
		)
	}
}

#[cfg(test)]
mod tests;
