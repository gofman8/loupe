//! Monotonic admission accounting in the caller's creation/first-lease transaction.
//! No helper here enqueues a speculative child or selects from a second queue.
//! Public callers supply repository authority, never a SQL connection.
//! ```compile_fail,E0308
//! use loupe_storage::admission::{charge, WorkClass};
//! fn raw(conn: &rusqlite::Connection) {
//!     let _ = charge(conn, 1, WorkClass::Survey, 0);
//! }
//! ```
use loupe_core::{JobKind, JobState};
use rusqlite::{params, Connection, OptionalExtension};

use crate::admission_policy::CampaignPolicyV2;
use crate::review::{parsed, string_enum};
use crate::scheduler::Band;
use crate::scope::RepoScope;
use crate::{campaigns, Conflict, Entity, Error, Result};

string_enum!(Pool { General => "general", Urgent => "urgent", Verification => "verification" });

// debug-ok: admission choices and counters contain only closed variants and integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkClass {
	Preparation,
	Survey,
	Drilldown,
	UrgentDrilldown,
	Verification,
	UrgentVerification,
}

impl WorkClass {
	fn pools(self) -> &'static [Pool] {
		match self {
			Self::Preparation | Self::Survey | Self::Drilldown => &[Pool::General],
			Self::UrgentDrilldown => &[Pool::General, Pool::Urgent],
			Self::Verification => &[Pool::General, Pool::Verification],
			Self::UrgentVerification => &[Pool::General, Pool::Verification, Pool::Urgent],
		}
	}
}

// debug-ok: admission choices and counters contain only closed variants and integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Spending {
	pub general: i64,
	pub urgent: i64,
	pub verification: i64,
}

impl Spending {
	pub fn total(self) -> Result<i64> {
		self.general
			.checked_add(self.urgent)
			.and_then(|sum| sum.checked_add(self.verification))
			.filter(|_| self.general >= 0 && self.urgent >= 0 && self.verification >= 0)
			.ok_or(Error::Conflict(Conflict::CampaignPolicy))
	}
}

// debug-ok: admission choices and counters contain only closed variants and integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityRefusal {
	CampaignBudget,
	ProtectedCapacity,
}

// debug-ok: admission choices and counters contain only closed variants and integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
	Pool(Pool),
	Refused(CapacityRefusal),
}

pub fn choose_pool(
	policy: &CampaignPolicyV2, spent: Spending, class: WorkClass,
) -> Result<Selection> {
	let general = policy.general_capacity()?;
	let total = spent.total()?;
	if spent.general > general
		|| spent.urgent > policy.campaign_urgent_reserve
		|| spent.verification > policy.campaign_verification_reserve
	{
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	if total == policy.campaign_max_jobs {
		return Ok(Selection::Refused(CapacityRefusal::CampaignBudget));
	}
	for pool in class.pools() {
		let available = match pool {
			Pool::General => spent.general < general,
			Pool::Urgent => spent.urgent < policy.campaign_urgent_reserve,
			Pool::Verification => spent.verification < policy.campaign_verification_reserve,
		};
		if available {
			return Ok(Selection::Pool(*pool));
		}
	}
	Ok(Selection::Refused(CapacityRefusal::ProtectedCapacity))
}

/// Read spending for a campaign in this repository only.
pub fn get_spending(scope: &RepoScope<'_>, campaign: i64) -> Result<Option<Spending>> {
	get_spending_raw(scope.conn, scope.repo_id, campaign)
}
pub(crate) fn get_spending_raw(
	conn: &Connection, repo_id: i64, campaign: i64,
) -> Result<Option<Spending>> {
	Ok(conn
		.query_row(
			"SELECT s.general_spent,s.urgent_spent,s.verification_spent
		 FROM campaign_admission_spending s JOIN review_campaigns c ON c.campaign_id=s.campaign_id
		 WHERE s.campaign_id=?1 AND s.policy_version=2 AND c.repo_id=?2",
			params![campaign, repo_id],
			|row| {
				Ok(Spending {
					general: row.get(0)?,
					urgent: row.get(1)?,
					verification: row.get(2)?,
				})
			},
		)
		.optional()?)
}

/// Validate exact frozen bytes/digest, never reinterpret them through live defaults.
pub fn load_policy(scope: &RepoScope<'_>, campaign: i64) -> Result<CampaignPolicyV2> {
	load_policy_raw(scope.conn, scope.repo_id, campaign)
}
pub(crate) fn load_policy_raw(
	conn: &Connection, repo_id: i64, campaign: i64,
) -> Result<CampaignPolicyV2> {
	conn.query_row(
		"SELECT effective_policy,effective_policy_digest FROM review_campaigns
		 WHERE campaign_id=?1 AND repo_id=?2",
		params![campaign, repo_id],
		|row| crate::ingress::admission_policy::policy(row, 0, 1),
	)
	.optional()?
	.ok_or(Error::NotFound(Entity::Campaign, campaign))
}

fn campaign_state(
	conn: &Connection, repo_id: i64, campaign: i64,
) -> Result<(campaigns::State, Option<i64>)> {
	conn.query_row(
		"SELECT state,deadline_at FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
		params![campaign, repo_id],
		|row| Ok((parsed(row, 0)?, row.get(1)?)),
	)
	.optional()?
	.ok_or(Error::NotFound(Entity::Campaign, campaign))
}

/// Initialize before creating a new campaign's first preparation job. Never
/// infer old charges from surviving rows or retrofit version-1 campaigns.
pub fn initialize(scope: &RepoScope<'_>, campaign_id: i64) -> Result<Spending> {
	scope.require_operator()?;
	initialize_raw(scope.conn, scope.repo_id, campaign_id)
}
pub(crate) fn initialize_raw(tx: &Connection, repo_id: i64, campaign_id: i64) -> Result<Spending> {
	let (state, _) = campaign_state(tx, repo_id, campaign_id)?;
	let policy = load_policy_raw(tx, repo_id, campaign_id)?;
	if let Some(spent) = get_spending_raw(tx, repo_id, campaign_id)? {
		choose_pool(&policy, spent, WorkClass::Preparation)?;
		return Ok(spent);
	}
	let nonempty: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1)",
		[campaign_id],
		|row| row.get(0),
	)?;
	if nonempty || state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	tx.execute(
		"INSERT INTO campaign_admission_spending(campaign_id,policy_version) VALUES(?1,2)",
		[campaign_id],
	)?;
	Ok(Spending::default())
}

// debug-ok: admission choices and counters contain only closed variants and integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charged {
	Fresh(Pool),
	Replayed(Pool),
	Refused(CapacityRefusal),
}

/// The selector creates and leases a chosen child before calling this helper
/// in that same transaction. Execution retry returns its original charge.
pub fn charge(scope: &RepoScope<'_>, job_id: i64, class: WorkClass, now: i64) -> Result<Charged> {
	scope.require_operator()?;
	charge_raw(scope.conn, scope.repo_id, job_id, class, now)
}
pub(crate) fn charge_raw(
	tx: &Connection, repo_id: i64, job_id: i64, class: WorkClass, now: i64,
) -> Result<Charged> {
	let row = tx
		.query_row(
			"SELECT campaign_id,kind,scheduling_band,state,attempts,continuation_of_job_id,
		 worker_id IS NOT NULL AND typeof(job_capability_hash)='blob' AND length(job_capability_hash)=32
		 AND typeof(lease_expires_at)='integer' AND lease_expires_at>=?2
		 FROM jobs WHERE id=?1 AND repo_id=?3",
			params![job_id, now, repo_id],
			|row| {
				Ok((
					row.get::<_, Option<i64>>(0)?,
					crate::ingress::job_kind(row, 1)?,
					crate::review::optional::<Band>(row, 2)?,
					parsed::<JobState>(row, 3)?,
					row.get::<_, i64>(4)?,
					row.get::<_, Option<i64>>(5)?,
					row.get::<_, Option<bool>>(6)?.unwrap_or(false),
				))
			},
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Job, job_id))?;
	let (campaign_id, kind, band, state, attempts, continuation, live_lease) = row;
	let campaign_id = campaign_id.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let (campaign_state, deadline) = campaign_state(tx, repo_id, campaign_id)?;
	let policy = load_policy_raw(tx, repo_id, campaign_id)?;
	let compatible = match class {
		WorkClass::Preparation | WorkClass::Survey => kind == JobKind::Survey,
		WorkClass::Drilldown => kind == JobKind::Drilldown && band != Some(Band::Urgent),
		WorkClass::UrgentDrilldown => kind == JobKind::Drilldown && band == Some(Band::Urgent),
		WorkClass::Verification => kind == JobKind::Verify && band != Some(Band::Urgent),
		WorkClass::UrgentVerification => kind == JobKind::Verify && band == Some(Band::Urgent),
	};
	if !compatible || band.is_none() {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let spent = get_spending_raw(tx, repo_id, campaign_id)?
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	choose_pool(&policy, spent, class)?;
	let existing: Option<Pool> = tx
		.query_row(
			"SELECT pool FROM job_admission_charges WHERE job_id=?1 AND campaign_id=?2",
			params![job_id, campaign_id],
			|row| parsed(row, 0),
		)
		.optional()?;
	if let Some(pool) = existing {
		if !class.pools().contains(&pool) {
			return Err(Error::Conflict(Conflict::CampaignPolicy));
		}
		return Ok(Charged::Replayed(pool));
	}
	if campaign_state != campaigns::State::Active
		|| deadline.is_some_and(|deadline| deadline <= now)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let valid_state = if class == WorkClass::Preparation {
		state == JobState::Queued
			&& attempts == 0
			&& continuation.is_none()
			&& spent.total()? == 0
			&& tx.query_row(
				"SELECT COUNT(*)=1 FROM jobs WHERE campaign_id=?1",
				[campaign_id],
				|row| row.get::<_, bool>(0),
			)?
	} else {
		state == JobState::Leased && attempts == 1 && live_lease
	};
	if !valid_state {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let pool = match choose_pool(&policy, spent, class)? {
		Selection::Pool(pool) => pool,
		Selection::Refused(reason) => return Ok(Charged::Refused(reason)),
	};
	let column = match pool {
		Pool::General => "general_spent",
		Pool::Urgent => "urgent_spent",
		Pool::Verification => "verification_spent",
	};
	tx.execute(
		&format!("UPDATE campaign_admission_spending SET {column}={column}+1 WHERE campaign_id=?1"),
		[campaign_id],
	)?;
	tx.execute(
		"INSERT INTO job_admission_charges(job_id,campaign_id,pool) VALUES(?1,?2,?3)",
		params![job_id, campaign_id, pool.as_str()],
	)?;
	Ok(Charged::Fresh(pool))
}

#[cfg(test)]
mod tests;
