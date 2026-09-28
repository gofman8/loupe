//! Initial preparation is the sole live admission producer before first lease.
//! Callers retain transaction ownership; this module never commits or leases.
use loupe_core::WORKFLOW_CONTRACT_VERSION;
use loupe_provenance::Db as DbSource;
type JobKind = loupe_core::JobKind<DbSource>;
use rusqlite::{params, Connection, OptionalExtension};

use crate::admission::{self, Charged, WorkClass};
use crate::admission_policy::CampaignPolicyV2;
use crate::scheduler::Band;
use crate::{campaigns, review_intents, Conflict, Entity, Error, Result};

/// The bounded projection routes rejection only. Acceptance still reads and
/// validates original SQL bytes, canonical form and digest in the same lock.
pub(super) fn frozen_policy(
	tx: &Connection, campaign: &campaigns::Campaign,
) -> Result<CampaignPolicyV2> {
	let version = serde_json::from_str::<serde_json::Value>(campaign.effective_policy.expose())
		.map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?["version"]
		.as_u64();
	if version != Some(2) {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	admission::load_policy_raw(tx, campaign.repo_id, campaign.campaign_id)
}
pub(super) struct NewJob<'a> {
	pub(super) kind: &'a JobKind,
	pub(super) band: Band,
	pub(super) score: i64,
	pub(super) parent: Option<i64>,
	pub(super) continuation: Option<i64>,
	pub(super) lead: Option<i64>,
	pub(super) finding: Option<i64>,
	pub(super) survey_recipe: &'a str,
}

pub(super) fn insert_job(
	tx: &Connection, campaign: &campaigns::Campaign, policy: &CampaignPolicyV2, new: &NewJob<'_>,
	now: i64,
) -> Result<i64> {
	let NewJob { kind, band, score, parent, continuation, lead, finding, survey_recipe } = *new;
	let recipe = if *kind == JobKind::Survey {
		serde_json::json!({"version":1,"phase":"survey","recipe":survey_recipe,"assignment_key":"ordinary"})
	} else {
		serde_json::json!({"version":1,"phase":kind.as_str()})
	};
	let recipe = recipe.to_string(); // Fixed host keys and closed values only.
	let budget = policy.phase(kind)?.token_budget;
	tx.execute("INSERT INTO jobs(repo_id,kind,state,enqueued_at,campaign_id,generation_id,parent_job_id,continuation_of_job_id,assigned_lead_id,target_finding_id,scheduling_band,effective_priority,eligible_at,token_budget,recipe,workflow_contract_version) VALUES(?1,?2,'queued',?3,?4,?5,?6,?7,?8,?9,?10,?11,?3,?12,?13,?14)",params![campaign.repo_id,kind.as_str(),now,campaign.campaign_id,campaign.generation_id,parent,continuation,lead,finding,band.as_str(),score,budget.map(|n|n as i64),recipe,WORKFLOW_CONTRACT_VERSION])?;
	Ok(tx.last_insert_rowid())
}

/// Initial preparation is the sole job admitted before its first lease. This
/// function is also uncommitted; errors require rollback of initialization and
/// insertion. Historical policies are never upgraded or retroactively charged.
pub(crate) fn create_preparation(
	scope: &crate::scope::RepoScope<'_>, campaign_id: i64, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	let campaign = campaigns::get_scoped_raw(tx, scope.repo_id, campaign_id)?
		.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let policy = frozen_policy(tx, &campaign)?;
	if now < 0
		|| (campaign.generation_id.is_some()
			&& !loupe_core::inventory_manifest::is_git_oid(campaign.target_commit_sha.expose()))
		|| campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|d| d <= now)
		|| !matches!(campaign.recipe, campaigns::Recipe::Bootstrap | campaigns::Recipe::Incremental)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let recipe = if let Some(generation) = campaign.generation_id {
		let context:Option<(String,Option<i64>)>=tx.query_row("SELECT state,predecessor_generation_id FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND generation_commit_sha=?3 AND workflow_contract_version=?4",params![generation,campaign.repo_id,campaign.target_commit_sha.expose(),WORKFLOW_CONTRACT_VERSION],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
		match context {
			Some((state, _)) if state == "active" => {
				if campaign.recipe == campaigns::Recipe::Bootstrap {
					"coverage"
				} else {
					"incremental"
				}
			},
			Some((state, None))
				if state == "building" && campaign.recipe == campaigns::Recipe::Bootstrap =>
			{
				"bootstrap"
			},
			_ => return Err(Error::Conflict(Conflict::GenerationState)),
		}
	} else {
		campaign.recipe.as_str()
	};
	admission::initialize_raw(tx, scope.repo_id, campaign_id)?;
	let id = insert_job(
		tx,
		&campaign,
		&policy,
		&NewJob {
			kind: &JobKind::Survey,
			band: Band::Normal,
			score: 0,
			parent: None,
			continuation: None,
			lead: None,
			finding: None,
			survey_recipe: recipe,
		},
		now,
	)?;
	if campaign.generation_id.is_some() && recipe != "bootstrap" {
		// Reuse the already published seal/profile; never create or republish it.
		review_intents::job_context(tx, scope.repo_id, id)?;
	}
	if !matches!(
		admission::charge_raw(tx, scope.repo_id, id, WorkClass::Preparation, now)?,
		Charged::Fresh(_)
	) {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	Ok(id)
}
