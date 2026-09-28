//! Transactional campaign orchestration. Worker checkout pins the commit.
use std::collections::BTreeMap;

use loupe_core::text::policy::{Reason, RevisionText};
use loupe_core::text::BoundedText;
pub use loupe_core::ReviewIntent as KindHint;
use loupe_core::{FollowUpTrigger, JobKind, JobState, PendingFollowUp, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::Source;
use rusqlite::{params, OptionalExtension};

use crate::admission::{self, CapacityRefusal, Selection, Spending, WorkClass};
use crate::admission_claim::{CallbackError, RecipeDecision, RecipeInput};
use crate::admission_policy::CampaignPolicyV2;
use crate::admission_quarantine::Cursor;
use crate::review_authority::{Context, Phase};
use crate::review_intents::BlockReason;
use crate::scope::RepoScope;
use crate::{
	campaign_work, campaigns, generations, jobs, scheduler, transaction, Conflict, Db, Entity,
	Error, Ownership, Result,
};

// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug)]
pub enum RequestedRef<'a, S: Source> {
	Pinned(&'a BoundedText<RevisionText, S>),
	Branch(&'a BoundedText<RevisionText, S>),
}
impl<S: Source> Clone for RequestedRef<'_, S> {
	fn clone(&self) -> Self {
		*self
	}
}
impl<S: Source> Copy for RequestedRef<'_, S> {}

impl<'a, S: Source> RequestedRef<'a, S> {
	fn value(&self) -> &'a BoundedText<RevisionText, S> {
		match self {
			Self::Pinned(value) | Self::Branch(value) => value,
		}
	}
}

pub struct OpenCampaign<'a, S: Source> {
	pub trigger: campaigns::Trigger,
	pub requested_ref: RequestedRef<'a, S>,
	pub base_sha: Option<&'a BoundedText<RevisionText, S>>,
	pub kind_hint: KindHint,
}

// debug-ok: opening outcomes contain only closed states and integer campaign/job IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
	Created { campaign_id: i64, job_id: i64 },
	Coalesced { campaign_id: i64 },
	Pending { campaign_id: i64 },
	Deferred { campaign_id: i64 },
}

fn get(scope: &RepoScope<'_>, id: i64) -> Result<campaigns::Campaign> {
	campaigns::get(scope, id)?.ok_or(Error::NotFound(Entity::Campaign, id))
}

pub fn open<S: Source>(
	scope: &RepoScope<'_>, new: &OpenCampaign<'_, S>, policy: &CampaignPolicyV2, now: i64,
) -> Result<Opened> {
	scope.require_operator()?;
	policy.validate()?;
	let tx = scope.conn;
	let active: Option<i64> = tx
		.query_row(
			"SELECT campaign_id FROM review_campaigns WHERE repo_id=?1 AND state='active'",
			[scope.repo_id],
			|r| r.get(0),
		)
		.optional()?;
	if let Some(campaign_id) = active {
		let campaign = get(scope, campaign_id)?;
		let Some(generation_id) = campaign.generation_id else {
			return Ok(Opened::Pending { campaign_id });
		};
		let generation = generations::get(scope, generation_id)?
			.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
		let trigger = match new.trigger {
			campaigns::Trigger::Manual => FollowUpTrigger::Manual,
			campaigns::Trigger::Scheduled => FollowUpTrigger::Scheduled,
			campaigns::Trigger::CompatScanApi => FollowUpTrigger::CompatScanApi,
			campaigns::Trigger::Reconciliation => FollowUpTrigger::Reconciliation,
			campaigns::Trigger::Operator => FollowUpTrigger::Operator,
		};
		let pending = PendingFollowUp::new(
			generation.pending_follow_up.as_ref(),
			new.requested_ref.value(),
			trigger,
			new.kind_hint,
			now,
		)?;
		generations::coalesce_follow_up(scope, generation_id, &pending)?;
		return Ok(Opened::Coalesced { campaign_id });
	}
	let baseline: Option<loupe_core::text::BoundedText<RevisionText,loupe_provenance::Db>> = tx.query_row(
		"SELECT generation_commit_sha FROM review_generations WHERE repo_id=?1 AND state='active'",
		[scope.repo_id], |r| crate::ingress::revision(r,0),
	).optional()?;
	let known_successor = if let RequestedRef::Pinned(sha) = new.requested_ref {
		if !is_commit_sha(sha.expose()) {
			return Err(loupe_core::text::Error::new(
				"commit_sha",
				loupe_core::text::Rule::Identifier,
			)
			.into());
		}
		baseline.as_ref().is_some_and(|old| old.expose() != sha.expose())
	} else {
		false
	};
	let initial = if baseline.is_none() {
		campaigns::Recipe::Bootstrap
	} else if new.kind_hint == KindHint::FullReview {
		campaigns::Recipe::Reconciliation
	} else {
		campaigns::Recipe::Incremental
	};
	let snapshot = policy;
	let deadline = now
		.checked_add(policy.campaign_deadline_seconds)
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let campaign_id = campaigns::create(
		scope,
		&campaigns::NewCampaign {
			recipe: initial,
			trigger: new.trigger,
			requested_base_sha: new.base_sha,
			target_commit_sha: new.requested_ref.value(),
			generation_id: None,
			effective_policy: campaigns::CampaignPolicyInput::<S>::ResolvedV2(snapshot),
			deadline_at: Some(deadline),
			root_campaign_id: None,
			continuation_of_campaign_id: None,
		},
		now,
	)?;
	if initial == campaigns::Recipe::Reconciliation || known_successor {
		let summary = campaigns::summarize(scope, campaign_id)?;
		campaigns::finish_scheduled(
			scope,
			campaign_id,
			&summary,
			campaigns::FinishedReason::Unsupported,
			now,
		)?;
		return Ok(Opened::Deferred { campaign_id });
	}
	let job_id = crate::admission_preparation::create_preparation(scope, campaign_id, now)?;
	if let RequestedRef::Pinned(sha) = new.requested_ref {
		pin(scope, campaign_id, job_id, sha, now)?;
	}
	Ok(Opened::Created { campaign_id, job_id })
}

/// A complete, lowercase Git object id (SHA-1 or SHA-256). The pinned commit
/// comes from the worker's checkout checkpoint, so it is boundary input and
/// nothing else may reach `target_commit_sha` or generation selection.
fn is_commit_sha(sha: &str) -> bool {
	matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn pin<S: Source>(
	scope: &RepoScope<'_>, campaign_id: i64, job_id: i64, sha: &BoundedText<RevisionText, S>,
	now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	if !is_commit_sha(sha.expose()) {
		return Err(
			loupe_core::text::Error::new("commit_sha", loupe_core::text::Rule::Identifier).into()
		);
	}
	let campaign = get(scope, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let job = jobs::get(scope, job_id)?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if job.campaign_id != Some(campaign_id)
		|| job.repo_id != campaign.repo_id
		|| job.kind != JobKind::Survey
		|| !matches!(job.state, JobState::Queued | JobState::Leased)
	{
		return Err(Error::Ownership(Ownership::CampaignJob));
	}
	if let Some(generation) = campaign.generation_id {
		return if campaign.target_commit_sha.expose() == sha.expose() {
			Ok(generation)
		} else {
			Err(Error::Conflict(Conflict::CampaignPinned))
		};
	}
	let generations = generations::list_for_repo(scope)?;
	let active = generations.iter().find(|g| g.state == generations::State::Active);
	let existing = active.and_then(|g| {
		if g.commit_sha.expose() == sha.expose()
			&& g.workflow_contract_version == WORKFLOW_CONTRACT_VERSION
		{
			Some(g.generation_id)
		} else if g.commit_sha.expose() != sha.expose() {
			generations
				.iter()
				.find(|s| {
					s.state == generations::State::Building
						&& s.commit_sha.expose() == sha.expose()
						&& s.workflow_contract_version == WORKFLOW_CONTRACT_VERSION
						&& s.predecessor_generation_id == Some(g.generation_id)
				})
				.map(|s| s.generation_id)
		} else {
			None
		}
	});
	let generation_id = if let Some(existing) = existing {
		existing
	} else {
		if active.is_none() {
			for g in generations.iter().filter(|g| g.state == generations::State::Building) {
				generations::abandon_superseded_bootstrap(scope, g.generation_id, now)?;
			}
		}
		generations::create(
			scope,
			&generations::NewGeneration {
				predecessor_generation_id: active.map(|g| g.generation_id),
				commit_sha: sha,
				workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
			},
			now,
		)?
	};
	tx.execute(
		"UPDATE review_campaigns SET target_commit_sha=?2,generation_id=?3 WHERE campaign_id=?1 AND repo_id=?4",
		params![campaign_id, sha.expose(), generation_id, scope.repo_id],
	)?;
	tx.execute(
		"UPDATE jobs SET generation_id=?2 WHERE id=?1 AND repo_id=?3",
		params![job_id, generation_id, scope.repo_id],
	)?;
	if job.state == JobState::Queued && active.is_some_and(|g| g.generation_id == generation_id) {
		crate::review_intents::job_context(tx, scope.repo_id, job_id)?;
	}
	Ok(generation_id)
}

/// Bootstrap finalization must call this inside its checkpoint transaction.
pub fn activate_generation(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<()> {
	scope.require_operator()?;
	let campaign = get(scope, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let id = campaign.generation_id.ok_or(Error::Conflict(Conflict::GenerationState))?;
	let generation = generations::get(scope, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	if generation.predecessor_generation_id.is_some() {
		return Err(Error::Conflict(Conflict::GenerationPredecessor));
	}
	if generation.state != generations::State::Building
		|| generation.generated_profile.is_none()
		|| generation.inventory_digest.is_none()
	{
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	generations::activate(scope, id, now)
}

/// Compatibility hook. Ordinary work is materialized only by its winning claim.
pub fn replenish(scope: &RepoScope<'_>, campaign_id: i64, _now: i64) -> Result<Option<i64>> {
	scope.require_operator()?;
	let exists: bool = scope.conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2)",
		params![campaign_id, scope.repo_id],
		|r| r.get(0),
	)?;
	if !exists {
		return Err(Error::NotFound(Entity::Campaign, campaign_id));
	}
	Ok(None)
}

pub fn cancel<S: Source>(
	scope: &RepoScope<'_>, campaign_id: i64, reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	// Metadata existence only: cancellation must preserve even malformed evidence.
	let exists: bool = scope.conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2)",
		params![campaign_id, scope.repo_id],
		|r| r.get(0),
	)?;
	if !exists {
		return Err(Error::NotFound(Entity::Campaign, campaign_id));
	}
	scheduler::cancel_queued_children(scope, campaign_id, now, reason)?;
	campaign_work::block_all(
		scope.conn,
		scope.repo_id,
		campaign_id,
		BlockReason::CampaignCancelled,
		now,
	)?;
	campaigns::cancel(scope, campaign_id, reason, now)
}

// debug-ok: finish reasons are closed host scheduling outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
	Completed,
	DeadlineReached,
}

// debug-ok: the tick report contains only outcome counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
	pub enqueued: usize,
	pub completed: usize,
	pub deadline_reached: usize,
	pub budget_exhausted: usize,
	/// A failed campaign transaction is rolled back; other campaigns proceed.
	pub failed: usize,
}

#[derive(Default)]
struct Progress {
	finish: Option<Finish>,
	budget_exhausted: bool,
}

/// A bounded one-shot attempt. Large campaigns require retained maintenance;
/// an incomplete scan cannot permit normal completion.
pub fn try_finish(
	scope: &RepoScope<'_>, campaign_id: i64, now: i64,
	mut policy: impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<Error>>,
) -> Result<Option<Finish>> {
	scope.require_operator()?;
	Ok(advance_checked(scope, campaign_id, now, None, &mut policy)?.0.finish)
}

/// Process-local scan progress, not persisted coverage or admission authority.
/// The background owner retains this across ticks; restart safely rescans.
#[derive(Default)]
pub struct Maintenance {
	identity: Option<std::sync::Arc<crate::db::DbIdentity>>,
	cursors: BTreeMap<(i64, i64), Cursor>,
}
impl Maintenance {
	fn bind(&mut self, db: &Db) {
		if self
			.identity
			.as_ref()
			.is_none_or(|identity| !std::sync::Arc::ptr_eq(identity, &db.identity))
		{
			self.cursors.clear();
			self.identity = Some(db.identity.clone());
		}
	}
}

fn advance_checked(
	scope: &RepoScope<'_>, campaign_id: i64, now: i64, cursor: Option<Cursor>,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<Error>>,
) -> Result<(Progress, Option<Cursor>)> {
	let (active, deadline): (bool, Option<i64>) = scope.conn.query_row(
		"SELECT state='active',deadline_at FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
		params![campaign_id, scope.repo_id], |row| Ok((row.get(0)?, row.get(1)?)),
	).optional()?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	// Identity-only control must not depend on a domain-integrity walk.
	if !active || deadline.is_some_and(|at| at <= now) {
		return Ok((advance(scope, campaign_id, now, false)?, None));
	}
	let scan = crate::admission_claim::validation::maintain_campaign(
		scope.conn,
		(scope.repo_id, campaign_id),
		now,
		cursor,
		256,
		32,
		policy,
	)?;
	Ok((advance(scope, campaign_id, now, scan.scan_complete)?, scan.next))
}

fn frozen_budget(scope: &RepoScope<'_>, campaign: i64) -> Result<(CampaignPolicyV2, Spending)> {
	let policy = admission::load_policy(scope, campaign)?;
	let spent = admission::get_spending(scope, campaign)?
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	admission::choose_pool(&policy, spent, WorkClass::Survey)?;
	Ok((policy, spent))
}
fn advance(
	scope: &RepoScope<'_>, campaign_id: i64, now: i64, scan_complete: bool,
) -> Result<Progress> {
	let tx = scope.conn;
	let repo = scope.repo_id;
	let (state,recipe,deadline): (campaigns::State,campaigns::Recipe,Option<i64>) = tx.query_row(
		"SELECT state,recipe,deadline_at FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
		params![campaign_id,repo], |r| Ok((crate::review::parsed(r,0)?,crate::review::parsed(r,1)?,r.get(2)?)),
	).optional()?.ok_or(Error::NotFound(Entity::Campaign,campaign_id))?;
	let mut progress = Progress::default();
	if state != campaigns::State::Active {
		return Ok(progress);
	}
	let expired = deadline.is_some_and(|at| at <= now);
	let mut reason = if expired {
		Some(BlockReason::CampaignDeadline)
	} else if !matches!(recipe, campaigns::Recipe::Bootstrap | campaigns::Recipe::Incremental) {
		Some(BlockReason::UnsupportedRecipe)
	} else {
		None
	};
	let mut budget = None;
	if reason.is_none() {
		match frozen_budget(scope, campaign_id) {
			Ok(value) => budget = Some(value),
			Err(
				Error::Conflict(Conflict::CampaignPolicy)
				| Error::Sqlite(
					rusqlite::Error::InvalidColumnType(..)
					| rusqlite::Error::FromSqlConversionFailure(..),
				),
			) => reason = Some(BlockReason::CompatibilityPolicy),
			Err(error) => return Err(error),
		}
	}
	if let Some(reason) = reason {
		scheduler::cancel_queued_for_reason(scope, campaign_id, now, reason)?;
		campaign_work::block_all(tx, repo, campaign_id, reason, now)?;
	}
	if reason.is_none() && !scan_complete {
		return Ok(progress);
	}
	let busy: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND repo_id=?2 AND state IN('queued','leased'))",params![campaign_id,repo],|r|r.get(0))?;
	if busy {
		return Ok(progress);
	}
	let mut terminal_reason = reason;
	if let Some((policy, spent)) = budget {
		let mut fundable = false;
		for group in campaign_work::pending(tx, repo, campaign_id, deadline)? {
			let reason = if !group.before_deadline {
				Some(BlockReason::CampaignDeadline)
			} else {
				match admission::choose_pool(&policy, spent, group.work_class())? {
					Selection::Pool(_) => {
						fundable = true;
						None
					},
					Selection::Refused(CapacityRefusal::CampaignBudget) => {
						progress.budget_exhausted = true;
						Some(BlockReason::CampaignBudget)
					},
					Selection::Refused(CapacityRefusal::ProtectedCapacity) => {
						Some(BlockReason::ProtectedCapacity)
					},
				}
			};
			if let Some(reason) = reason {
				campaign_work::block_pending(tx, repo, campaign_id, group, deadline, reason, now)?;
				terminal_reason.get_or_insert(reason);
			}
		}
		if fundable {
			return Ok(progress);
		}
	}
	campaign_work::block_unexplained(tx, repo, campaign_id, now)?;
	let summary = campaigns::summarize(scope, campaign_id)?;
	let (finish, reason) = if expired {
		(Finish::DeadlineReached, campaigns::FinishedReason::Deadline)
	} else {
		let reason = match terminal_reason {
			Some(reason) => campaigns::FinishedReason::Blocked(reason),
			None if summary.coverage == generations::Coverage::Complete
				&& !campaign_work::has_unfinished(tx, repo, campaign_id)? =>
			{
				campaigns::FinishedReason::Completed
			},
			None => campaigns::FinishedReason::Partial,
		};
		(Finish::Completed, reason)
	};
	campaigns::finish_scheduled(scope, campaign_id, &summary, reason, now)?;
	progress.finish = Some(finish);
	Ok(progress)
}

/// No active campaigns means no write transaction. Each campaign otherwise
/// advances independently, so a malformed row cannot stall another repository.
pub fn tick(
	db: &Db, now: i64, maintenance: &mut Maintenance,
	mut policy: impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<Error>>,
) -> Result<TickReport> {
	maintenance.bind(db);
	let active: Vec<(i64, i64)> = db.with_conn(|c| {
		Ok(c.prepare(
			"SELECT campaign_id,repo_id FROM review_campaigns WHERE state='active' ORDER BY campaign_id",
		)?
		.query_map([], |r| Ok((r.get(0)?,r.get(1)?)))?
		.collect::<rusqlite::Result<_>>()?)
	})?;
	maintenance
		.cursors
		.retain(|(repo, campaign), _| active.binary_search(&(*campaign, *repo)).is_ok());
	let mut report = TickReport::default();
	for (campaign_id, repo_id) in active {
		let key = (repo_id, campaign_id);
		let cursor = maintenance.cursors.get(&key).copied();
		let progress = db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let committed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
				let scope = RepoScope {
					conn: tx,
					repo_id,
					identity: &db.identity,
					operator: true,
					committed: &committed,
				};
				advance_checked(&scope, campaign_id, now, cursor, &mut policy)
			})
		});
		let (progress, next) = match progress {
			Ok(progress) => progress,
			Err(_) => {
				report.failed += 1;
				continue;
			},
		};
		// Only successful SQL commit publishes process-local scan progress.
		if let Some(next) = next.filter(|_| progress.finish.is_none()) {
			maintenance.cursors.insert(key, next);
		} else {
			maintenance.cursors.remove(&key);
		}
		match progress.finish {
			Some(Finish::Completed) => report.completed += 1,
			Some(Finish::DeadlineReached) => report.deadline_reached += 1,
			None => {},
		}
		if progress.budget_exhausted {
			report.budget_exhausted += 1;
			// The finish committed above; subsequent ticks cannot log this again.
		}
	}
	Ok(report)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn scope_safety_invalid_policy_cannot_hide_behind_an_active_campaign() {
		let db = crate::review_tests::fixture();
		let reference = crate::test_support::text("main").unwrap();
		let invalid = CampaignPolicyV2 { survey_units_per_job: 33, ..CampaignPolicyV2::default() };
		let result = crate::scope::with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			crate::scope::OperatorTarget::Repository(1),
			|scope| {
				open(
					scope,
					&OpenCampaign {
						trigger: campaigns::Trigger::Manual,
						requested_ref: RequestedRef::Branch(&reference),
						base_sha: None,
						kind_hint: KindHint::Incremental,
					},
					&invalid,
					1,
				)
			},
		);
		assert!(
			matches!(result, Err(Error::Conflict(Conflict::CampaignPolicy))),
			"public campaign open must validate policy even on the coalescing path"
		);
		db.with_conn(|conn| {
			let pending: Option<String> = conn.query_row(
				"SELECT pending_follow_up FROM review_generations WHERE generation_id=11",
				[],
				|row| row.get(0),
			)?;
			assert!(pending.is_none(), "invalid policy must not mutate the active generation");
			Ok(())
		})
		.unwrap();
	}

	#[test]
	fn stored_policy_sql_bytes_and_digest_match_the_actual_typed_readback() {
		for policy in [
			CampaignPolicyV2::default(),
			CampaignPolicyV2 {
				campaign_max_jobs: 19,
				campaign_urgent_reserve: 3,
				survey_units_per_job: 7,
				max_attempts: 5,
				survey_token_budget: Some(1000),
				..CampaignPolicyV2::default()
			},
		] {
			let db = crate::review_tests::fixture();
			db.with_conn(|conn| {
				conn.execute_batch("DELETE FROM jobs; DELETE FROM review_campaigns;")?;
				Ok(())
			})
			.unwrap();
			let reference = crate::test_support::text("main").unwrap();
			crate::scope::with_operator_repository(
				&db,
				&crate::test_support::operator_ingress(),
				crate::scope::OperatorTarget::Repository(1),
				|scope| {
					let opened = open(
						scope,
						&OpenCampaign {
							trigger: campaigns::Trigger::Manual,
							requested_ref: RequestedRef::Branch(&reference),
							base_sha: None,
							kind_hint: KindHint::Incremental,
						},
						&policy,
						0,
					)?;
					let Opened::Created { campaign_id, .. } = opened else {
						panic!("new campaign")
					};
					let stored = campaigns::get(scope, campaign_id)?.unwrap().effective_policy;
					let (raw, digest): (String, Vec<u8>) = scope.conn.query_row(
						"SELECT effective_policy,effective_policy_digest FROM review_campaigns WHERE campaign_id=?1",
						[campaign_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
					assert_eq!(raw.as_bytes(), stored.canonical());
					assert_eq!(digest.as_slice(), stored.digest());
					Ok(())
				},
			)
			.unwrap();
		}
	}

	#[test]
	fn requested_ref_traits_need_only_source_and_preserve_variant_and_borrow() {
		#[allow(clippy::clone_on_copy)] // Exercise Clone independently to check its generic bounds.
		fn cloned<'a, S: Source>(value: &RequestedRef<'a, S>) -> RequestedRef<'a, S> {
			Clone::clone(value)
		}
		fn copied<'a, S: Source>(value: &RequestedRef<'a, S>) -> RequestedRef<'a, S> {
			*value
		}

		let pinned = crate::test_support::text("pinned-revision").unwrap();
		let branch = crate::test_support::text("main").unwrap();
		for original in [RequestedRef::Pinned(&pinned), RequestedRef::Branch(&branch)] {
			for copy in [cloned(&original), copied(&original)] {
				match (&original, &copy) {
					(RequestedRef::Pinned(left), RequestedRef::Pinned(right))
					| (RequestedRef::Branch(left), RequestedRef::Branch(right)) => {
						assert!(std::ptr::eq(*left, *right));
					},
					_ => panic!("requested reference clone or copy changed variant"),
				}
			}
		}
	}
}
