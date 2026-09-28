//! Transaction-bound review authority. Server policy chooses supported recipes;
//! storage owns identity, preparation, readiness and subject predicates.
//!
//! Scopes cannot escape, be cloned, or coexist with later reauthorization.
//! ```compile_fail
//! use loupe_storage::{Db, jobs::LeaseIdentity, review_authority::*};
//! fn escape(db: &Db, identity: LeaseIdentity<'_>) {
//!     let _ = with_phase_transaction(db, identity, || 0, |tx| {
//!         tx.authorize(Phase::Survey, Access::LeaseControl, |_| Ok(None))
//!     });
//! }
//! ```
//! ```compile_fail
//! use loupe_storage::review_authority::*;
//! fn reuse(tx: &mut PhaseTransaction<'_>) -> loupe_storage::Result<()> {
//!     let first = tx.authorize(Phase::Survey, Access::LeaseControl, |_| Ok(None))?.unwrap();
//!     let second = tx.authorize(Phase::Survey, Access::Domain, |_| Ok(None))?;
//!     let _ = first.job();
//!     Ok(())
//! }
//! ```
//! ```compile_fail
//! use loupe_storage::review_authority::PhaseScope;
//! fn sql(scope: &PhaseScope<'_, '_>) { scope.execute_batch("DELETE FROM jobs"); }
//! ```
use loupe_core::text::policy::RevisionText;
use loupe_core::text::{BoundedText, Normalization, TextPolicy, Whitespace};
use loupe_core::{JobKind, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::Db as DbSource;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{jobs, review_units, Error, Result};

mod context;
mod envelope;
mod host;
pub use context::{CapacitySnapshot, LimitsSnapshot};
pub use envelope::{AssignedUnit, ReviewPreparation};

// debug-ok: phase, purpose and policy decisions contain only closed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
	Survey,
	Drilldown,
	Verify,
}
impl Phase {
	pub fn job_kind(self) -> JobKind<DbSource> {
		match self {
			Self::Survey => JobKind::Survey,
			Self::Drilldown => JobKind::Drilldown,
			Self::Verify => JobKind::Verify,
		}
	}
}
// debug-ok: access purpose contains no caller text or capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
	LeaseControl,
	Checkout,
	PreparedHost,
	Domain,
}
// debug-ok: recipe policy decisions contain only the two supported subject modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
	Ordinary,
	Bootstrap,
}

/// Original stored recipe text. JSON/schema policy belongs to the server;
/// duplicate keys and whitespace must survive the SQL boundary unchanged.
pub struct RecipeText;
impl TextPolicy for RecipeText {
	const FIELD: &'static str = "review_recipe";
	const MAX_CHARS: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_BYTES: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = true;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
	const ALLOW_CR: bool = true;
}

/// Narrow identity facts; deliberately excludes recipes and deadline decoding.
pub struct Job {
	pub id: i64,
	pub repo_id: i64,
	pub phase: Phase,
	pub campaign_id: i64,
	pub generation_id: Option<i64>,
	pub assigned_lead_id: Option<i64>,
	pub target_finding_id: Option<i64>,
}
/// Policy input, never an authorization token. Every textual field retains Db.
pub struct Context {
	pub campaign_recipe: crate::campaigns::Recipe,
	pub target_commit: BoundedText<RevisionText, DbSource>,
	pub generation: Option<Generation>,
	pub head_sha: Option<BoundedText<RevisionText, DbSource>>,
	pub recipe: Option<BoundedText<RecipeText, DbSource>>,
}
pub struct Generation {
	pub id: i64,
	pub predecessor: Option<i64>,
	pub commit: BoundedText<RevisionText, DbSource>,
	pub state: crate::generations::State,
}

/// Bound once to the requested identity and to this IMMEDIATE transaction.
/// No SQL access, repository authority, clone or identity retargeting exists.
pub struct PhaseTransaction<'tx> {
	conn: &'tx Connection,
	job_id: i64,
	worker_id: i64,
	capability_hash: Option<[u8; 32]>,
	now: i64,
}
/// Purpose-bound authority borrows the issuing facade, not an HTTP precheck.
pub struct PhaseScope<'scope, 'tx> {
	transaction: &'scope PhaseTransaction<'tx>,
	job: Job,
	access: Access,
	bootstrap: bool,
}

/// The clock runs only after IMMEDIATE acquires its lock. Every callback error,
/// including response conversion errors, drops the transaction before commit.
pub fn with_phase_transaction<T, E: From<Error>>(
	db: &crate::Db, identity: jobs::LeaseIdentity<'_>, clock: impl FnOnce() -> i64,
	body: impl for<'tx> FnOnce(&mut PhaseTransaction<'tx>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
	db.with_conn(|conn| {
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let mut facade = PhaseTransaction {
			conn: &tx,
			job_id: identity.job_id,
			worker_id: identity.worker_id,
			capability_hash: identity.capability_hash.try_into().ok(),
			now: clock(),
		};
		let value = match body(&mut facade) {
			Ok(value) => value,
			Err(error) => return Ok(Err(error)),
		};
		tx.commit()?;
		Ok(Ok(value))
	})
	.map_err(E::from)?
}

impl PhaseTransaction<'_> {
	/// Authenticate a terminal retry without consulting live or derived state.
	pub fn replay_terminal(
		&mut self, phase: Phase, payload: &crate::terminal_payloads::TerminalPayload,
	) -> Result<crate::terminal_receipt::Replayed> {
		use crate::terminal_receipt::{Reject, Replayed};
		let Some(hash) = self.capability_hash else {
			return Ok(Replayed::Reject(Reject::Denied));
		};
		if payload.phase() != phase.job_kind() {
			return Ok(Replayed::Reject(Reject::Denied));
		}
		crate::terminal_receipt::replay_terminal(
			self.conn,
			jobs::LeaseIdentity {
				job_id: self.job_id,
				worker_id: self.worker_id,
				capability_hash: &hash,
			},
			phase,
			&payload.digest()?,
		)
	}

	pub fn authorize(
		&mut self, phase: Phase, access: Access,
		policy: impl FnOnce(&Context) -> Result<Option<PolicyDecision>>,
	) -> Result<Option<PhaseScope<'_, '_>>> {
		let Some(hash) = self.capability_hash else { return Ok(None) };
		let job = self.conn.query_row(
			"SELECT j.id,j.repo_id,j.campaign_id,j.generation_id,j.assigned_lead_id,j.target_finding_id
			 FROM jobs j JOIN workers w ON w.id=j.worker_id
			 WHERE j.id=?1 AND j.worker_id=?2 AND j.job_capability_hash=?3 AND j.kind=?4
			 AND j.state='leased' AND typeof(j.lease_expires_at)='integer' AND j.lease_expires_at>=?5
			 AND typeof(j.attempts)='integer' AND j.attempts>0
			 AND j.campaign_id IS NOT NULL AND w.kind='worker' AND w.revoked_at IS NULL",
			params![self.job_id,self.worker_id,hash.as_slice(),phase.job_kind().as_str(),self.now],
			|row| Ok(Job { id:row.get(0)?,repo_id:row.get(1)?,phase,campaign_id:row.get(2)?,
				generation_id:row.get(3)?,assigned_lead_id:row.get(4)?,target_finding_id:row.get(5)? }),
		).optional()?;
		let Some(job) = job else { return Ok(None) };
		if access == Access::LeaseControl {
			return Ok(Some(PhaseScope { transaction: self, job, access, bootstrap: false }));
		}
		let Some(context) = self.context(&job)? else { return Ok(None) };
		let Some(decision) = policy(&context)? else { return Ok(None) };
		if matches!(access, Access::PreparedHost | Access::Domain)
			&& !self.prepared(&job, &context)?
		{
			return Ok(None);
		}
		let scope = PhaseScope {
			transaction: self,
			job,
			access,
			bootstrap: decision == PolicyDecision::Bootstrap,
		};
		if phase == Phase::Drilldown
			&& !scope
				.job
				.assigned_lead_id
				.map(|id| scope.lead_owned(id))
				.transpose()?
				.unwrap_or(false)
			|| phase == Phase::Verify
				&& !scope
					.job
					.target_finding_id
					.map(|id| scope.finding_owned(id))
					.transpose()?
					.unwrap_or(false)
		{
			return Ok(None);
		}
		if access == Access::Domain || phase != Phase::Survey {
			let Some(generation) = &context.generation else { return Ok(None) };
			if !self.ready(&scope.job, generation)? {
				return Ok(None);
			}
		}
		Ok(Some(scope))
	}

	fn context(&self, job: &Job) -> Result<Option<Context>> {
		let row = self.conn.query_row(
			"SELECT c.recipe,c.target_commit_sha,c.generation_id,j.head_sha,j.recipe
			 FROM review_campaigns c JOIN jobs j ON j.campaign_id=c.campaign_id
			 WHERE j.id=?1 AND c.repo_id=?2 AND j.workflow_contract_version=?3
			 AND c.state='active' AND (c.deadline_at IS NULL OR (typeof(c.deadline_at)='integer' AND c.deadline_at>?4))
			 AND typeof(j.hard_deadline_at)='integer' AND j.hard_deadline_at>?4",
			params![job.id,job.repo_id,WORKFLOW_CONTRACT_VERSION,self.now],
			|row| Ok((Context { campaign_recipe:crate::review::parsed(row,0)?,
				target_commit:crate::ingress::revision(row,1)?,generation:None,
				head_sha:crate::ingress::optional_revision(row,3)?,
				recipe:crate::ingress::review_authority::optional_recipe(row,4)?,
			},row.get::<_,Option<i64>>(2)?)),
		).optional()?;
		let Some((mut context, generation_id)) = row else { return Ok(None) };
		if generation_id != job.generation_id {
			return Ok(None);
		}
		context.generation = if let Some(id) = generation_id {
			let value = self.conn.query_row(
				"SELECT predecessor_generation_id,generation_commit_sha,state FROM review_generations
				 WHERE generation_id=?1 AND repo_id=?2 AND workflow_contract_version=?3",
				params![id,job.repo_id,WORKFLOW_CONTRACT_VERSION],
				|row| Ok(Generation { id,predecessor:row.get(0)?,commit:crate::ingress::revision(row,1)?,state:crate::review::parsed(row,2)? }),
			).optional()?;
			let Some(value) = value else { return Ok(None) };
			Some(value)
		} else {
			None
		};
		Ok(Some(context))
	}
	fn prepared(&self, job: &Job, context: &Context) -> Result<bool> {
		let Some(generation) = &context.generation else { return Ok(false) };
		let Some(head) = &context.head_sha else { return Ok(false) };
		let head = head.expose();
		if !loupe_core::inventory_manifest::is_git_oid(head)
			|| head != context.target_commit.expose()
			|| head != generation.commit.expose()
		{
			return Ok(false);
		}
		Ok(self.conn.query_row(
			"SELECT prepared_attempt=attempts AND prepared_capability_hash=?2 AND prepared_at<=?3 FROM jobs WHERE id=?1",
			params![job.id,self.capability_hash.as_ref().map(|hash| hash.as_slice()),self.now],
			|row| row.get::<_,Option<bool>>(0),
		)?.unwrap_or(false))
	}
	fn ready(&self, job: &Job, generation: &Generation) -> Result<bool> {
		Ok(self
			.conn
			.query_row(
				"SELECT g.profile_version,g.generated_profile,g.generated_profile_digest,g.generated_profile_source FROM review_generations g
			 JOIN generation_manifests m ON m.generation_id=g.generation_id
			 WHERE g.generation_id=?1 AND g.repo_id=?2 AND typeof(g.profile_version)='integer'
			 AND g.profile_version BETWEEN 1 AND 4294967295 AND m.sealed_at IS NOT NULL
			 AND m.received_entry_count=m.expected_entry_count",
				params![generation.id, job.repo_id],
				|row| Ok(crate::ingress::profile::frozen_profile(row, 0, 1, 2, 3).is_ok_and(|profile| profile.is_some())),
			)
			.optional()?
			.unwrap_or(false))
	}
}

impl PhaseScope<'_, '_> {
	pub fn job(&self) -> &Job {
		&self.job
	}
	/// Fresh-only: callers run subject checks after checkpoint replay lookup.
	pub fn survey_unit(&self, id: i64, epoch: i64) -> Result<bool> {
		if self.access != Access::Domain || self.job.phase != Phase::Survey {
			return Ok(false);
		}
		let membership = if self.bootstrap {
			"u.created_by_job_id=?3"
		} else {
			"EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?3 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?4)"
		};
		Ok(self.transaction.conn.query_row(&format!(
			"SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id
			 WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND {membership} AND g.repo_id=?5
			 AND u.assignment_epoch=?4 AND u.status='open' AND u.stale=0
			 AND NOT EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id
			 AND NOT EXISTS(SELECT 1 FROM survey_continuation_batches b JOIN job_assigned_review_units a ON a.job_id=b.admitted_job_id
			 WHERE b.batch_id=h.pending_batch_id AND b.generation_id=u.generation_id AND b.state='admitted' AND b.admitted_job_id=?3
			 AND a.review_unit_id=u.review_unit_id AND a.position=h.batch_position AND a.assignment_epoch=?4))
			 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id
			 WHERE a.review_unit_id=u.review_unit_id AND a.job_id<>?3 AND j.state IN ('queued','leased'))
			 AND NOT ({}))",review_units::UNIT_COVERED),
			params![id,self.job.generation_id,self.job.id,epoch,self.job.repo_id],|row| row.get(0))?)
	}
	pub fn assigned_lead(&self, id: i64) -> Result<bool> {
		Ok(self.access == Access::Domain
			&& self.job.phase == Phase::Drilldown
			&& self.lead_owned(id)?)
	}
	pub fn assigned_finding(&self, id: i64) -> Result<bool> {
		Ok(self.access == Access::Domain
			&& self.job.phase == Phase::Verify
			&& self.finding_owned(id)?)
	}
	fn lead_owned(&self, id: i64) -> Result<bool> {
		Ok(self.job.assigned_lead_id == Some(id) && self.transaction.conn.query_row(
			"SELECT EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id
			 WHERE l.lead_id=?1 AND l.generation_id=?2 AND g.repo_id=?3)",
			params![id,self.job.generation_id,self.job.repo_id],|row| row.get(0))?)
	}
	fn finding_owned(&self, id: i64) -> Result<bool> {
		Ok(self.job.target_finding_id == Some(id)
			&& self.transaction.conn.query_row(
				"SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",
				params![id, self.job.repo_id],
				|row| row.get(0),
			)?)
	}
}

#[cfg(test)]
mod tests;
