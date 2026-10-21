//! Named host operations keep SQL inside the purpose-bound authority owner.
use loupe_core::review_metadata::ReviewCommit;
use loupe_provenance::Worker;
use rusqlite::{params, OptionalExtension};

use super::{Access, Context, Phase, PhaseScope, PhaseTransaction, PolicyDecision};
use crate::host_preparation::{PinOutcome, PinReplay};
use crate::{Conflict, Error, Result};

mod manifest;
mod pin;

fn denied() -> Error {
	Error::ScopeDenied
}

fn generation_state() -> Error {
	Error::Conflict(Conflict::GenerationState)
}

impl PhaseTransaction<'_> {
	/// Terminal replay authenticates the original finishing capability before
	/// any live context, preparation or rebuildable generation is consulted.
	pub fn replay_pin_target(
		&mut self, _commit: &ReviewCommit<Worker>, digest: &[u8; 32],
	) -> Result<PinReplay> {
		let Some(hash) = self.capability_hash else {
			return Ok(PinReplay::Reject(crate::terminal_receipt::Reject::Denied));
		};
		match crate::terminal_receipt::replay_terminal(
			self.conn,
			crate::jobs::LeaseIdentity {
				job_id: self.job_id,
				worker_id: self.worker_id,
				capability_hash: &hash,
			},
			Phase::Survey,
			digest,
		)? {
			crate::terminal_receipt::Replayed::Receipt(receipt) => {
				if receipt.terminal_reason.expose() != "unsupported_recipe" {
					return Ok(PinReplay::Reject(crate::terminal_receipt::Reject::Denied));
				}
				let commit = self.conn.query_row(
					"SELECT pinned_commit_sha FROM job_terminal_receipts WHERE job_id=?1",
					[self.job_id],
					|row| crate::ingress::profile::commit(row, 0),
				)?;
				Ok(PinReplay::Receipt { receipt, commit })
			},
			crate::terminal_receipt::Replayed::Reject(reason) => Ok(PinReplay::Reject(reason)),
		}
	}

	pub fn pin_target(
		&mut self, commit: &ReviewCommit<Worker>, digest: &[u8; 32],
		policy: impl Fn(Phase, Access, &Context) -> Result<Option<PolicyDecision>>,
	) -> Result<PinOutcome<'_, '_>> {
		// Read only the closed phase before the identity-bound issuer performs
		// the full worker/capability/current-attempt check.
		let phase: Option<i64>=self.conn.query_row("SELECT CASE kind WHEN 'survey' THEN 1 WHEN 'drilldown' THEN 2 WHEN 'verify' THEN 3 ELSE 0 END FROM jobs WHERE id=?1",[self.job_id],|row|row.get(0)).optional()?;
		let phase = match phase {
			Some(1) => Phase::Survey,
			Some(2) => Phase::Drilldown,
			Some(3) => Phase::Verify,
			_ => return Err(denied()),
		};
		let bootstrap = {
			let scope = self
				.authorize(phase, Access::Checkout, |context| {
					policy(phase, Access::Checkout, context)
				})?
				.ok_or_else(denied)?;
			if let Some((receipt, commit)) = pin::pin_and_confirm(&scope, commit, digest)? {
				return Ok(PinOutcome::Deferred { receipt, commit });
			}
			scope.bootstrap
		};
		let access = if bootstrap { Access::PreparedHost } else { Access::Domain };
		let scope = self
			.authorize(phase, access, |context| policy(phase, access, context))?
			.ok_or_else(denied)?;
		if phase == Phase::Survey && !bootstrap {
			crate::scheduler::initialize_ordinary_batch(
				scope.transaction.conn,
				scope.job.id,
				scope.transaction.now,
			)?;
		}
		Ok(PinOutcome::Prepared(scope))
	}
}

impl PhaseScope<'_, '_> {
	pub fn is_bootstrap(&self) -> bool {
		self.bootstrap
	}

	fn bootstrap_generation(&self) -> Result<i64> {
		if self.access != Access::PreparedHost || self.job.phase != Phase::Survey || !self.bootstrap
		{
			return Err(denied());
		}
		let generation = self.job.generation_id.ok_or_else(denied)?;
		let preparing:bool=self.transaction.conn.query_row("SELECT g.state='building' AND g.predecessor_generation_id IS NULL FROM review_generations g JOIN review_campaigns c ON c.generation_id=g.generation_id WHERE g.generation_id=?1 AND g.repo_id=?2 AND c.campaign_id=?3 AND c.repo_id=?2 AND c.recipe='bootstrap'",params![generation,self.job.repo_id,self.job.campaign_id],|row|row.get(0)).optional()?.ok_or_else(denied)?;
		if !preparing {
			return Err(generation_state());
		}
		Ok(generation)
	}
}
