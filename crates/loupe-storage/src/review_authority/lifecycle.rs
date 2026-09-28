//! Purpose-bound worker execution control, without Domain payload authority.
use loupe_core::text::policy::Reason;
use loupe_core::text::BoundedText;
use loupe_provenance::Worker;

use super::{Access, PhaseScope};
use crate::scheduler::{FailureReason, RetryOutcome};
use crate::{Error, Result};

impl PhaseScope<'_, '_> {
	pub fn retry_failure(
		&self, error: Option<&BoundedText<Reason, Worker>>,
	) -> Result<RetryOutcome> {
		if self.access != Access::LeaseControl {
			return Err(Error::ScopeDenied);
		}
		crate::phase_lifecycle::retry_or_fail(
			self.transaction.conn,
			self.job.repo_id,
			self.job.id,
			self.transaction.now,
			error.map_or(FailureReason::ExecutionFailed, FailureReason::Submitted),
		)
	}
	pub fn heartbeat(&self, lease_seconds: i64, grace_seconds: i64) -> Result<i64> {
		if self.access != Access::LeaseControl {
			return Err(Error::ScopeDenied);
		}
		crate::phase_lifecycle::heartbeat(
			self.transaction.conn,
			self.job.repo_id,
			self.job.id,
			self.transaction.now,
			lease_seconds,
			grace_seconds,
		)
	}
}
