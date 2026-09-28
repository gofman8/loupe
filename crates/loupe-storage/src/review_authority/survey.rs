//! Survey completion certifies retained evidence, never an agent's terminal
//! reason. All domain writes stay inside the identity-bound phase transaction.
use loupe_core::review_payload::{
	SurveyTerminalV1, UnitResultDisposition, UnitResultPayloadV1, Version1,
};
use loupe_provenance::Agent;
use rusqlite::{params, Connection};

use super::terminal::{self, incompatible, stored_error};
use super::{
	Access, Context, Phase, PhaseScope, PhaseTransaction, PolicyDecision, SurveyCoverage,
	SurveyFinalization, SurveySummary,
};
use crate::terminal_payloads::TerminalPayload;
use crate::terminal_receipt::{Reject, Replayed};
use crate::{
	generations, inventory, review_unit_results, unit_holds, Conflict, Error, Result,
	StoredEvidence,
};
fn evidence(
	tx: &Connection, repo: i64, result: i64,
) -> Result<StoredEvidence<UnitResultPayloadV1<Agent>>> {
	review_unit_results::get_evidence_raw(tx, repo, result).map_err(stored_error)
}

/// Terminal validation cannot use the checkpoint's fresh-write predicate: that
/// deliberately denies already-conclusive units. Persisted assignments remain
/// authoritative even after their checkpoint marked them completed.
fn owned_result(
	tx: &Connection, generation: i64, producer: i64, payload: &UnitResultPayloadV1<Agent>,
) -> Result<bool> {
	Ok(tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_units u JOIN jobs j ON j.id=?3
		JOIN review_generations g ON g.generation_id=u.generation_id
		WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND j.generation_id=u.generation_id
		AND j.kind='survey' AND j.repo_id=g.repo_id AND j.workflow_contract_version=?5 AND j.head_sha=g.generation_commit_sha
		AND u.assignment_epoch=?4 AND u.stale=0 AND u.status IN('open','deferred')
		AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units other JOIN jobs live ON live.id=other.job_id
		WHERE other.review_unit_id=u.review_unit_id AND other.job_id<>j.id AND live.state IN('queued','leased'))
		AND ((u.created_by_job_id=j.id AND ?4=0) OR EXISTS(SELECT 1 FROM job_assigned_review_units a
		WHERE a.job_id=j.id AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?4)))",
		params![payload.review_unit_id, generation, producer, payload.assignment_epoch,loupe_core::WORKFLOW_CONTRACT_VERSION],
		|r| r.get(0),
	)?)
}

fn validate_producer(
	tx: &Connection, scope: &PhaseScope<'_, '_>, generation: &generations::Generation,
) -> Result<()> {
	let foreign:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_unit_results r WHERE r.produced_by_job_id=?1 AND r.invalidated=0 AND NOT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=r.review_unit_id AND u.generation_id=?2 AND g.repo_id=?3))",params![scope.job.id,generation.generation_id,generation.repo_id],|row|row.get(0))?;
	if foreign {
		return Err(incompatible());
	}
	let mut statement = tx.prepare(
		"SELECT r.review_unit_result_id,r.commit_sha,r.profile_version
        FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id
        JOIN review_generations g ON g.generation_id=u.generation_id
        WHERE r.produced_by_job_id=?1 AND r.invalidated=0 AND u.generation_id=?2 AND g.repo_id=?3
        ORDER BY r.review_unit_result_id",
	)?;
	let mut rows =
		statement.query(params![scope.job.id, generation.generation_id, generation.repo_id])?;
	while let Some(row) = rows.next()? {
		let id: i64 = row.get(0)?;
		let payload = match evidence(tx, generation.repo_id, id)? {
			StoredEvidence::Recorded(value) => value,
			StoredEvidence::Historical => continue,
			StoredEvidence::Missing => return Err(incompatible()),
		};
		if crate::ingress::profile::commit(row, 1)?.expose() != generation.commit_sha.expose()
			|| row.get::<_, i64>(2)? != generation.profile_version
			|| !owned_result(tx, generation.generation_id, scope.job.id, &payload)?
		{
			return Err(incompatible());
		}
		if !scope.bootstrap {
			let assigned: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM job_assigned_review_units
				WHERE job_id=?1 AND review_unit_id=?2 AND assignment_epoch=?3)",
				params![scope.job.id, payload.review_unit_id, payload.assignment_epoch],
				|r| r.get(0),
			)?;
			if !assigned {
				return Err(incompatible());
			}
		}
		inventory::verify_refs_raw(
			tx,
			generation.repo_id,
			generation.generation_id,
			payload.inspected_refs.as_slice(),
		)?;
		let held = unit_holds::get_hold_raw(tx, generation.repo_id, payload.review_unit_id)?;
		if payload.disposition == UnitResultDisposition::NeedsFollowUp {
			let Some(hold) = held else { return Err(incompatible()) };
			if hold.generation_id != generation.generation_id
				|| hold.producing_job_id != scope.job.id
				|| hold.producing_result_id != id
				|| hold.source_assignment_epoch != payload.assignment_epoch
				|| Some(hold.continuation_class) != payload.continuation
			{
				return Err(incompatible());
			}
		} else if held.is_some() {
			return Err(incompatible());
		}
	}
	// A dangling/corrupted hold cannot be hidden by the result iteration above.
	let mut statement=tx.prepare("SELECT review_unit_id,producing_result_id FROM review_unit_holds WHERE producing_job_id=?1")?;
	let mut rows = statement.query([scope.job.id])?;
	while let Some(row) = rows.next()? {
		let unit: i64 = row.get(0)?;
		let result: i64 = row.get(1)?;
		let StoredEvidence::Recorded(payload) = evidence(tx, generation.repo_id, result)? else {
			return Err(incompatible());
		};
		if payload.review_unit_id != unit
			|| payload.disposition != UnitResultDisposition::NeedsFollowUp
		{
			return Err(incompatible());
		}
	}
	Ok(())
}

/// Stream rather than collecting repository-size evidence. Relational legacy
/// projections alone never certify modern coverage; historical evidence stays
/// retained and simply leaves work incomplete.
fn coverage(tx: &Connection, generation: &generations::Generation) -> Result<SurveySummary> {
	let legacy =
		generations::coverage_rollup_raw(tx, generation.repo_id, generation.generation_id)?;
	let mut summary = SurveySummary {
		version: Version1,
		coverage: SurveyCoverage::Partial,
		corroboration_satisfied: generation.corroboration == generations::Corroboration::Satisfied,
		missing_results: 0,
		needs_follow_up: 0,
		unresolved_inventory: legacy.unresolved_inventory.try_into().map_err(|_| incompatible())?,
		follow_up_batches: 0,
		follow_up_units: 0,
	};
	let mut statement=tx.prepare("SELECT u.review_unit_id,EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)
		FROM review_units u WHERE u.generation_id=?1 AND (u.status IN('open','deferred') OR EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)) ORDER BY u.review_unit_id")?;
	let mut rows = statement.query([generation.generation_id])?;
	while let Some(row) = rows.next()? {
		let unit: i64 = row.get(0)?;
		let held: bool = row.get(1)?;
		let mut conclusive = false;
		let mut follows = held;
		let mut results=tx.prepare("SELECT review_unit_result_id,produced_by_job_id FROM review_unit_results
			WHERE review_unit_id=?1 AND invalidated=0 AND commit_sha=?2 AND profile_version=?3
			AND corroborates_review_unit_result_id IS NULL AND corroborates_inventory_exclusion_id IS NULL ORDER BY review_unit_result_id DESC")?;
		let mut evidence_rows = results.query(params![
			unit,
			generation.commit_sha.expose(),
			generation.profile_version
		])?;
		while let Some(row) = evidence_rows.next()? {
			let id: i64 = row.get(0)?;
			let producer: Option<i64> = row.get(1)?;
			let StoredEvidence::Recorded(payload) = evidence(tx, generation.repo_id, id)? else {
				continue;
			};
			if let Some(producer) = producer
				&& owned_result(tx, generation.generation_id, producer, &payload)?
			{
				inventory::verify_refs_raw(
					tx,
					generation.repo_id,
					generation.generation_id,
					payload.inspected_refs.as_slice(),
				)?;
				if payload.disposition == UnitResultDisposition::NeedsFollowUp {
					follows = true;
				} else {
					conclusive = true;
				}
			}
		}
		if held || !conclusive {
			summary.missing_results += 1;
			if follows {
				summary.needs_follow_up += 1;
			}
		}
	}
	if summary.missing_results == 0
		&& summary.unresolved_inventory == 0
		&& summary.corroboration_satisfied
	{
		summary.coverage = SurveyCoverage::Complete;
	}
	Ok(summary)
}

impl PhaseTransaction<'_> {
	/// Receipt-only replay precedes all live context and supplied recipe policy.
	/// The caller must render the bounded response inside this same transaction.
	pub fn finalize_survey(
		&mut self, payload: &SurveyTerminalV1<Agent>,
		policy: impl FnOnce(&Context) -> Result<Option<PolicyDecision>>,
	) -> Result<SurveyFinalization> {
		let payload = TerminalPayload::Survey(payload.clone());
		match self.replay_terminal(Phase::Survey, &payload)? {
			Replayed::Receipt(_) => return terminal::snapshot(self).map_err(stored_error),
			Replayed::Reject(Reject::WrongDigest) => {
				return Err(Error::Conflict(Conflict::TerminalReceipt))
			},
			Replayed::Reject(Reject::Denied) => {},
		}
		let scope =
			self.authorize(Phase::Survey, Access::Domain, policy)?.ok_or(Error::ScopeDenied)?;
		finalize(&scope, &payload).map_err(stored_error)
	}
}
fn finalize(scope: &PhaseScope<'_, '_>, payload: &TerminalPayload) -> Result<SurveyFinalization> {
	if scope.access != Access::Domain || scope.job.phase != Phase::Survey {
		return Err(Error::ScopeDenied);
	}
	let tx = scope.transaction.conn;
	let now = scope.transaction.now;
	let repo = scope.job.repo_id;
	let generation_id = scope.job.generation_id.ok_or(Error::ScopeDenied)?;
	let generation =
		generations::get_for_repo_raw(tx, repo, generation_id)?.ok_or(Error::ScopeDenied)?;
	if generation.state == generations::State::Building {
		let owns:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM generation_manifests m JOIN review_generations g ON g.generation_id=m.generation_id WHERE g.generation_id=?1 AND g.repo_id=?2 AND m.owner_job_id=?3 AND g.predecessor_generation_id IS NULL AND m.sealed_at IS NOT NULL)",params![generation_id,repo,scope.job.id],|row|row.get(0))?;
		if !scope.bootstrap || !owns {
			return Err(Error::ScopeDenied);
		}
	}
	let audit = terminal::audit(scope)?;
	validate_producer(tx, scope, &generation)?;
	let mut summary = coverage(tx, &generation)?;
	if generation.state == generations::State::Building {
		generations::activate_raw(tx, repo, generation_id, now)?;
	}
	generations::set_coverage_raw(
		tx,
		repo,
		generation_id,
		match summary.coverage {
			SurveyCoverage::Complete => generations::Coverage::Complete,
			SurveyCoverage::Partial => generations::Coverage::Partial,
		},
	)?;
	terminal::succeed(scope)?;
	let batches = unit_holds::freeze_survey_batches_raw(tx, repo, scope.job.id, now)?;
	summary.follow_up_batches = batches.len().try_into().map_err(|_| incompatible())?;
	summary.follow_up_units = batches.iter().try_fold(0u64, |count, batch| {
		count.checked_add(u64::from(batch.expected_unit_count)).ok_or_else(incompatible)
	})?;
	terminal::seal(scope, &audit, payload, &summary)
}

#[cfg(test)]
mod tests;
