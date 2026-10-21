//! Purpose-bound snapshots. Wire aggregate bounds remain the server's concern;
//! all reads and original-column content admission stay under this transaction.
use loupe_core::review_metadata::ReviewCommit;
use loupe_core::text::policy::{Objective, Reason, Title};
use loupe_core::text::BoundedText;
use loupe_provenance::{Agent, Db};
use rusqlite::{params, OptionalExtension};

use super::{Access, Phase, PhaseScope};
use crate::{Conflict, Error, Result};

pub struct ReviewPreparation {
	pub generation_id: i64,
	pub commit: ReviewCommit<Db>,
	pub profile: Option<crate::generations::FrozenProfile>,
	pub assignments: Option<Vec<AssignedUnit>>,
}
pub struct AssignedUnit {
	pub id: i64,
	pub epoch: u64,
	pub title: BoundedText<Title, Agent>,
	pub objective: BoundedText<Objective, Agent>,
	pub source_refs: crate::source_refs::UnitRefs<Agent>,
	pub depends_on: Vec<i64>,
	pub closure_criteria: Option<BoundedText<Reason, Agent>>,
}

fn incompatible() -> Error {
	Error::Conflict(Conflict::GenerationState)
}

impl PhaseScope<'_, '_> {
	pub fn preparation_snapshot(&self) -> Result<ReviewPreparation> {
		if self.access != Access::Domain && !(self.access == Access::PreparedHost && self.bootstrap)
		{
			return Err(incompatible());
		}
		let generation = self.job.generation_id.ok_or_else(incompatible)?;
		let conn = self.transaction.conn;
		let (commit, profile) = conn.query_row(
			"SELECT generation_commit_sha,profile_version,generated_profile,generated_profile_digest,generated_profile_source
			 FROM review_generations WHERE generation_id=?1 AND repo_id=?2",
			params![generation,self.job.repo_id],
			|row| Ok((crate::ingress::profile::commit(row,0)?,crate::ingress::profile::frozen_profile(row,1,2,3,4)?)),
		).optional()?.ok_or_else(incompatible)?;
		let assignments = if self.job.phase == Phase::Survey && !self.bootstrap {
			Some(self.assignment_snapshot(generation)?)
		} else {
			None
		};
		Ok(ReviewPreparation { generation_id: generation, commit, profile, assignments })
	}

	fn assignment_snapshot(&self, generation: i64) -> Result<Vec<AssignedUnit>> {
		let conn = self.transaction.conn;
		let expected: usize = conn.query_row(
			"SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=?1 AND completed=0",
			[self.job.id],
			|row| row.get(0),
		)?;
		if expected > 32 {
			return Err(incompatible());
		}
		let mut query = conn.prepare(
			"SELECT a.review_unit_id,a.assignment_epoch,u.assignment_epoch,u.generation_id,
			 u.title,u.objective,u.source_refs,u.depends_on,u.closure_criteria,u.source
			 FROM job_assigned_review_units a JOIN review_units u ON u.review_unit_id=a.review_unit_id
			 JOIN review_generations g ON g.generation_id=u.generation_id
			 WHERE a.job_id=?1 AND a.completed=0 AND g.repo_id=?2
			 ORDER BY a.position LIMIT 33",
		)?;
		let mut rows = query.query(params![self.job.id, self.job.repo_id])?;
		let mut assignments = Vec::new();
		while let Some(row) = rows.next()? {
			crate::ingress::require_agent_source(row, 9)?;
			let epoch: u64 = row.get(1)?;
			if epoch != row.get::<_, u64>(2)? || generation != row.get::<_, i64>(3)? {
				return Err(incompatible());
			}
			let refs = crate::ingress::unit_refs(row, 6)?;
			crate::inventory::verify_refs_raw(conn, self.job.repo_id, generation, refs.as_slice())?;
			let depends_on: Vec<i64> = crate::ingress::optional_agent_payload(row, 7)?
				.map(|raw| serde_json::from_str(raw.expose()))
				.transpose()
				.map_err(|_| incompatible())?
				.unwrap_or_default();
			for dependency in &depends_on {
				let belongs: bool = conn.query_row(
					"SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",
					params![dependency,generation], |row| row.get(0),
				)?;
				if !belongs {
					return Err(incompatible());
				}
			}
			assignments.push(AssignedUnit {
				id: row.get(0)?,
				epoch,
				title: crate::ingress::title(row, 4)?,
				objective: crate::ingress::objective(row, 5)?,
				source_refs: refs,
				depends_on,
				closure_criteria: crate::ingress::optional_closure_criteria(row, 8)?,
			});
		}
		if assignments.len() != expected {
			return Err(incompatible());
		}
		Ok(assignments)
	}
}
