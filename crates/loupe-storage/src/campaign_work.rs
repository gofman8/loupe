//! Bounded metadata-only campaign maintenance, never candidate ranking or admission.
use loupe_core::text::policy::JsonLeaf;
use loupe_core::text::BoundedText;
use loupe_provenance::Db;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::admission::WorkClass;
use crate::review::parsed;
use crate::review_intents::BlockReason;
use crate::scheduler::Band;
use crate::{review_units, Conflict, Entity, Error, Result};

pub(crate) fn has_unfinished(tx: &Connection, repo: i64, campaign: i64) -> Result<bool> {
	Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM lead_drilldown_intents WHERE admission_campaign_id=?1 AND repo_id=?2 AND state!='complete' UNION ALL SELECT 1 FROM finding_verification_intents WHERE admission_campaign_id=?1 AND repo_id=?2 AND state!='complete' UNION ALL SELECT 1 FROM survey_continuation_batches WHERE campaign_id=?1 AND repo_id=?2 AND state!='complete')",params![campaign,repo],|r|r.get(0))?)
}

// debug-ok: pending sources are closed storage relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
	Lead,
	Finding,
	ExactBatch,
	Ordinary,
}
impl Source {
	fn relation(self) -> Option<(&'static str, &'static str)> {
		match self {
			Self::Lead => Some(("lead_drilldown_intents", "admission_campaign_id")),
			Self::Finding => Some(("finding_verification_intents", "admission_campaign_id")),
			Self::ExactBatch => Some(("survey_continuation_batches", "campaign_id")),
			Self::Ordinary => None,
		}
	}
}

// debug-ok: pending groups contain only closed state and a cutoff comparison.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingGroup {
	source: Source,
	band: Band,
	pub(crate) before_deadline: bool,
}
impl PendingGroup {
	pub(crate) fn work_class(self) -> WorkClass {
		match (self.source, self.band) {
			(Source::Lead, Band::Urgent) => WorkClass::UrgentDrilldown,
			(Source::Lead, _) => WorkClass::Drilldown,
			(Source::Finding, Band::Urgent) => WorkClass::UrgentVerification,
			(Source::Finding, _) => WorkClass::Verification,
			_ => WorkClass::Survey,
		}
	}
}

/// At most 25 groups. Future due time before the exclusive cutoff remains work.
pub(crate) fn pending(
	tx: &Connection, repo: i64, campaign: i64, deadline: Option<i64>,
) -> Result<Vec<PendingGroup>> {
	let mut groups = Vec::new();
	for source in [Source::Lead, Source::Finding, Source::ExactBatch] {
		let (table, owner) = source.relation().ok_or(Error::Conflict(Conflict::CampaignState))?;
		let sql = format!("SELECT accepted_band, (?3 IS NULL OR not_before IS NULL OR not_before < ?3) FROM {table} WHERE {owner}=?1 AND repo_id=?2 AND state='pending' GROUP BY 1,2 ORDER BY 1,2");
		let mut statement = tx.prepare(&sql)?;
		for row in statement.query_map(params![campaign, repo, deadline], |r| {
			Ok(PendingGroup { source, band: parsed(r, 0)?, before_deadline: r.get(1)? })
		})? {
			groups.push(row?);
		}
	}
	let ordinary: bool = tx.query_row(&format!("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id JOIN review_campaigns c ON c.generation_id=g.generation_id AND c.repo_id=g.repo_id WHERE c.campaign_id=?1 AND c.repo_id=?2 AND g.state='active' AND {})", *review_units::UNIT_NEEDS_WORK), params![campaign,repo], |r| r.get(0))?;
	if ordinary {
		groups.push(PendingGroup {
			source: Source::Ordinary,
			band: Band::Normal,
			before_deadline: true,
		});
	}
	Ok(groups)
}

/// Block only the examined group, retaining evidence, rank, revision and membership.
pub(crate) fn block_pending(
	tx: &Connection, repo: i64, campaign: i64, group: PendingGroup, deadline: Option<i64>,
	reason: BlockReason, now: i64,
) -> Result<()> {
	if group.source == Source::Ordinary {
		tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?3 WHERE review_unit_id IN(SELECT u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id JOIN review_campaigns c ON c.generation_id=g.generation_id AND c.repo_id=g.repo_id WHERE c.campaign_id=?1 AND c.repo_id=?2 AND {})", *review_units::UNIT_NEEDS_WORK), params![campaign,repo,reason.as_str()])?;
		return Ok(());
	}
	let (table, owner) = group.source.relation().ok_or(Error::Conflict(Conflict::CampaignState))?;
	let predicate = format!("{owner}=?1 AND repo_id=?2 AND state='pending' AND accepted_band=?3 AND (?4 IS NULL OR not_before IS NULL OR not_before < ?4)=?5");
	if group.source == Source::ExactBatch {
		tx.execute(&format!("UPDATE review_unit_holds SET block_reason=?6,updated_at=?7 WHERE pending_batch_id IN(SELECT batch_id FROM {table} WHERE {predicate}) AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_unit_holds.generation_id AND g.repo_id=?2)"), params![campaign,repo,group.band.as_str(),deadline,group.before_deadline,reason.as_str(),now])?;
		tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?6 WHERE status IN('open','deferred') AND review_unit_id IN(SELECT h.review_unit_id FROM review_unit_holds h JOIN review_generations g ON g.generation_id=h.generation_id AND g.repo_id=?2 WHERE h.pending_batch_id IN(SELECT batch_id FROM {table} WHERE {predicate})) AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?2)"),params![campaign,repo,group.band.as_str(),deadline,group.before_deadline,reason.as_str()])?;
	}
	let updated = if group.source == Source::ExactBatch { "" } else { ",updated_at=?7" };
	let sql = format!("UPDATE {table} SET state='blocked',not_before=NULL,block_reason=?6{updated} WHERE {predicate}");
	if group.source == Source::ExactBatch {
		tx.execute(
			&sql,
			params![
				campaign,
				repo,
				group.band.as_str(),
				deadline,
				group.before_deadline,
				reason.as_str()
			],
		)?;
	} else {
		tx.execute(
			&sql,
			params![
				campaign,
				repo,
				group.band.as_str(),
				deadline,
				group.before_deadline,
				reason.as_str(),
				now
			],
		)?;
	}
	Ok(())
}

/// Cancellation and deadline preserve unfinished work and all live lease identities.
pub(crate) fn block_all(
	tx: &Connection, repo: i64, campaign: i64, reason: BlockReason, now: i64,
) -> Result<()> {
	block(tx, repo, campaign, reason, now, false)
}
pub(crate) fn block_unexplained(tx: &Connection, repo: i64, campaign: i64, now: i64) -> Result<()> {
	block(tx, repo, campaign, BlockReason::RequiresSuccessor, now, true)
}
fn block(
	tx: &Connection, repo: i64, campaign: i64, reason: BlockReason, now: i64,
	only_unexplained: bool,
) -> Result<()> {
	let generation: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",
			params![campaign, repo],
			|r| r.get(0),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Campaign, campaign))?;
	let filter = if only_unexplained { " AND block_reason IS NULL" } else { "" };
	for table in ["lead_drilldown_intents", "finding_verification_intents"] {
		tx.execute(&format!("UPDATE {table} SET state='blocked',not_before=NULL,block_reason=?3,updated_at=?4 WHERE admission_campaign_id=?1 AND repo_id=?2 AND state!='complete'{filter}"),params![campaign,repo,reason.as_str(),now])?;
	}
	tx.execute(&format!("UPDATE review_unit_holds SET block_reason=?3,updated_at=?4 WHERE (pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE campaign_id=?1 AND repo_id=?2) OR (pending_batch_id IS NULL AND producing_job_id IN(SELECT id FROM jobs WHERE campaign_id=?1 AND repo_id=?2))) AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_unit_holds.generation_id AND g.repo_id=?2){filter}"),params![campaign,repo,reason.as_str(),now])?;
	tx.execute(&format!("UPDATE survey_continuation_batches SET state='blocked',not_before=NULL,block_reason=?3 WHERE campaign_id=?1 AND repo_id=?2 AND state!='complete'{filter}"),params![campaign,repo,reason.as_str()])?;
	let defer_filter = if only_unexplained { " AND u.defer_reason IS NULL" } else { "" };
	tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?3 WHERE review_unit_id IN(SELECT u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND g.repo_id=?2 AND u.status IN('open','deferred'){defer_filter} AND (EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id AND h.generation_id=g.generation_id) OR NOT ({})))",review_units::UNIT_COVERED),params![generation,repo,reason.as_str()])?;
	Ok(())
}

type Leaf = BoundedText<JsonLeaf, Db>;
// debug-ok: content members are actual redacted Db owners; counts are numeric.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StateCount {
	state: Leaf,
	reason: Option<Leaf>,
	count: i64,
}
// debug-ok: content members are actual redacted Db owners; counts are numeric.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HoldCount {
	reason: Option<Leaf>,
	count: i64,
}
/// Closed composition of actual SQL observations, not a newly labelled JSON input.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Summary {
	leads: Vec<StateCount>,
	findings: Vec<StateCount>,
	exact_batches: Vec<StateCount>,
	holds: Vec<HoldCount>,
}
impl Summary {
	pub(crate) fn nodes(&self) -> usize {
		5usize
			.saturating_add(
				self.leads
					.len()
					.saturating_add(self.findings.len())
					.saturating_add(self.exact_batches.len())
					.saturating_mul(4),
			)
			.saturating_add(self.holds.len().saturating_mul(3))
	}
	pub(crate) fn render(&self) -> serde_json::Value {
		let states = |rows: &[StateCount]| {
			rows.iter()
				.map(
					|row| serde_json::json!({"state":row.state,"reason":row.reason,"count":row.count}),
				)
				.collect::<Vec<_>>()
		};
		let holds = self
			.holds
			.iter()
			.map(|row| serde_json::json!({"reason":row.reason,"count":row.count}))
			.collect::<Vec<_>>();
		serde_json::json!({"leads":states(&self.leads),"findings":states(&self.findings),"exact_batches":states(&self.exact_batches),"unit_holds":holds})
	}
}
fn reason(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<Leaf>> {
	if matches!(row.get_ref(index)?, rusqlite::types::ValueRef::Null) {
		Ok(None)
	} else {
		crate::ingress::count_json_leaf(row, index).map(Some)
	}
}
/// Grouped metadata never reads canonical finding or checkpoint evidence.
pub(crate) fn summary(tx: &Connection, repo: i64, campaign: i64) -> Result<Summary> {
	let [leads,findings,exact_batches] = [
		("lead_drilldown_intents", "admission_campaign_id"),
		("finding_verification_intents", "admission_campaign_id"),
		("survey_continuation_batches", "campaign_id"),
	].map(|(table,owner)| -> Result<Vec<StateCount>> {
		let mut statement = tx.prepare(&format!("SELECT state,block_reason,COUNT(*) FROM {table} WHERE {owner}=?1 AND repo_id=?2 GROUP BY state,block_reason ORDER BY state,block_reason"))?;
		Ok(statement
				.query_map(params![campaign, repo], |r| {
					Ok(StateCount {
						state: crate::ingress::count_json_leaf(r, 0)?,
						reason: reason(r, 1)?,
						count: r.get(2)?,
					})
				})?
				.collect::<rusqlite::Result<Vec<_>>>()?)
	});
	let mut statement = tx.prepare("SELECT h.block_reason,COUNT(*) FROM review_unit_holds h JOIN review_generations g ON g.generation_id=h.generation_id AND g.repo_id=?2 WHERE h.pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE campaign_id=?1 AND repo_id=?2) OR (h.pending_batch_id IS NULL AND h.producing_job_id IN(SELECT id FROM jobs WHERE campaign_id=?1 AND repo_id=?2)) GROUP BY h.block_reason ORDER BY h.block_reason")?;
	let holds = statement
		.query_map(params![campaign, repo], |r| {
			Ok(HoldCount { reason: reason(r, 0)?, count: r.get(1)? })
		})?
		.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(Summary { leads: leads?, findings: findings?, exact_batches: exact_batches?, holds })
}
