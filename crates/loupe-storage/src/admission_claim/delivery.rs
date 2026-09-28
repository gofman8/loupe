//! Scoped typed delivery snapshots. Wire construction remains a pure callback.
use loupe_core::review_metadata::ReviewCommit;
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::policy::{
	GitBranch, ReviewFindingDescription, ReviewFindingTitle, RevisionText,
};
use loupe_core::text::{BoundedText, SourceRef};
use loupe_core::{JobKind, Severity, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::{Agent, Db};
use rusqlite::{params, Transaction};

use super::validation::{self, invalid, Failure, Planned, Result};
use super::{CallbackError, RecipeDecision, RecipeInput};
use crate::admission_quarantine::{Reason, Source};
use crate::review_authority::{AssignedUnit, Context, Phase};
use crate::{Error, StoredEvidence};

pub struct DeliverySnapshot {
	pub job: crate::jobs::JobRow,
	pub repository: crate::repos::RepoRow,
	pub head_branch: Option<BoundedText<GitBranch, Db>>,
	pub phase: Option<PhaseDelivery>,
	pub target: Option<crate::findings::FindingRow>,
	pub reviewed_revision: Option<BoundedText<RevisionText, Db>>,
}
pub struct PhaseDelivery {
	pub recipe: RecipeDecision,
	pub policy: crate::admission_policy::CampaignPolicyV2,
	pub generation: Option<(i64, ReviewCommit<Db>)>,
	pub profile: Option<crate::generations::FrozenProfile>,
	pub subject: PhaseSubject,
}
pub enum PhaseSubject {
	Survey(Vec<AssignedUnit>),
	Lead {
		id: i64,
		commit: ReviewCommit<Db>,
		evidence: LeadEvidenceV1<Agent>,
	},
	Finding {
		id: i64,
		commit: ReviewCommit<Db>,
		severity: Severity,
		title: BoundedText<ReviewFindingTitle, Agent>,
		description: BoundedText<ReviewFindingDescription, Agent>,
		details: crate::finding_details::ReviewEvidence,
	},
}
pub(super) fn profile_snapshot(
	tx: &Transaction<'_>, repo: i64, generation: i64,
) -> crate::Result<Option<crate::generations::FrozenProfile>> {
	Ok(tx.query_row("SELECT profile_version,generated_profile,generated_profile_digest,generated_profile_source FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![generation,repo],|r|crate::ingress::profile::frozen_profile(r,0,1,2,3))?)
}
pub(super) fn assignment_snapshot<E: From<Error>>(
	tx: &Transaction<'_>, repo: i64, job: i64, generation: i64,
) -> Result<Vec<AssignedUnit>, E> {
	let rows=tx.prepare("SELECT review_unit_id,assignment_epoch,position,completed FROM job_assigned_review_units WHERE job_id=?1 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND generation_id=?3) ORDER BY position LIMIT 33")?
		.query_map(params![job,repo,generation],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Option<u64>>(1)?,r.get::<_,i64>(2)?,r.get::<_,bool>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
	if rows.len() > 32 || rows.iter().enumerate().any(|(i, r)| r.2 != i as i64) {
		return Err(invalid());
	}
	let mut units = Vec::new();
	for (id, epoch, _, completed) in rows {
		if !completed {
			units.push(unit_snapshot(tx, repo, id, generation, Some(epoch.ok_or_else(invalid)?))?);
		}
	}
	Ok(units)
}
pub(super) fn unit_snapshot<E: From<Error>>(
	tx: &Transaction<'_>, repo: i64, id: i64, generation: i64, epoch: Option<u64>,
) -> Result<AssignedUnit, E> {
	unit_inner(tx, repo, id, generation, epoch).map_err(|error| match error {
		Failure::Defect(reason) => Failure::Unit(id, reason),
		other => other,
	})
}
fn unit_inner<E: From<Error>>(
	tx: &Transaction<'_>, repo: i64, id: i64, generation: i64, epoch: Option<u64>,
) -> Result<AssignedUnit, E> {
	let (mut unit,status,stale)=tx.query_row(
		"SELECT u.review_unit_id,u.assignment_epoch,u.title,u.objective,u.source_refs,u.depends_on,u.closure_criteria,u.source,u.status,u.stale FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND g.repo_id=?3",
		params![id,generation,repo],|r| {
			crate::ingress::require_agent_source(r,7)?;
			Ok((AssignedUnit{id:r.get(0)?,epoch:r.get(1)?,title:crate::ingress::title(r,2)?,objective:crate::ingress::objective(r,3)?,source_refs:crate::ingress::unit_refs(r,4)?,depends_on:crate::ingress::admission_dependencies(r,5)?,closure_criteria:crate::ingress::optional_closure_criteria(r,6)?},crate::review::parsed::<crate::review_units::Status>(r,8)?,r.get::<_,bool>(9)?))
		})?;
	if stale
		|| (status != crate::review_units::Status::Open
			&& !(epoch.is_none() && status == crate::review_units::Status::Deferred))
		|| epoch.is_some_and(|e| e != unit.epoch)
	{
		return Err(invalid());
	}
	crate::inventory::verify_refs_raw(tx, repo, generation, unit.source_refs.as_slice())?;
	for (position, dependency) in unit.depends_on.iter().enumerate() {
		if *dependency <= 0 || *dependency == id || unit.depends_on[..position].contains(dependency)
		{
			return Err(invalid());
		}
		let belongs:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",params![dependency,generation],|r|r.get(0))?;
		if !belongs {
			return Err(invalid());
		}
	}
	if epoch.is_none() {
		unit.epoch = unit.epoch.checked_add(1).ok_or_else(invalid)?;
	}
	if id <= 0 || unit.epoch == 0 {
		return Err(invalid());
	}
	Ok(unit)
}
pub(super) fn lead_snapshot<E: From<Error>>(
	tx: &Transaction<'_>, id: i64, plan: &Planned,
) -> Result<PhaseSubject, E> {
	let meta = crate::leads::get_metadata_raw(tx, plan.repo, id)?.ok_or_else(invalid)?;
	if Some(meta.generation_id) != plan.generation
		|| meta.commit_sha.expose() != plan.context.target_commit.expose()
	{
		return Err(invalid());
	}
	let producer = meta.created_by_job.ok_or_else(invalid)?;
	let provenance:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND generation_id=?3 AND campaign_id IS NOT NULL AND kind IN('survey','drilldown') AND head_sha=?4 AND workflow_contract_version=?5)",params![producer,plan.repo,meta.generation_id,meta.commit_sha.expose(),WORKFLOW_CONTRACT_VERSION],|r|r.get(0))?;
	if !provenance {
		return Err(invalid());
	}
	let StoredEvidence::Recorded(evidence) = crate::leads::get_evidence_raw(tx, plan.repo, id)?
	else {
		return Err(Failure::Defect(Reason::CompatibilityPolicy));
	};
	crate::inventory::verify_refs_raw(
		tx,
		plan.repo,
		meta.generation_id,
		evidence.source_refs.as_slice(),
	)?;
	let commit=tx.query_row("SELECT commit_sha FROM leads WHERE lead_id=?1 AND generation_id=?2 AND EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?2 AND repo_id=?3)",params![id,meta.generation_id,plan.repo],|r|crate::ingress::profile::commit(r,0))?;
	Ok(PhaseSubject::Lead { id, commit, evidence })
}
pub(super) fn finding_snapshot<E: From<Error>>(
	tx: &Transaction<'_>, id: i64, plan: &Planned,
) -> Result<PhaseSubject, E> {
	let StoredEvidence::Recorded(details) =
		crate::finding_details::read_review_evidence_raw(tx, plan.repo, id)?
	else {
		return Err(Failure::Defect(Reason::CompatibilityPolicy));
	};
	let generation = plan.generation.ok_or_else(invalid)?;
	let profile = profile_snapshot(tx, plan.repo, generation)?.ok_or_else(invalid)?;
	let digest = tx.query_row(
		"SELECT profile_digest FROM finding_review_details WHERE finding_id=?1 AND repo_id=?2",
		params![id, plan.repo],
		|r| crate::ingress::profile::digest(r, 0),
	)?;
	if details.repo_id != plan.repo
		|| details.workflow_contract_version != WORKFLOW_CONTRACT_VERSION
		|| details.reviewed_commit_sha.expose() != plan.context.target_commit.expose()
		|| details.profile_version != i64::from(profile.version.get())
		|| digest != profile.digest
	{
		return Err(invalid());
	}
	let refs: Vec<_> = details
		.evidence
		.material_locations
		.as_slice()
		.iter()
		.map(|l| SourceRef { path: l.file.clone(), symbol: None })
		.collect();
	crate::inventory::verify_refs_raw(tx, plan.repo, generation, &refs)?;
	let (severity, title, description) = tx.query_row(
		"SELECT severity,title,description,source FROM findings WHERE id=?1 AND repo_id=?2",
		params![id, plan.repo],
		|r| {
			crate::ingress::require_agent_source(r, 3)?;
			Ok((
				crate::review::parsed(r, 0)?,
				crate::ingress::review_finding_title(r, 1)?,
				crate::ingress::review_finding_description(r, 2)?,
			))
		},
	)?;
	let commit = tx.query_row(
		"SELECT reviewed_commit_sha FROM finding_review_details WHERE finding_id=?1 AND repo_id=?2",
		params![id, plan.repo],
		|r| crate::ingress::profile::commit(r, 0),
	)?;
	Ok(PhaseSubject::Finding { id, commit, severity, title, description, details })
}

pub(super) fn snapshot<E: From<Error>>(
	tx: &Transaction<'_>, job: &crate::jobs::JobRow,
	policy: &mut impl FnMut(
		Phase,
		&Context,
		RecipeInput<'_>,
	) -> std::result::Result<RecipeDecision, CallbackError<E>>,
) -> Result<DeliverySnapshot, E> {
	let repository = crate::repos::get_raw(tx, job.repo_id)?.ok_or_else(invalid)?;
	let mut head_branch = repository.default_branch.clone();
	let mut target = None;
	let mut reviewed_revision = None;
	let phase = if job.campaign_id.is_some() {
		let plan = validation::planned(tx, job.repo_id, Source::Job(job.id), policy)?
			.ok_or_else(invalid)?;
		if plan.generation.is_none() {
			head_branch=Some(tx.query_row("SELECT target_commit_sha FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",params![plan.campaign,plan.repo],|r|crate::ingress::branch(r,0))?);
		}
		let generation=plan.generation.map(|id|tx.query_row("SELECT generation_commit_sha FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![id,plan.repo],|r|crate::ingress::profile::commit(r,0)).map(|commit|(id,commit))).transpose()?;
		let profile =
			plan.generation.map(|id| profile_snapshot(tx, plan.repo, id)).transpose()?.flatten();
		let subject = match plan.phase {
			Phase::Survey => PhaseSubject::Survey(
				if plan.recipe == RecipeDecision::Bootstrap || plan.generation.is_none() {
					Vec::new()
				} else {
					assignment_snapshot(
						tx,
						plan.repo,
						job.id,
						plan.generation.ok_or_else(invalid)?,
					)?
				},
			),
			Phase::Drilldown => {
				lead_snapshot(tx, job.assigned_lead_id.ok_or_else(invalid)?, &plan)?
			},
			Phase::Verify => {
				finding_snapshot(tx, job.target_finding_id.ok_or_else(invalid)?, &plan)?
			},
		};
		Some(PhaseDelivery {
			recipe: plan.recipe,
			policy: crate::admission::load_policy_raw(tx, plan.repo, plan.campaign)?,
			generation,
			profile,
			subject,
		})
	} else {
		if crate::jobs::targets_phase_finding(tx, job.repo_id, job.id)? {
			return Err(Failure::Defect(Reason::CompatibilityPolicy));
		}
		match job.kind {
			JobKind::Scan => {},
			JobKind::Verify => {
				let id = job.target_finding_id.ok_or_else(invalid)?;
				let finding = tx.query_row(
					&format!(
						"SELECT {} FROM findings WHERE id=?1 AND repo_id=?2",
						crate::findings::FINDING_COLUMNS
					),
					params![id, job.repo_id],
					crate::findings::row_to_finding,
				)?;
				let reviewed = crate::jobs::get_scoped_raw(
					tx,
					job.repo_id,
					job.parent_job_id.unwrap_or(finding.job_id),
				)?;
				reviewed_revision =
					reviewed.and_then(|j| if j.kind == JobKind::Scan { j.head_sha } else { None });
				target = Some(finding);
			},
			_ => return Err(invalid()),
		}
		None
	};
	Ok(DeliverySnapshot {
		job: job.clone(),
		repository,
		head_branch,
		phase,
		target,
		reviewed_revision,
	})
}
