//! Bounded wire assembly from source-labelled storage snapshots. Conversion
//! runs under the phase transaction; incompatible derived state is not truncated.
use loupe_proto::review_api::{PinTargetResponse, ReviewProtocol};
use loupe_proto::review_lease::{
	AssignedReviewUnit, FrozenReviewProfile, LeaseList, ReviewAssignments, ReviewGeneration,
};
use loupe_provenance::{Agent, Db};
use loupe_storage::review_authority::ReviewPreparation;

use super::http::{ApiError, Result};

fn incompatible() -> ApiError {
	ApiError::conflict("incompatible_review_state")
}

pub fn preparation(snapshot: ReviewPreparation) -> Result<PinTargetResponse<Agent, Db>> {
	let assignments = snapshot.assignments.map(assignments).transpose()?;
	Ok(PinTargetResponse::Prepared {
		protocol_version: ReviewProtocol,
		generation: ReviewGeneration {
			generation_id: snapshot.generation_id.try_into().map_err(|_| incompatible())?,
			commit_sha: snapshot.commit,
		},
		profile: snapshot.profile.map(|profile| FrozenReviewProfile {
			profile_version: profile.version,
			profile_digest: profile.digest,
			profile: profile.profile,
		}),
		assignments,
	})
}

fn assignments(
	units: Vec<loupe_storage::review_authority::AssignedUnit>,
) -> Result<ReviewAssignments<Agent>> {
	let units = units
		.into_iter()
		.map(|unit| {
			Ok(AssignedReviewUnit {
				review_unit_id: unit.id.try_into().map_err(|_| incompatible())?,
				assignment_epoch: unit.epoch.try_into().map_err(|_| incompatible())?,
				title: unit.title,
				objective: unit.objective,
				source_refs: LeaseList::new(unit.source_refs.as_slice().to_vec())
					.map_err(|_| incompatible())?,
				depends_on: LeaseList::new(
					unit.depends_on
						.into_iter()
						.map(|id| id.try_into().map_err(|_| incompatible()))
						.collect::<Result<Vec<_>>>()?,
				)
				.map_err(|_| incompatible())?,
				closure_criteria: unit.closure_criteria,
			})
		})
		.collect::<Result<Vec<_>>>()?;
	LeaseList::new(units).and_then(ReviewAssignments::try_from).map_err(|_| incompatible())
}

/// No database or external effects: this conversion and the credential encoder
/// both run before the owning claim transaction commits.
pub fn delivery(
	snapshot: loupe_storage::admission_claim::DeliverySnapshot,
	capability: loupe_proto::JobCapability,
) -> Result<loupe_proto::LeaseEnvelope<Agent, Db>> {
	use loupe_proto::review_lease::*;
	use loupe_proto::{LeaseEnvelope, LeasePayload, PROTOCOL_VERSION};
	use loupe_storage::admission_claim::{PhaseSubject, RecipeDecision};
	let job = snapshot.job;
	let repo = snapshot.repository;
	let payload = if let Some(phase) = snapshot.phase {
		let provenance = ReviewProvenance {
			workflow_contract_version: loupe_core::review_payload::Version1,
			campaign_id: job
				.campaign_id
				.ok_or_else(incompatible)?
				.try_into()
				.map_err(|_| incompatible())?,
			attempt: job.attempts.try_into().map_err(|_| incompatible())?,
			limits: ReviewLimits {
				soft_deadline_at: job.soft_deadline_at.ok_or_else(incompatible)?,
				submit_by: job.submit_by.ok_or_else(incompatible)?,
				hard_deadline_at: job.hard_deadline_at.ok_or_else(incompatible)?,
				token_budget: job
					.token_budget
					.map(|n| n.try_into().map_err(|_| incompatible()))
					.transpose()?,
				new_unit_limit: phase.policy.max_units_per_survey,
				lead_limit: phase.policy.max_leads_per_survey,
				sibling_limit: phase.policy.max_sibling_leads_per_drilldown,
			},
		};
		let generation = phase
			.generation
			.map(|(id, commit)| -> Result<_> {
				Ok(ReviewGeneration {
					generation_id: id.try_into().map_err(|_| incompatible())?,
					commit_sha: commit,
				})
			})
			.transpose()?;
		let profile = phase.profile.map(|p| FrozenReviewProfile {
			profile_version: p.version,
			profile_digest: p.digest,
			profile: p.profile,
		});
		match phase.subject {
			PhaseSubject::Survey(units) => {
				let context = match (phase.recipe, generation) {
					(RecipeDecision::Bootstrap, None) => {
						ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Unresolved {} }
					},
					(RecipeDecision::Bootstrap, Some(generation)) => {
						ReviewSurveyContext::Bootstrap {
							target: BootstrapTarget::Pinned {
								generation,
								published_profile: profile,
							},
						}
					},
					(RecipeDecision::Incremental, None) => ReviewSurveyContext::ResolveTarget {},
					(
						recipe @ (RecipeDecision::Coverage | RecipeDecision::Incremental),
						Some(generation),
					) => ReviewSurveyContext::Ordinary {
						generation,
						profile: profile.ok_or_else(incompatible)?,
						ordinary_recipe: if recipe == RecipeDecision::Coverage {
							OrdinarySurveyRecipe::Coverage
						} else {
							OrdinarySurveyRecipe::SameCommitIncremental
						},
						assignments: assignments(units)?,
					},
					_ => return Err(incompatible()),
				};
				LeasePayload::ReviewSurvey(Box::new(ReviewSurveyLease { provenance, context }))
			},
			PhaseSubject::Lead { id, commit, evidence } => {
				LeasePayload::ReviewDrilldown(Box::new(ReviewDrilldownLease {
					provenance,
					generation: generation.ok_or_else(incompatible)?,
					profile: profile.ok_or_else(incompatible)?,
					lead: AssignedReviewLead {
						lead_id: id.try_into().map_err(|_| incompatible())?,
						producer_commit_sha: commit,
						identity_family: evidence.identity_family,
						identity_anchor: evidence.identity_anchor,
						identity_instance_key: evidence.identity_instance_key,
						hypothesis: evidence.hypothesis,
						invariant_or_boundary: evidence.invariant_or_boundary,
						source_refs: LeaseList::new(evidence.source_refs.as_slice().to_vec())
							.map_err(|_| incompatible())?,
						next_proof_step: evidence.next_proof_step,
						counterevidence: evidence.counterevidence,
						proof_gaps: evidence.proof_gaps,
					},
				}))
			},
			PhaseSubject::Finding { id, commit, severity, title, description, details } => {
				LeasePayload::ReviewVerify(Box::new(ReviewVerifyLease {
					provenance,
					generation: generation.ok_or_else(incompatible)?,
					profile: profile.ok_or_else(incompatible)?,
					finding: AssignedReviewFinding {
						finding_id: id.try_into().map_err(|_| incompatible())?,
						reviewed_commit_sha: commit,
						severity,
						title,
						description,
						identity_family: details.identity.family,
						identity_anchor: details.identity.anchor,
						identity_instance_key: details.identity.instance,
						evidence: details.evidence,
					},
				}))
			},
		}
	} else {
		match job.kind {
			loupe_core::JobKind::Scan => LeasePayload::Scan { since_sha: job.since_sha },
			loupe_core::JobKind::Verify => LeasePayload::Verify {
				finding_id: job.target_finding_id.ok_or_else(incompatible)?,
				finding: Box::new(snapshot.target.ok_or_else(incompatible)?.into_finding()),
				reviewed_sha: snapshot.reviewed_revision,
			},
			_ => return Err(incompatible()),
		}
	};
	Ok(LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: job.id,
		job_capability: capability,
		repo_id: repo.id,
		repo: loupe_core::RepoSpec {
			host: repo.host,
			owner: repo.owner,
			repo: repo.repo,
			clone_url: repo.clone_url,
			branch: snapshot.head_branch.clone(),
		},
		head_branch: snapshot.head_branch,
		lease_expires_at: job.lease_expires_at.ok_or_else(incompatible)?,
		scanner_config: repo.scanner_config,
		github_pat: None,
		payload,
	})
}
