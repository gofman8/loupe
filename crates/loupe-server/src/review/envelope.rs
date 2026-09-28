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
	let assignments = snapshot
		.assignments
		.map(|units| {
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
		})
		.transpose()?;
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
