//! Pure closed terminal-summary wire projections.
use loupe_proto::review_terminal as wire;
use loupe_storage::review_authority as stored;

pub(crate) fn continuation(value: stored::ContinuationSummary) -> wire::ContinuationSummary {
	match value {
		stored::ContinuationSummary::Pending { class, revision, logical_sequence, not_before } => {
			wire::ContinuationSummary::Pending { class, revision, logical_sequence, not_before }
		},
		stored::ContinuationSummary::Blocked { class, revision, logical_sequence, reason } => {
			wire::ContinuationSummary::Blocked {
				class,
				revision,
				logical_sequence,
				reason: match reason {
					stored::ContinuationBlockReason::AwaitingProofInfrastructure => {
						wire::ContinuationBlockReason::AwaitingProofInfrastructure
					},
					stored::ContinuationBlockReason::ExternalDependency => {
						wire::ContinuationBlockReason::ExternalDependency
					},
					stored::ContinuationBlockReason::RequiresSuccessor => {
						wire::ContinuationBlockReason::RequiresSuccessor
					},
				},
			}
		},
	}
}
