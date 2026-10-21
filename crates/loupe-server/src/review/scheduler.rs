//! Complete bounded delivery stays inside storage's claim transaction.
use axum::response::Response;
use loupe_core::JobKind;
use loupe_proto::{LeasePayload, LeaseResponse};
use loupe_provenance::Worker;
use loupe_storage::admission_claim::{self, CallbackError, DeliveryRequest, Incompatibility};

use crate::auth::AuthedWorker;
use crate::state::AppState;

pub const PHASE_LEASE_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

pub fn claim_for_worker(
	state: &AppState, worker: &AuthedWorker, legacy_kinds: &[JobKind<Worker>],
	phase_kinds: &[JobKind<Worker>], repairs_left: &mut u32,
) -> super::http::Result<Option<Response>> {
	let ingress = worker.worker_ingress().ok_or_else(super::http::ApiError::denied)?;
	let (capability, hash) = crate::job_capability::issue();
	Ok(admission_claim::claim_with_delivery(
		&state.db,
		&ingress,
		&DeliveryRequest {
			worker_id: worker.id(),
			legacy_kinds,
			phase_kinds,
			policy: &state.review_policy.claim_policy(),
			capability_hash: &hash,
			legacy_lease_seconds: loupe_storage::jobs::DEFAULT_LEASE_SECONDS,
		},
		|| {
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap_or_default()
				.as_secs() as i64
		},
		repairs_left,
		&mut super::authority::admission_policy,
		&mut |snapshot| {
			let envelope = super::envelope::delivery(snapshot, capability.clone())
				.map_err(|_| CallbackError::Incompatible(Incompatibility::InvalidData))?;
			// Phase bounds must not make existing legacy work undeliverable.
			let limit = match &envelope.payload {
				LeasePayload::Scan { .. } | LeasePayload::Verify { .. } => {
					loupe_http::MAX_RESPONSE_BYTES
				},
				LeasePayload::ReviewSurvey(_)
				| LeasePayload::ReviewDrilldown(_)
				| LeasePayload::ReviewVerify(_) => PHASE_LEASE_RESPONSE_LIMIT,
			};
			let encoded = LeaseResponse::Lease(Box::new(envelope))
				.credential_json_bounded(limit)
				.map_err(|_| CallbackError::Incompatible(Incompatibility::InvalidData))?;
			Ok(crate::routes::credential_response::encoded_lease(encoded))
		},
	)?)
}
