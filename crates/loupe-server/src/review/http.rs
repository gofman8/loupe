//! Shared phase transport boundaries. Serialize the bounded response before
//! committing the same transaction that granted authority or changed state.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
use loupe_storage::review_authority::PhaseTransaction;
use loupe_storage::Db;
use serde::Serialize;

use super::authority;
use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;

pub type Result<T> = std::result::Result<T, ApiError>;

// debug-ok: status and error code are closed host metadata, never input text.
#[derive(Debug)]
pub struct ApiError {
	status: StatusCode,
	code: &'static str,
	current_revision: Option<i64>,
}
impl ApiError {
	pub fn new(status: StatusCode, code: &'static str) -> Self {
		Self { status, code, current_revision: None }
	}
	pub fn denied() -> Self {
		Self::new(StatusCode::FORBIDDEN, "denied")
	}
	pub fn conflict(code: &'static str) -> Self {
		Self::new(StatusCode::CONFLICT, code)
	}
	/// Only a repository/entry-scoped storage conflict supplies this scalar.
	fn inventory_revision_conflict(current_revision: i64) -> Self {
		Self {
			current_revision: Some(current_revision),
			..Self::conflict("inventory_revision_conflict")
		}
	}
	pub fn invalid(_detail: impl std::fmt::Display) -> Self {
		// Decoder diagnostics can contain arbitrary input keys and tokens.
		Self::new(StatusCode::BAD_REQUEST, "invalid_request")
	}
}
impl From<loupe_storage::Error> for ApiError {
	fn from(error: loupe_storage::Error) -> Self {
		use loupe_storage::{Conflict, Error};
		match error {
			Error::ScopeDenied | Error::Ownership(_) | Error::NotFound(_, _) => Self::denied(),
			Error::Conflict(Conflict::Checkpoint) => Self::conflict("checkpoint_conflict"),
			Error::Conflict(Conflict::CheckpointLimit) => Self::conflict("checkpoint_limit"),
			Error::Conflict(Conflict::UnitResultExists) => Self::conflict("unit_result_exists"),
			Error::Conflict(Conflict::IncompatibleReviewState) => {
				Self::conflict("incompatible_review_state")
			},
			Error::Conflict(Conflict::Limits) => Self::conflict("invalid_limits"),
			Error::Conflict(Conflict::CompatibilityPolicy) => {
				Self::conflict("compatibility_policy")
			},
			Error::Conflict(Conflict::InventoryLimit) => Self::conflict("inventory_limit"),
			Error::Conflict(Conflict::InventoryRevision(revision)) => {
				Self::inventory_revision_conflict(revision)
			},
			Error::Conflict(Conflict::CampaignPinned) => Self::conflict("checkout_conflict"),
			Error::Conflict(_) => Self::conflict("state_conflict"),
			Error::Validation(error) => Self::invalid(error),
			Error::ReviewPayload(error) => Self::invalid(error),
			Error::UnknownPaths(_) => Self::invalid("source outside pinned inventory"),
			error => {
				tracing::error!(error = %error, "phase transaction failed");
				Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
			},
		}
	}
}
impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let mut error = serde_json::json!({"code":self.code,"detail":null});
		if let Some(revision) = self.current_revision {
			error["current_revision"] = serde_json::json!(revision);
		}
		let mut response = (
			self.status,
			axum::Json(serde_json::json!({
				"protocol_version": PROTOCOL_VERSION,
				"error": error
			})),
		)
			.into_response();
		response
			.headers_mut()
			.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
		response
	}
}

pub fn require_version(headers: &HeaderMap) -> Result<()> {
	let mut versions = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
	let valid = versions.next().is_some_and(|value| {
		value.to_str().ok().and_then(|raw| raw.parse::<u16>().ok()) == Some(PROTOCOL_VERSION)
	});
	if !valid || versions.next().is_some() {
		return Err(ApiError::invalid("one exact X-Loupe-Protocol header is required"));
	}
	Ok(())
}

/// Use the registered matched path, not arbitrary URI suffixes. The outer
/// boundary must include role middleware and extractor rejections too.
pub fn is_phase_route(path: &str) -> bool {
	matches!(
		path,
		"/v1/jobs/{id}/pin-target"
			| "/v1/jobs/{id}/inventory-batches"
			| "/v1/jobs/{id}/seal-inventory"
			| "/v1/jobs/{id}/publish-profile"
			| "/v1/jobs/{id}/inventory-dispositions"
			| "/v1/jobs/{id}/review-units"
			| "/v1/jobs/{id}/leads"
			| "/v1/jobs/{id}/sibling-leads"
			| "/v1/jobs/{id}/review-unit-results"
			| "/v1/jobs/{id}/finalize-survey"
			| "/v1/jobs/{id}/finalize-drilldown"
			| "/v1/jobs/{id}/limits"
			| "/v1/jobs/{id}/lead-candidates"
	)
}

pub async fn bound_phase_errors(response: Response) -> Response {
	if !response.status().is_client_error() && !response.status().is_server_error() {
		return response;
	}
	let (mut parts, body) = response.into_parts();
	let json = parts
		.headers
		.get(header::CONTENT_TYPE)
		.is_some_and(|value| value.as_bytes() == b"application/json");
	if json && let Ok(bytes) = to_bytes(body, 4096).await {
		parts.headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
		return Response::from_parts(parts, Body::from(bytes));
	}
	// Never echo an extractor's arbitrary-size untrusted path or middleware
	// text. Preserve its status, with the same bounded structured vocabulary.
	let code = match parts.status {
		StatusCode::UNAUTHORIZED => "unauthenticated",
		StatusCode::FORBIDDEN => "denied",
		StatusCode::NOT_FOUND => "not_found",
		StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
		StatusCode::PAYLOAD_TOO_LARGE => "request_too_large",
		StatusCode::BAD_REQUEST => "invalid_request",
		_ => "request_failed",
	};
	ApiError::new(parts.status, code).into_response()
}

/// Validate the already captured request, without bypassing worker quotas or
/// copying the body into a second unguarded plaintext buffer.
pub fn body(headers: &HeaderMap, body: WorkerBody, max_bytes: usize) -> Result<WorkerBody> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	if !headers.get(header::CONTENT_TYPE).is_some_and(|value| {
		value.to_str().is_ok_and(|raw| {
			raw.split(';').next().is_some_and(|mime| mime.trim() == "application/json")
		})
	}) {
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type"));
	}
	body.0.as_bytes().validate(BodyLimit(max_bytes))?;
	Ok(body)
}
/// Context GETs use the same quota-charged capture as phase writes. They have
/// no media-type requirement, but reject any actual body or content encoding.
pub fn no_body(headers: &HeaderMap, body: WorkerBody) -> Result<()> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	body.0.as_bytes().validate(BodyLimit(0)).map_err(|_| ApiError::invalid("GET has no body"))
}

struct BodyLimit(usize);
impl Validate<&[u8], Worker> for BodyLimit {
	type Output = ();
	type Error = ApiError;
	fn validate<'v>(self, input: Unvalidated<'v, &[u8]>, _: Mark<'v, Worker>) -> Result<()> {
		if input.get().len() > self.0 {
			Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"))
		} else {
			Ok(())
		}
	}
}

struct BoundedBody {
	bytes: Vec<u8>,
	limit: usize,
}
impl Write for BoundedBody {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(std::io::Error::other("phase response exceeds its byte limit"));
		}
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

/// The result is serialized under the write lock. A response overflow or any
/// operation error drops the uncommitted transaction, including prior writes.
pub fn transaction<T: Serialize>(
	db: &Db, worker: &AuthedWorker, headers: &HeaderMap, job: i64, response_limit: usize,
	body: impl for<'tx> FnOnce(&mut PhaseTransaction<'tx>) -> Result<T>,
) -> Result<Response> {
	authority::with_transaction(
		db,
		worker,
		headers,
		job,
		|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
		|tx| {
			let value = body(tx)?;
			let mut output = BoundedBody { bytes: Vec::new(), limit: response_limit };
			serde_json::to_writer(&mut output, &value).map_err(|_| {
				ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "response_too_large")
			})?;
			Ok::<_, ApiError>(
				(
					[
						(header::CONTENT_TYPE, "application/json"),
						(header::CACHE_CONTROL, "no-store"),
					],
					output.bytes,
				)
					.into_response(),
			)
		},
	)?
	.ok_or_else(ApiError::denied)
}

#[cfg(test)]
mod tests {
	use loupe_proto::review_api::SealInventoryRequestDecoder;

	use super::*;

	fn headers() -> HeaderMap {
		let mut headers = HeaderMap::new();
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
		headers
	}

	#[tokio::test]
	async fn limits_count_actual_bytes_without_a_content_length() {
		let headers = headers();
		let raw = " ".repeat(2048) + r#"{"protocol_version":3}"#;
		let err =
			body(&headers, crate::test_support::worker_body(raw.as_bytes()), 2048).err().unwrap();
		assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
		let captured =
			body(&headers, crate::test_support::worker_body(br#"{"protocol_version":3}"#), 2048)
				.ok()
				.unwrap();
		assert!(captured.0.as_bytes().validate(SealInventoryRequestDecoder).is_ok());
	}

	#[tokio::test]
	async fn phase_transport_rejects_missing_version_and_encoded_bodies() {
		let mut headers = headers();
		headers.remove(PROTOCOL_VERSION_HEADER);
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.append(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
		assert_eq!(
			body(&headers, crate::test_support::worker_body(b""), 2048).err().unwrap().status,
			StatusCode::UNSUPPORTED_MEDIA_TYPE
		);
	}

	#[tokio::test]
	async fn phase_errors_never_echo_untrusted_diagnostics() {
		let response = ApiError::invalid("SECRET_PHASE_DIAGNOSTIC").into_response();
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(
			!String::from_utf8_lossy(&bytes).contains("SECRET_PHASE_DIAGNOSTIC"),
			"phase error echoed untrusted diagnostic"
		);
	}
	#[test]
	fn context_get_admits_empty_capture_without_media_type() {
		let mut headers = headers();
		headers.remove(header::CONTENT_TYPE);
		assert!(no_body(&headers, crate::test_support::worker_body(b"")).is_ok());
		assert_eq!(
			no_body(&headers, crate::test_support::worker_body(b" ")).unwrap_err().status,
			StatusCode::BAD_REQUEST
		);
		headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
		assert_eq!(
			no_body(&headers, crate::test_support::worker_body(b"")).unwrap_err().status,
			StatusCode::UNSUPPORTED_MEDIA_TYPE
		);
	}
	#[test]
	fn context_gets_share_the_registered_phase_error_boundary() {
		assert!(is_phase_route("/v1/jobs/{id}/limits"));
		assert!(is_phase_route("/v1/jobs/{id}/lead-candidates"));
		assert!(!is_phase_route("/v1/repos/{id}/lead-candidates"));
		assert!(!is_phase_route("/arbitrary/limits"));
	}
	#[test]
	fn scope_denial_is_not_an_internal_error() {
		assert_eq!(
			ApiError::from(loupe_storage::Error::ScopeDenied).status,
			StatusCode::FORBIDDEN,
			"phase scope denial must be forbidden"
		);
	}
}
