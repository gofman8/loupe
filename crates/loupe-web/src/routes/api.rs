//! JSON endpoints that proxy the `loupe-server` admin RPCs.
//!
//! Every route here is an explicit entry rather than a catch-all
//! forwarder. A wildcard proxy would let the browser reach any upstream
//! path — which the admin cert would happily authenticate — so the set of
//! reachable operations would be defined by whatever the page happened to
//! request rather than by this file. Query parameters are likewise
//! rebuilt from typed structs, not passed through, so the browser cannot
//! smuggle a parameter the server would honour.
//!
//! Request bodies get `protocol_version` stamped in by the client, so the
//! page never sends a version and cannot get it wrong.

use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::client::{AdminClient, UpstreamError};
use crate::state::WebState;

/// Axum's path/query rejections may repeat browser input. Keep these
/// diagnostics inside the same JSON envelope as upstream API errors.
pub(crate) async fn enclose_bad_request(response: Response) -> Response {
	if response.status() != StatusCode::BAD_REQUEST
		|| !response
			.headers()
			.get(axum::http::header::CONTENT_TYPE)
			.and_then(|value| value.to_str().ok())
			.is_some_and(|value| value.starts_with("text/plain"))
	{
		return response;
	}
	// Extractor errors are small; a pathological URI must not create an
	// unbounded second allocation merely to construct an error response.
	let error = match axum::body::to_bytes(response.into_body(), 16 * 1024).await {
		Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
		Err(_) => "invalid request".to_owned(),
	};
	(StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": error }))).into_response()
}

/// Translate an upstream failure into a response.
///
/// Upstream statuses are preserved where they are meaningful to the page —
/// a 409 on retry means "wrong state", a 404 means "gone" — because
/// flattening everything to 500 would leave the UI unable to say anything
/// useful. Errors bodies are plain text upstream, so wrap them in JSON for
/// uniform handling in the page.
fn upstream_error(err: UpstreamError) -> Response {
	let status = match err.status {
		// A 401/403 from upstream is about *our* admin cert, not the
		// browser's token. Reporting it verbatim would make the page
		// prompt for a token that is perfectly fine, so recast it.
		Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN) => StatusCode::BAD_GATEWAY,
		Some(status) => status,
		None => StatusCode::BAD_GATEWAY,
	};
	(status, Json(serde_json::json!({ "error": err.message }))).into_response()
}

/// Pass the upstream status through rather than flattening it. `201` on
/// repo/scan creation and `204` on the mutating routes both carry meaning,
/// and the page should see the same codes a `loupectl` user would.
fn ok(status: StatusCode, value: Option<serde_json::Value>) -> Response {
	match value {
		Some(value) => (status, Json(value)).into_response(),
		None => status.into_response(),
	}
}

async fn forward(
	state: &WebState, method: Method, path: &str, query: &[(&str, String)],
	body: Option<serde_json::Value>,
) -> Response {
	match state.client.call(method, path, query, body).await {
		Ok((status, value)) => ok(status, value),
		Err(err) => upstream_error(err),
	}
}

/// Stamp the protocol version and hand the body upstream.
fn body(value: Option<Json<serde_json::Value>>) -> Option<serde_json::Value> {
	let value = value.map(|Json(v)| v).unwrap_or_else(|| serde_json::json!({}));
	Some(AdminClient::with_protocol_version(value))
}

// ---------------------------------------------------------------- status

pub async fn health(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/health", &[], None).await
}

pub async fn whoami(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/whoami", &[], None).await
}

/// Read-only view of the server-wide GitHub App, so the page can tell
/// whether a PAT is optional. Setting or clearing the app stays a
/// `loupectl` job: the private key should never pass through a browser.
pub async fn github_app(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/github-app", &[], None).await
}

// ----------------------------------------------------------------- repos

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
	#[serde(default)]
	pub limit: Option<i64>,
}

impl LimitQuery {
	fn pairs(&self) -> Vec<(&'static str, String)> {
		self.limit.map(|n| vec![("limit", n.to_string())]).unwrap_or_default()
	}
}

pub async fn list_repos(State(state): State<WebState>, Query(q): Query<LimitQuery>) -> Response {
	forward(&state, Method::GET, "/v1/repos", &q.pairs(), None).await
}

pub async fn create_repo(
	State(state): State<WebState>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(&state, Method::POST, "/v1/repos", &[], body(payload)).await
}

pub async fn update_repo(
	State(state): State<WebState>, Path(id): Path<i64>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(&state, Method::PATCH, &format!("/v1/repos/{id}"), &[], body(payload)).await
}

pub async fn delete_repo(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::DELETE, &format!("/v1/repos/{id}"), &[], None).await
}

pub async fn rotate_repo_pat(
	State(state): State<WebState>, Path(id): Path<i64>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(
		&state,
		Method::POST,
		&format!("/v1/repos/{id}/reporting/github-pat"),
		&[],
		body(payload),
	)
	.await
}

pub async fn set_github_reporting(
	State(state): State<WebState>, Path(id): Path<i64>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(&state, Method::PUT, &format!("/v1/repos/{id}/reporting/github"), &[], body(payload))
		.await
}

pub async fn enqueue_scan(
	State(state): State<WebState>, Path(id): Path<i64>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/repos/{id}/scan"), &[], body(payload)).await
}

// ------------------------------------------------------------------ jobs

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
	#[serde(default)]
	pub limit: Option<i64>,
	#[serde(default)]
	pub state: Option<String>,
	#[serde(default)]
	pub kind: Option<String>,
}

pub async fn list_jobs(State(state): State<WebState>, Query(q): Query<JobsQuery>) -> Response {
	let mut pairs: Vec<(&'static str, String)> = Vec::new();
	if let Some(limit) = q.limit {
		pairs.push(("limit", limit.to_string()));
	}
	// Values are forwarded verbatim; the server validates them and returns
	// a 400 naming the accepted set, which the page surfaces as-is.
	if let Some(job_state) = q.state.filter(|s| !s.is_empty()) {
		pairs.push(("state", job_state));
	}
	if let Some(kind) = q.kind.filter(|s| !s.is_empty()) {
		pairs.push(("kind", kind));
	}
	forward(&state, Method::GET, "/v1/jobs", &pairs, None).await
}

pub async fn get_job(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::GET, &format!("/v1/jobs/{id}"), &[], None).await
}

pub async fn retry_job(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::POST, &format!("/v1/jobs/{id}/retry"), &[], None).await
}

pub async fn cancel_job(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::POST, &format!("/v1/jobs/{id}/cancel"), &[], None).await
}

// -------------------------------------------------------------- findings

pub async fn list_findings(
	State(state): State<WebState>, Path(repo_id): Path<i64>, Query(q): Query<LimitQuery>,
) -> Response {
	forward(&state, Method::GET, &format!("/v1/repos/{repo_id}/findings"), &q.pairs(), None).await
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
	pub q: String,
	#[serde(default)]
	pub limit: Option<i64>,
}

pub async fn search_findings(
	State(state): State<WebState>, Path(repo_id): Path<i64>, Query(q): Query<SearchQuery>,
) -> Response {
	let mut pairs = vec![("q", q.q)];
	if let Some(limit) = q.limit {
		pairs.push(("limit", limit.to_string()));
	}
	forward(&state, Method::GET, &format!("/v1/repos/{repo_id}/findings/search"), &pairs, None)
		.await
}

pub async fn get_finding(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::GET, &format!("/v1/findings/{id}"), &[], None).await
}

pub async fn approve_finding(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/approve"), &[], None).await
}

pub async fn reject_finding(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/reject"), &[], None).await
}

pub async fn retry_report_finding(State(state): State<WebState>, Path(id): Path<i64>) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/retry-report"), &[], None).await
}

pub async fn retry_verify(
	State(state): State<WebState>, payload: Option<Json<serde_json::Value>>,
) -> Response {
	forward(&state, Method::POST, "/v1/findings/retry-verify", &[], body(payload)).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_missing_body_becomes_an_object_with_the_protocol_version() {
		// The scan and retry-verify routes take an all-defaults body, so
		// the page is allowed to send nothing at all.
		let stamped = body(None).unwrap();
		assert_eq!(stamped["protocol_version"], loupe_proto::PROTOCOL_VERSION);
	}

	#[test]
	fn a_supplied_body_keeps_its_fields() {
		let stamped = body(Some(Json(serde_json::json!({"incremental": true})))).unwrap();
		assert_eq!(stamped["incremental"], true);
		assert_eq!(stamped["protocol_version"], loupe_proto::PROTOCOL_VERSION);
	}

	#[test]
	fn limit_query_is_omitted_when_absent() {
		assert!(LimitQuery { limit: None }.pairs().is_empty());
		assert_eq!(LimitQuery { limit: Some(50) }.pairs(), vec![("limit", "50".to_owned())]);
	}

	#[test]
	fn upstream_auth_failures_are_recast_as_bad_gateway() {
		// A 401 from the server means our admin cert is wrong, which is
		// not something the operator fixes by re-entering a token.
		for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
			let resp = upstream_error(UpstreamError { status: Some(status), message: "no".into() });
			assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{status} should be recast");
		}
	}

	#[test]
	fn meaningful_upstream_statuses_are_preserved() {
		for status in [StatusCode::NOT_FOUND, StatusCode::CONFLICT, StatusCode::BAD_REQUEST] {
			let resp =
				upstream_error(UpstreamError { status: Some(status), message: "why".into() });
			assert_eq!(resp.status(), status, "{status} should pass through");
		}
	}

	#[test]
	fn a_transport_failure_is_a_bad_gateway() {
		let resp = upstream_error(UpstreamError { status: None, message: "refused".into() });
		assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
	}

	#[test]
	fn the_upstream_success_status_is_preserved() {
		// A create returns 201 upstream; flattening it to 200 would hide a
		// distinction the CLI's users can see.
		assert_eq!(
			ok(StatusCode::CREATED, Some(serde_json::json!({"repo_id": 1}))).status(),
			StatusCode::CREATED
		);
		assert_eq!(ok(StatusCode::OK, Some(serde_json::json!({}))).status(), StatusCode::OK);
		assert_eq!(ok(StatusCode::NO_CONTENT, None).status(), StatusCode::NO_CONTENT);
	}
}
