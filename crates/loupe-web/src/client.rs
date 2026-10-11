//! Typed client for the `loupe-server` admin RPCs.
//!
//! Modelled on `loupe-worker`'s client rather than `loupectl`'s: it sends
//! `X-Loupe-Protocol` on every request *and* validates it on every
//! response, and folds the response body into its errors. Both matter for
//! a UI — server errors are plain text, not JSON, so the body is the only
//! useful message, and a protocol cutover should surface as one clear
//! banner instead of a wall of opaque 400s.

use anyhow::{Context, Result};
use loupe_http::read_response_bytes;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use reqwest::{Method, StatusCode, Url};

/// An upstream call that failed. Keeps the status so the dashboard can
/// pass a meaningful code back to the browser rather than flattening
/// everything to 500.
#[derive(Debug)]
pub struct UpstreamError {
	pub status: Option<StatusCode>,
	pub message: String,
}

impl std::fmt::Display for UpstreamError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.status {
			Some(status) => write!(f, "{status}: {}", self.message),
			None => f.write_str(&self.message),
		}
	}
}

impl std::error::Error for UpstreamError {}

impl UpstreamError {
	fn transport(message: String) -> Self {
		Self { status: None, message }
	}
}

pub type UpstreamResult<T> = std::result::Result<T, UpstreamError>;

/// Admin-authenticated client. Holds the mTLS identity; every method is a
/// thin pass-through so the dashboard never invents its own semantics.
#[derive(Clone)]
pub struct AdminClient {
	http: reqwest::Client,
	base: Url,
}

impl AdminClient {
	/// Build from PEM material. Pins the private loupe CA as an additional
	/// root and presents the admin cert; certificate verification stays on.
	pub fn new(base: Url, ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<Self> {
		let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
		combined.push_str(cert_pem);
		if !cert_pem.ends_with('\n') {
			combined.push('\n');
		}
		combined.push_str(key_pem);

		let identity = reqwest::Identity::from_pem(combined.as_bytes())
			.context("parsing admin identity from cert + key PEM")?;
		let root =
			reqwest::Certificate::from_pem(ca_pem.as_bytes()).context("parsing CA cert PEM")?;
		let http = reqwest::Client::builder()
			.add_root_certificate(root)
			.identity(identity)
			.use_rustls_tls()
			.build()
			.context("building reqwest client")?;
		Ok(Self { http, base })
	}

	/// Test-only constructor for a pre-built client (lets integration
	/// tests use `.resolve()` to reach an ephemeral port).
	pub fn from_parts(http: reqwest::Client, base: Url) -> Self {
		Self { http, base }
	}

	/// Perform an admin request and return the raw JSON body.
	///
	/// Everything the dashboard exposes is a proxy, so one generic method
	/// beats a hand-written wrapper per route: there is no place for the
	/// two to drift, and the browser gets the server's own JSON shapes.
	/// Returns the upstream status alongside the body so the proxy can pass
	/// it through rather than flattening every success to 200 — `201` on
	/// create and `204` on the mutating routes are both meaningful.
	pub async fn call(
		&self, method: Method, path: &str, query: &[(&str, String)],
		body: Option<serde_json::Value>,
	) -> UpstreamResult<(StatusCode, Option<serde_json::Value>)> {
		let mut url = self.base.join(path).map_err(|e| {
			UpstreamError::transport(format!("building upstream URL for {path}: {e}"))
		})?;
		if !query.is_empty() {
			// Built through `query_pairs_mut` so values are percent-encoded:
			// the search term is free-form operator input.
			let mut pairs = url.query_pairs_mut();
			for (name, value) in query {
				pairs.append_pair(name, value);
			}
		}
		let mut req = self
			.http
			.request(method, url)
			.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string());
		if let Some(body) = body {
			req = req.json(&body);
		}
		let resp = req
			.send()
			.await
			.map_err(|e| UpstreamError::transport(format!("upstream request failed: {e}")))?;

		let status = resp.status();
		if !status.is_success() {
			let bytes = read_response_bytes(resp).await.map_err(|error| UpstreamError {
				status: Some(status),
				message: format!("reading upstream body: {error}"),
			})?;
			let body = String::from_utf8_lossy(&bytes);
			let message = body.trim();
			let message = if message.is_empty() {
				format!("server returned {status}")
			} else {
				message.into()
			};
			return Err(UpstreamError { status: Some(status), message });
		}
		check_protocol_header(&resp)?;

		// 204 and empty bodies are normal on the mutating routes.
		let bytes = read_response_bytes(resp)
			.await
			.map_err(|e| UpstreamError::transport(format!("reading upstream body: {e}")))?;
		let text = String::from_utf8_lossy(&bytes);
		if text.trim().is_empty() {
			return Ok((status, None));
		}
		serde_json::from_str(&text)
			.map(|value| (status, Some(value)))
			.map_err(|e| UpstreamError::transport(format!("upstream sent invalid JSON: {e}")))
	}

	/// GET a path and deserialize into `T`. Used for the few places the
	/// dashboard itself needs to understand a response.
	pub async fn get_typed<T: serde::de::DeserializeOwned>(&self, path: &str) -> UpstreamResult<T> {
		let (_, value) = self.call(Method::GET, path, &[], None).await?;
		let value = value
			.ok_or_else(|| UpstreamError::transport(format!("{path} returned an empty body")))?;
		serde_json::from_value(value)
			.map_err(|e| UpstreamError::transport(format!("decoding {path}: {e}")))
	}

	/// Stamp `protocol_version` into an outgoing body.
	///
	/// Every admin request DTO carries the field, and the server rejects a
	/// mismatch with a 400. Filling it in here means the browser never
	/// sends a version and cannot get it wrong.
	pub fn with_protocol_version(mut body: serde_json::Value) -> serde_json::Value {
		if let Some(map) = body.as_object_mut() {
			map.insert("protocol_version".to_owned(), serde_json::Value::from(PROTOCOL_VERSION));
		}
		body
	}

	/// Unauthenticated liveness probe. Returns the server's protocol
	/// version so the UI can diagnose a mismatch explicitly.
	pub async fn health(&self) -> UpstreamResult<serde_json::Value> {
		self.get_typed("/v1/health").await
	}
}

/// Reject a response whose protocol header is missing or disagrees with
/// this build. `loupectl` skips this check; the worker does it, and for a
/// long-running dashboard it is the difference between one actionable
/// banner and every action failing for no visible reason.
fn check_protocol_header(resp: &reqwest::Response) -> UpstreamResult<()> {
	let header = resp.headers().get(PROTOCOL_VERSION_HEADER).ok_or_else(|| {
		UpstreamError::transport(format!("server response missing {PROTOCOL_VERSION_HEADER}"))
	})?;
	let server_version = header
		.to_str()
		.map_err(|_| UpstreamError::transport("server protocol header is not ASCII".into()))?
		.parse::<u16>()
		.map_err(|_| UpstreamError::transport("server protocol header is not a u16".into()))?;
	if server_version != PROTOCOL_VERSION {
		return Err(UpstreamError::transport(format!(
			"server speaks protocol {server_version}, this loupe-web build speaks \
			 {PROTOCOL_VERSION} — rebuild loupe-web against the running server"
		)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn protocol_version_is_stamped_into_an_object() {
		let body = AdminClient::with_protocol_version(serde_json::json!({"incremental": true}));
		assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
		assert_eq!(body["incremental"], true);
	}

	#[test]
	fn a_client_supplied_protocol_version_is_overwritten() {
		// The browser must not be able to talk a different protocol than
		// the build it is served from.
		let body =
			AdminClient::with_protocol_version(serde_json::json!({"protocol_version": 9999}));
		assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
	}

	#[test]
	fn non_objects_pass_through_unchanged() {
		let body = AdminClient::with_protocol_version(serde_json::json!([1, 2, 3]));
		assert_eq!(body, serde_json::json!([1, 2, 3]));
	}

	#[test]
	fn upstream_error_renders_status_and_body() {
		let err = UpstreamError {
			status: Some(StatusCode::CONFLICT),
			message: "job 3 is Succeeded, not queued or leased".into(),
		};
		let rendered = err.to_string();
		assert!(rendered.contains("409"));
		assert!(rendered.contains("not queued or leased"));
	}

	#[test]
	fn transport_error_renders_without_a_status() {
		let err = UpstreamError::transport("upstream request failed: connection refused".into());
		assert_eq!(err.to_string(), "upstream request failed: connection refused");
	}
}
