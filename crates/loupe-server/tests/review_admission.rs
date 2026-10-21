//! Real HTTP regression guards for the shared lease transaction boundary.
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use loupe_proto::PROTOCOL_VERSION;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tower::Service;

mod common;

struct Fixture {
	state: AppState,
	peer: PeerCert,
	offline: common::offline::OfflineDatabase,
}

fn fixture() -> Fixture {
	fixture_with_scanner("null")
}

fn fixture_with_scanner(scanner: &str) -> Fixture {
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let mut repo = common::new_repo();
	repo.scanner_config = common::marked::scanner_config(scanner);
	assert_eq!(common::register_repo(&db, &repo, None), 1);
	let ca = Ca::new("admission-tests").unwrap();
	let cert = ca.mint_client("worker").unwrap();
	let peer =
		PeerCert(CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes()).next().unwrap().unwrap());
	registry::register_worker(
		&db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("worker"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		0,
	)
	.unwrap();
	Fixture {
		state: AppState::new(
			db,
			Arc::new(ca),
			Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
		),
		peer,
		offline,
	}
}

async fn lease(f: &Fixture) -> (StatusCode, Value, usize) {
	lease_with_reviews(f, &[]).await
}

async fn lease_with_reviews(f: &Fixture, reviews: &[&str]) -> (StatusCode, Value, usize) {
	let mut req = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from(
			json!({"protocol_version":PROTOCOL_VERSION,"capabilities":["verify:llm"],"review_capabilities":reviews,"wait_seconds":0})
				.to_string(),
		))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	let status = response.status();
	let bytes = to_bytes(response.into_body(), loupe_http::MAX_RESPONSE_BYTES).await.unwrap();
	(
		status,
		serde_json::from_slice(&bytes)
			.unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
		bytes.len(),
	)
}

#[tokio::test]
async fn unreadable_legacy_envelope_is_quarantined_before_any_lease_commits() {
	let f = fixture();
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'verify','queued',0),(2,1,'scan','queued',1)",[])?;
		Ok(())
	}).unwrap();
	let (status, response, _) = lease(&f).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"A bad envelope must not strand its lease or poison healthy work: {response}"
	);
	assert_eq!(response["job_id"], 2);
	let bad = common::job(&f.state.db, 1, 1);
	assert_eq!(bad.state, loupe_core::JobState::Failed);
	assert_eq!(bad.attempts, 0);
	assert!(bad.worker_id.is_none() && bad.lease_expires_at.is_none());
}

#[tokio::test]
async fn canonical_target_is_not_delivered_through_legacy_verify() {
	let f = fixture();
	f.offline.external_corruption(|conn| {
		conn.execute_batch("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,state,effective_policy,effective_policy_digest,created_at) VALUES(1,1,'bootstrap','manual','main','finished','{}',zeroblob(32),0);
		INSERT INTO jobs(id,repo_id,kind,state,campaign_id,enqueued_at) VALUES(1,1,'drilldown','succeeded',1,0);
		INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity) VALUES(1,1,1,'review','high','Canonical finding','Evidence','canonical','validating',0,randomblob(16));
		INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,enqueued_at) VALUES(2,1,'verify','queued',1,0),(3,1,'scan','queued',NULL,1);")?;
		Ok(())
	}).unwrap();
	let (status, response, _) = lease(&f).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		response["job_id"], 3,
		"Canonical phase finding provenance must block legacy claim authority"
	);
	assert_eq!(common::job(&f.state.db, 1, 2).attempts, 0);
	assert_eq!(common::finding(&f.state.db, 1, 1).state, loupe_core::FindingState::Validating);
}

#[tokio::test]
async fn chunked_lease_body_is_bounded_before_claim() {
	let f = fixture();
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','queued',0)",
				[],
			)?;
			Ok(())
		})
		.unwrap();
	let mut body =
		json!({"protocol_version":PROTOCOL_VERSION,"capabilities":[],"wait_seconds":0}).to_string();
	body.push_str(&" ".repeat(8192));
	let mut req = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.header("transfer-encoding", "chunked")
		.body(Body::from(body))
		.unwrap();
	req.extensions_mut().insert(f.peer);
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(
		response.status(),
		StatusCode::PAYLOAD_TOO_LARGE,
		"actual bytes must be bounded without Content-Length"
	);
	assert_eq!(
		response.headers().get("cache-control").and_then(|v| v.to_str().ok()),
		Some("no-store")
	);
	assert!(to_bytes(response.into_body(), 4096).await.is_ok());
	assert_eq!(common::job(&f.state.db, 1, 1).attempts, 0);
}

#[tokio::test]
async fn lease_outer_auth_errors_are_bounded_and_noncacheable() {
	let f = fixture();
	let request = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from("{}"))
		.unwrap();
	let response = router(f.state).call(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	assert_eq!(
		response.headers().get("cache-control").and_then(|v| v.to_str().ok()),
		Some("no-store")
	);
	let body = to_bytes(response.into_body(), 4096).await.unwrap();
	assert_eq!(
		serde_json::from_slice::<Value>(&body).unwrap()["protocol_version"],
		PROTOCOL_VERSION
	);
}

#[tokio::test]
async fn long_poll_has_one_request_wide_quarantine_budget() {
	let f = fixture();
	f.offline.external_corruption(|conn| {
		for id in 1..=40 {conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(?1,1,'verify','queued',0)",[id])?;}
		Ok(())
	}).unwrap();
	let mut request = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from(
			json!({"protocol_version":PROTOCOL_VERSION,"capabilities":["verify:llm"],"wait_seconds":1})
				.to_string(),
		))
		.unwrap();
	request.extensions_mut().insert(f.peer);
	assert_eq!(router(f.state.clone()).call(request).await.unwrap().status(), StatusCode::OK);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE state='failed'", [], |r| r
					.get::<_, i64>(0))?,
				32,
				"long polling must not reset the permanent-repair budget"
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn small_escaped_lease_response_keeps_exact_content_and_commits_once() {
	let f = fixture();
	let description = "Small proof\nwith \"quotes\", \\ and exact bytes";
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','succeeded',0)",[])?;
		conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity) VALUES(1,1,1,'test','high','Bounded delivery',?1,'small-size','validating',0,randomblob(16))",[description])?;
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,enqueued_at) VALUES(2,1,'verify','queued',1,0)",[])?;
		Ok(())
	}).unwrap();
	let (status, response, bytes) = lease(&f).await;
	assert_eq!(status, StatusCode::OK);
	assert!(bytes <= 4 * 1024 * 1024);
	assert_eq!(response["job_id"], 2);
	assert_eq!(response["payload"]["finding"]["description"], description);
	assert!(response["github_pat"].is_null(), "delivery never exposes reporting credentials");
	let accepted = common::job(&f.state.db, 1, 2);
	assert_eq!(accepted.state, loupe_core::JobState::Leased);
	assert_eq!(accepted.attempts, 1);
	assert!(accepted.worker_id.is_some() && accepted.lease_expires_at.is_some());
	assert_eq!(common::finding(&f.state.db, 1, 1).state, loupe_core::FindingState::Validating);
}

#[tokio::test]
async fn escaped_legacy_verify_uses_client_ceiling_and_commits_once() {
	let f = fixture();
	let large =
		format!("Proof{}", "\n".repeat(loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES - 5));
	let small = "Small proof\nwith exact bytes";
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','succeeded',0)",[])?;
		for (id, description) in [(1, large.as_str()), (2, small)] {
			conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity) VALUES(?1,1,1,'test','high','Bounded delivery',?2,?3,'validating',0,randomblob(16))",rusqlite::params![id,description,format!("size-{id}")])?;
		}
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,enqueued_at) VALUES(2,1,'verify','queued',1,0),(3,1,'verify','queued',2,1)",[])?;
		Ok(())
	}).unwrap();
	// Both stored findings satisfy existing leaf bounds. Only the complete,
	// escaped lease response crosses the phase ceiling, not the legacy ceiling.
	assert_eq!(common::finding(&f.state.db, 1, 1).description.expose(), large);
	assert_eq!(common::finding(&f.state.db, 1, 2).description.expose(), small);
	let (status, response, bytes) = lease(&f).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(response["job_id"], 2, "legacy delivery must retain its client-compatible ceiling");
	assert!(bytes > 4 * 1024 * 1024 && bytes <= loupe_http::MAX_RESPONSE_BYTES);
	assert_eq!(response["payload"]["finding"]["description"], large);
	assert!(response["github_pat"].is_null());
	let accepted = common::job(&f.state.db, 1, 2);
	assert_eq!(accepted.state, loupe_core::JobState::Leased);
	assert_eq!(accepted.attempts, 1);
	assert!(accepted.worker_id.is_some() && accepted.lease_expires_at.is_some());
	let neighbor = common::job(&f.state.db, 1, 3);
	assert_eq!(neighbor.state, loupe_core::JobState::Queued);
	assert_eq!(neighbor.attempts, 0);
	for id in [1, 2] {
		assert_eq!(common::finding(&f.state.db, 1, id).state, loupe_core::FindingState::Validating);
	}
	assert_eq!(common::finding(&f.state.db, 1, 1).description.expose(), large);
}

fn expanded_scanner() -> String {
	let scanner = format!("{{\"opaque\":[{}]}}", vec!["1e15"; 250_000].join(","));
	assert!(scanner.len() + 1024 < 2 * 1024 * 1024, "fits registration with metadata");
	scanner
}

#[tokio::test]
async fn expanded_legacy_scan_uses_client_ceiling_and_commits_once() {
	let scanner: Value = serde_json::from_str(&expanded_scanner()).unwrap();
	assert!(scanner.to_string().len() > 4 * 1024 * 1024);
	let f = fixture_with_scanner(&expanded_scanner());
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','queued',0)",
				[],
			)?;
			Ok(())
		})
		.unwrap();
	let (status, response, bytes) = lease(&f).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(response["job_id"], 1, "accepted scanner configuration must remain deliverable");
	assert!(bytes > 4 * 1024 * 1024 && bytes <= loupe_http::MAX_RESPONSE_BYTES);
	assert_eq!(response["payload"]["kind"], "scan");
	assert_eq!(response["scanner_config"], scanner);
	let accepted = common::job(&f.state.db, 1, 1);
	assert_eq!(accepted.state, loupe_core::JobState::Leased);
	assert_eq!(accepted.attempts, 1);
	assert!(accepted.worker_id.is_some() && accepted.lease_expires_at.is_some());
}

#[tokio::test]
async fn phase_delivery_retains_the_smaller_ceiling() {
	use loupe_server::review::campaign;
	for scanner in ["null".to_owned(), expanded_scanner()] {
		let oversized = scanner != "null";
		let f = fixture_with_scanner(&scanner);
		let now =
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
				as i64;
		let job = common::with_repo(&f.state.db, 1, |scope| {
			let campaign::Opened::Created { job_id, .. } = campaign::open(
				scope,
				&campaign::OpenCampaign {
					trigger: loupe_storage::campaigns::Trigger::Manual,
					requested_ref: campaign::RequestedRef::Branch(&common::marked::operator::text(
						"main",
					)),
					base_sha: None,
					kind_hint: campaign::KindHint::Incremental,
				},
				&f.state.review_policy,
				now,
			)?
			else {
				panic!("created")
			};
			Ok(job_id)
		})
		.unwrap();
		let (status, response, bytes) = lease_with_reviews(&f, &["review:survey:v1"]).await;
		assert_eq!(status, StatusCode::OK);
		assert!(bytes <= 4 * 1024 * 1024);
		let stored = common::job(&f.state.db, 1, job);
		if oversized {
			assert!(response.get("job_id").is_none());
			assert_eq!(stored.state, loupe_core::JobState::Failed);
			assert_eq!(stored.attempts, 0);
			assert!(stored.worker_id.is_none() && stored.lease_expires_at.is_none());
		} else {
			assert_eq!(response["job_id"], job);
			assert_eq!(response["payload"]["kind"], "review_survey");
			assert_eq!(stored.state, loupe_core::JobState::Leased);
			assert_eq!(stored.attempts, 1);
		}
	}
}

#[tokio::test]
async fn legacy_above_client_ceiling_is_quarantined_without_blocking_neighbor() {
	let scanner = json!({"opaque":"x".repeat(loupe_http::MAX_RESPONSE_BYTES)}).to_string();
	let f = fixture_with_scanner(&scanner);
	let mut neighbor = common::new_repo();
	neighbor.repo = common::marked::operator::text("neighbor");
	neighbor.clone_url = common::marked::operator::text("https://github.com/example/neighbor.git");
	assert_eq!(common::register_repo(&f.state.db, &neighbor, None), 2);
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','queued',0),(2,2,'scan','queued',1)",[])?;
		Ok(())
	}).unwrap();
	let (status, response, bytes) = lease(&f).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(response["job_id"], 2, "unreadable delivery must not poison healthy work");
	assert!(bytes <= loupe_http::MAX_RESPONSE_BYTES);
	let rejected = common::job(&f.state.db, 1, 1);
	assert_eq!(rejected.state, loupe_core::JobState::Failed);
	assert_eq!(rejected.attempts, 0);
	assert!(rejected.worker_id.is_none() && rejected.lease_expires_at.is_none());
	assert_eq!(common::job(&f.state.db, 2, 2).attempts, 1);
}
