use serde_json::{json, Value};

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
	QuarantineEmptyScan,
	QuarantineFindings,
	QuarantineScanError,
	QuarantineVerifier,
	ScannerError,
	CancelScan,
	Healthy,
	CancelDuringBatch,
	CancelVerifier,
}

struct OutcomeScanner {
	scenario: Scenario,
}
#[async_trait::async_trait]
impl Scanner for OutcomeScanner {
	fn id(&self) -> &'static str {
		"quarantine-fixture"
	}
	fn capabilities(&self) -> &[&'static str] {
		&["scan:fixture", "verify:fixture"]
	}
	async fn scan(&self, ctx: &ScanContext) -> Result<Vec<loupe_core::Finding<Repo>>> {
		if self.scenario == Scenario::ScannerError {
			anyhow::bail!("untrusted-scanner-error-sentinel");
		}
		let findings = if matches!(
			self.scenario,
			Scenario::QuarantineFindings
				| Scenario::CancelScan
				| Scenario::Healthy
				| Scenario::CancelDuringBatch
		) {
			let findings = crate::scanners::RegexSecretsScanner::new().scan(ctx).await?;
			assert_eq!(findings.len(), 1, "must exercise real nonempty batch path");
			findings
		} else {
			Vec::new()
		};
		if self.scenario == Scenario::CancelScan {
			ctx.cancel.cancel();
		}
		if matches!(
			self.scenario,
			Scenario::CancelScan | Scenario::Healthy | Scenario::CancelDuringBatch
		) {
			return Ok(findings);
		}
		assert!(ctx
			.security
			.observe(b"runner-quarantine-fixture", loupe_core::security_event::Broker::Mcp));
		if self.scenario == Scenario::QuarantineScanError {
			anyhow::bail!("untrusted-scanner-error-sentinel");
		}
		Ok(findings)
	}
	async fn verify(&self, ctx: &VerifyContext) -> Result<crate::VerifyOutcome> {
		if self.scenario == Scenario::CancelVerifier {
			ctx.cancel.cancel();
			return Ok(crate::VerifyOutcome::Host(HostVerifyReason::ScannerDoesNotVerify));
		}
		assert!(ctx
			.security
			.observe(b"runner-quarantine-fixture", loupe_core::security_event::Broker::Model));
		Ok(crate::VerifyOutcome::Host(HostVerifyReason::ScannerDoesNotVerify))
	}
}

async fn run(scenario: Scenario) -> Vec<(String, Value)> {
	let remote = tempfile::tempdir().unwrap();
	init_git_repo(remote.path());
	let revision = commit_file(remote.path(), "AKIAIOSFODNN7EXAMPLE\n", "Fixture");
	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_owned(), 1024 * 1024, None).unwrap());
	let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
	let received = calls.clone();
	let cancel = CancellationToken::new();
	let server_cancel = cancel.clone();
	let app = axum::Router::new().fallback(axum::routing::post(
		move |uri: axum::http::Uri, axum::Json(value): axum::Json<Value>| {
			let received = received.clone();
			let server_cancel = server_cancel.clone();
			async move {
				if scenario == Scenario::CancelDuringBatch && uri.path().ends_with("/findings") {
					server_cancel.cancel();
				}
				received.lock().unwrap().push((uri.path().to_owned(), value));
				(
					[(loupe_proto::PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
					axum::Json(json!({"protocol_version":PROTOCOL_VERSION})),
				)
			}
		},
	));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let payload = if matches!(scenario, Scenario::QuarantineVerifier | Scenario::CancelVerifier) {
		json!({"kind":"verify","finding_id":3,"reviewed_sha":revision,
		"finding":{"scanner_id":"test","severity":"low","title":"finding","description":"description","fingerprint":"fp"}})
	} else {
		json!({"kind":"scan"})
	};
	let wire = json!({"kind":"lease","protocol_version":PROTOCOL_VERSION,"job_id":7,"repo_id":9,
		"job_capability":"fixture-capability", "repo":{"host":"local","owner":"owner","repo":"repo",
		"clone_url":reqwest::Url::from_directory_path(remote.path()).unwrap().to_string()},
		"head_branch":"main", "lease_expires_at":i64::MAX,"scanner_config":null,"payload":payload});
	let receipt = crate::client::test_lease(&serde_json::to_vec(&wire).unwrap());
	let LeaseResponse::Lease(env) = receipt.response else { panic!("lease fixture") };
	let client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), url));
	let mut scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(OutcomeScanner { scenario })];
	if matches!(scenario, Scenario::ScannerError | Scenario::Healthy) {
		scanners.insert(0, Arc::new(crate::scanners::RegexSecretsScanner::new()));
	}
	let runner = Runner::new(client, cache, scanners).with_credential_watches(vec![
		crate::llm::model_broker::ModelCredential::anthropic_api_key("runner-quarantine-fixture")
			.watch(),
	]);
	runner
		.run_lease(*env, receipt.reviewed_revision, receipt.scanner_patch, &cancel)
		.await
		.unwrap();
	server.abort();
	calls.lock().unwrap().clone()
}

macro_rules! refuses {
	($name:ident,$scenario:ident) => {
		#[tokio::test]
		async fn $name() {
			let calls = run(Scenario::$scenario).await;
			assert_eq!(calls.len(), 1, "quarantine must permit only host Failed completion, without a verdict or finding POST");
			assert_eq!(calls[0].0, "/v1/jobs/7/complete");
			assert_eq!(calls[0].1, json!({"protocol_version":PROTOCOL_VERSION,"outcome":"failed","error":"injection_suspected"}), "quarantine must never become Succeeded or expose a scanner error");
		}
	};
}
refuses!(empty_scan_is_failed_after_quarantine, QuarantineEmptyScan);
refuses!(nonempty_scan_is_not_batch_posted_after_quarantine, QuarantineFindings);
refuses!(scan_error_is_replaced_by_fixed_quarantine_failure, QuarantineScanError);
refuses!(verify_fallback_is_not_posted_after_quarantine, QuarantineVerifier);

#[tokio::test]
async fn runner_diagnostics_omit_scanner_error_payloads() {
	if !crate::test_env::in_env(
		"runner::tests::quarantine_tests::runner_diagnostics_omit_scanner_error_payloads",
		"runner-i8",
		&[],
	) {
		return;
	}
	let capture = crate::test_support::LogCapture::default();
	capture.install();
	let calls = run(Scenario::ScannerError).await;
	assert_eq!(calls.len(), 1);
	assert_eq!(calls[0].0, "/v1/jobs/7/complete");
	assert_eq!(
		calls[0].1,
		json!({"protocol_version":PROTOCOL_VERSION,"outcome":"failed","error":"scanner failed"}),
		"a healthy scanner must not mask a fatal scanner error"
	);
	let logs = capture.text();
	assert!(logs.contains("scanner failed") && logs.contains("job failed"));
	assert!(
		!logs.contains("untrusted-scanner-error-sentinel"),
		"scanner error payload leaked into runner logs"
	);
}

#[tokio::test]
async fn cancelled_scan_discards_returned_findings() {
	let calls = run(Scenario::CancelScan).await;
	assert_eq!(calls.len(), 1, "cancelled scans must not submit accumulated findings");
	assert_eq!(calls[0].0, "/v1/jobs/7/complete");
	assert_eq!(
		calls[0].1,
		json!({"protocol_version":PROTOCOL_VERSION,"outcome":"failed","error":"job cancelled"})
	);
}

#[tokio::test]
async fn healthy_scan_still_submits_and_completes() {
	let calls = run(Scenario::Healthy).await;
	assert_eq!(calls.len(), 2);
	assert_eq!(calls[0].0, "/v1/jobs/7/findings");
	assert_eq!(calls[0].1["findings"].as_array().unwrap().len(), 2);
	assert_eq!(calls[1].0, "/v1/jobs/7/complete");
	assert_eq!(calls[1].1["outcome"], "succeeded");
	assert!(calls[1].1["error"].is_null());
	assert!(calls[1].1["head_sha"].as_str().is_some());
}

#[tokio::test]
async fn cancellation_during_batch_prevents_successful_completion() {
	let calls = run(Scenario::CancelDuringBatch).await;
	assert_eq!(calls.len(), 2);
	assert_eq!(calls[0].0, "/v1/jobs/7/findings");
	assert_eq!(calls[1].0, "/v1/jobs/7/complete");
	assert_eq!(
		calls[1].1,
		json!({"protocol_version":PROTOCOL_VERSION,"outcome":"failed","error":"job cancelled"}),
		"cancellation after scanner return must not advance a scan cursor"
	);
}

#[tokio::test]
async fn cancelled_verifier_does_not_submit_a_verdict() {
	let calls = run(Scenario::CancelVerifier).await;
	assert_eq!(calls.len(), 1, "cancelled verification must not submit a verdict");
	assert_eq!(calls[0].0, "/v1/jobs/7/complete");
	assert_eq!(
		calls[0].1,
		json!({"protocol_version":PROTOCOL_VERSION,"outcome":"failed","error":"job cancelled"})
	);
}
