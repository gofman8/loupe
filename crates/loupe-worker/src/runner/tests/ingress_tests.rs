//! Current host-verdict compatibility through the runner and HTTP serializer.

use super::*;

const PRIVATE_REVIEWED_REVISION: &str = "private-reviewed-revision-sentinel";

struct CountingVerifier(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl Scanner for CountingVerifier {
	fn id(&self) -> &'static str {
		"counting-verifier"
	}
	fn capabilities(&self) -> &[&'static str] {
		&["verify:fixture"]
	}
	async fn scan(&self, _: &ScanContext) -> Result<Vec<loupe_core::Finding<Repo>>> {
		Ok(Vec::new())
	}
	async fn verify(&self, _: &VerifyContext) -> Result<crate::VerifyOutcome> {
		self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
		Ok(crate::VerifyOutcome::Host(HostVerifyReason::ScannerDoesNotVerify))
	}
}

#[tokio::test]
async fn missing_or_unavailable_revision_emits_terminal_verdict_then_successful_completion() {
	revision_outcomes(false).await;
}

#[tokio::test]
async fn unavailable_revision_diagnostics_omit_server_text() {
	if !crate::test_env::in_env(
		"runner::tests::ingress_tests::unavailable_revision_diagnostics_omit_server_text",
		"reviewed-revision-log",
		&[],
	) {
		return;
	}
	let capture = crate::test_support::LogCapture::default();
	capture.install();
	revision_outcomes(false).await;
	let logs = capture.text();
	assert!(logs.contains("verify revision missing from refreshed cache; re-cloning"));
	assert!(
		!logs.contains(PRIVATE_REVIEWED_REVISION),
		"server-provided reviewed revision leaked into runner diagnostics"
	);
}

#[test]
fn cancellation_during_cache_prevents_host_verdicts_and_verifier_launch() {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap()
		.block_on(revision_outcomes(true));
}

async fn revision_outcomes(cancel_during_cache: bool) {
	use std::future::Future;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use axum::extract::{Json, Path as RoutePath};
	use axum::http::{HeaderMap, StatusCode};
	use axum::routing::post;
	use loupe_proto::{JOB_CAPABILITY_HEADER, PROTOCOL_VERSION_HEADER};

	let remote = tempfile::tempdir().unwrap();
	init_git_repo(remote.path());
	let valid_revision = commit_file(remote.path(), "original\n", "Original");
	let clone_url = reqwest::Url::from_directory_path(remote.path()).unwrap().to_string();
	let cache_dir = tempfile::tempdir().unwrap();
	let cache =
		Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), 1024 * 1024, None).unwrap());
	let (send, mut received) = tokio::sync::mpsc::unbounded_channel();
	let leased = Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
	let response_lease = leased.clone();
	let app = axum::Router::new()
		.route(
			"/v1/jobs/lease",
			post(move || {
				let response_lease = response_lease.clone();
				async move {
					(
						[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
						Json(response_lease.lock().unwrap().take().unwrap()),
					)
				}
			}),
		)
		.route(
			"/v1/jobs/7/{operation}",
			post(
				move |RoutePath(operation): RoutePath<String>,
				      headers: HeaderMap,
				      Json(body): Json<serde_json::Value>| {
					let send = send.clone();
					async move {
						assert_eq!(headers[JOB_CAPABILITY_HEADER], "fixture-capability");
						assert_eq!(headers[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
						send.send((operation, body)).unwrap();
						(
							[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
							StatusCode::NO_CONTENT,
						)
					}
				},
			),
		);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let stop = CancellationToken::new();
	let shutdown = stop.clone();
	let server = tokio::spawn(async move {
		axum::serve(listener, app)
			.with_graceful_shutdown(shutdown.cancelled_owned())
			.await
			.unwrap();
	});
	let client = Arc::new(ServerClient::from_parts(
		reqwest::Client::new(),
		format!("http://{address}").parse().unwrap(),
	));
	let verifier_calls = Arc::new(AtomicUsize::new(0));
	let runner =
		Runner::new(client, cache, vec![Arc::new(CountingVerifier(verifier_calls.clone()))]);
	let absent_oid = "1111111111111111111111111111111111111111";
	let mut cancelled_calls = Vec::new();
	for revision in [
		None,
		Some(" \t"),
		Some("base"),
		Some(PRIVATE_REVIEWED_REVISION),
		Some(absent_oid),
		Some(valid_revision.as_str()),
	] {
		// Original response bytes are admitted by the actual HTTP lease decoder.
		let mut env = serde_json::json!({
			"kind": "lease", "protocol_version": PROTOCOL_VERSION,
			"job_id": 7, "job_capability": "fixture-capability", "repo_id": 9,
			"repo": {"host": "local", "owner": "owner", "repo": "repo",
				"clone_url": clone_url, "branch": "main"},
			"head_branch": "main", "lease_expires_at": i64::MAX,
			"scanner_config": null,
			"payload": {"kind": "verify", "finding_id": 3,
				"finding": {"scanner_id": "test", "severity": "low", "title": "unverified",
					"description": "unverified finding", "fingerprint": "test"}}
		});
		if let Some(revision) = revision {
			env["payload"]["reviewed_sha"] = serde_json::json!(revision);
		}
		*leased.lock().unwrap() = Some(env);
		let outcome = if cancel_during_cache {
			let receipt =
				runner.client.lease_for_runner(runner.capabilities.clone(), 0).await.unwrap();
			let LeaseResponse::Lease(env) = receipt.response else { panic!("lease fixture") };
			let (entered, wait_entered) = std::sync::mpsc::channel();
			let (release, wait_release) = std::sync::mpsc::channel();
			let blocker = tokio::task::spawn_blocking(move || {
				entered.send(()).unwrap();
				wait_release.recv().unwrap();
			});
			wait_entered.recv().unwrap();
			let cancel = CancellationToken::new();
			let mut execution = Box::pin(runner.run_lease(
				*env,
				receipt.reviewed_revision,
				receipt.scanner_patch,
				&cancel,
			));
			let queued =
				std::future::poll_fn(|cx| std::task::Poll::Ready(execution.as_mut().poll(cx)))
					.await;
			cancel.cancel();
			release.send(()).unwrap();
			blocker.await.unwrap();
			assert!(queued.is_pending(), "cache refresh must wait behind the blocking gate");
			execution.await.map(|()| true)
		} else {
			runner.step(&CancellationToken::new()).await
		};
		assert!(
			matches!(outcome, Ok(true)),
			"original lease admission must reach the host outcome for {revision:?}: {outcome:?}"
		);
		if cancel_during_cache {
			let mut calls = Vec::new();
			while let Ok(call) = received.try_recv() {
				calls.push(call);
			}
			cancelled_calls.push((revision, calls));
			continue;
		}
		let (operation, verdict) =
			tokio::time::timeout(Duration::from_secs(1), received.recv()).await.unwrap().unwrap();
		assert_eq!(operation, "verdict");
		let expected_head = revision.filter(|value| !value.trim().is_empty());
		let reason = match expected_head {
			None => "original reviewed revision is unavailable: verify lease did not carry the original reviewed revision".to_owned(),
			Some(sha) if sha == valid_revision => "scanner does not verify".to_owned(),
			Some(sha) => {
				let operation = if sha == absent_oid { "locating" } else { "parsing" };
				format!("original reviewed revision {sha} is unavailable after refreshing and re-cloning the repository: {operation} reviewed revision {sha}")
			},
		};
		let mut expected_verdict = serde_json::json!({
			"protocol_version": PROTOCOL_VERSION,
			"verdict": {"outcome": "inconclusive", "reason": reason, "terminal": true}
		});
		if expected_head == Some(valid_revision.as_str()) {
			expected_verdict["verdict"].as_object_mut().unwrap().remove("terminal");
		}
		assert_eq!(verdict, expected_verdict);
		let (operation, complete) =
			tokio::time::timeout(Duration::from_secs(1), received.recv()).await.unwrap().unwrap();
		assert_eq!(operation, "complete");
		let mut expected_complete = serde_json::json!({
			"protocol_version": PROTOCOL_VERSION, "outcome": "succeeded"
		});
		if let Some(head) = expected_head {
			expected_complete["head_sha"] = serde_json::json!(head);
		}
		assert_eq!(complete, expected_complete);
		assert!(received.try_recv().is_err(), "host branch emitted an extra submission");
	}
	stop.cancel();
	server.await.unwrap();
	if cancel_during_cache {
		let expected = vec![(
			"complete".to_owned(),
			serde_json::json!({
				"protocol_version": PROTOCOL_VERSION, "outcome": "failed", "error": "job cancelled"
			}),
		)];
		assert!(cancelled_calls.iter().all(|(_, calls)| *calls == expected)
			&& verifier_calls.load(Ordering::SeqCst) == 0,
			"cancelled verification must emit only Failed and never launch a verifier: {cancelled_calls:?}; verifier calls: {}", verifier_calls.load(Ordering::SeqCst));
	} else {
		assert_eq!(
			verifier_calls.load(Ordering::SeqCst),
			1,
			"only the valid revision may launch a verifier"
		);
	}
}

#[tokio::test]
async fn revision_checkout_rejects_a_branch_name_that_latest_checkout_accepts() {
	let remote = tempfile::tempdir().unwrap();
	init_git_repo(remote.path());
	let commit = commit_file(remote.path(), "original\n", "Original");
	git(remote.path(), &["branch", "base"]);
	let cache = tempfile::tempdir().unwrap();
	let bare = cache.path().join("repo.git");
	clone_bare(remote.path(), &bare);
	let (workdir, observed) = checkout_latest(&bare, Some("base")).await.unwrap();
	assert_eq!(observed.expose(), commit);
	assert_eq!(std::fs::read(workdir.path().join("file.txt")).unwrap(), b"original\n");
	let error = checkout_revision(&bare, "base").await.unwrap_err();
	assert!(matches!(
		error.downcast_ref::<CheckoutFailure>(),
		Some(CheckoutFailure::ParseRevision)
	));
	assert_eq!(error.to_string(), "parsing reviewed revision");
}
