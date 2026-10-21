//! Private production transaction seam: no second public mutation API.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use loupe_core::inventory_manifest::{ManifestEntry, ManifestHasher};
use loupe_core::review_payload::DrilldownTerminalV1;
use loupe_core::WORKFLOW_CONTRACT_VERSION;
use loupe_proto::review_api::RawPathHexPolicy;
use loupe_proto::review_drilldown::FinalizeDrilldownRequestDecoder;
use loupe_storage::admission_policy::{AcceptedPriority, CampaignPolicyV2};
use loupe_storage::{
	finding_details, findings, registry, review_findings, review_intents, scheduler,
	terminal_payloads, StoredEvidence,
};
use rusqlite::params;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::json;
use tower::Service;

use super::*;
use crate as server;
#[path = "../common/marked.rs"]
// This fixed-source fixture has helpers for other integration-test binaries.
#[allow(dead_code)]
pub(crate) mod marked;
mod common {
	pub(crate) use super::marked;
	pub(crate) use crate::test_support::offline;
	pub fn with_repo<T>(
		db: &loupe_storage::Db, repo: i64,
		body: impl for<'tx> FnOnce(&loupe_storage::scope::RepoScope<'tx>) -> loupe_storage::Result<T>,
	) -> loupe_storage::Result<T> {
		loupe_storage::scope::with_operator_repository(
			db,
			&crate::test_support::operator(),
			loupe_storage::scope::OperatorTarget::Repository(repo),
			body,
		)
	}
}
#[path = "reporter.rs"]
mod reporter;

#[tokio::test]
async fn committed_verification_without_dispatch_is_recovered_only_by_admin_retry() {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	let ca = Arc::new(loupe_tls::Ca::new("gap").unwrap());
	let certificate = ca.mint_client("gap-worker").unwrap();
	let peer = crate::PeerCert(
		CertificateDer::pem_slice_iter(certificate.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	let fingerprint = loupe_tls::cert_fingerprint(peer.0.as_ref());
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let offline = Arc::new(offline);
	let token = "g".repeat(43);
	let hash = *blake3::hash(token.as_bytes()).as_bytes();
	let evidence = json!({"version":1,"l2_argument":{"attacker_source":"request","control":"length","sink":"allocator","reachable_path":"producer path","trust_boundary":"network to process"},"material_locations":[{"role":"sink","file":"src.rs"}],"counterevidence":"none known","assumptions_gaps":"source contract","confidence":"high"});
	let raw = json!({"protocol_version":3,"payload":{"version":1,"disposition":"promote","promotion":{"version":1,"severity":"high","title":"Allocation boundary","description":"Source finding","identity_family":"allocation","identity_anchor":"allocator","evidence":evidence}}}).to_string();
	let input = crate::test_support::worker_body(raw.as_bytes());
	let admitted = input.0.as_bytes().validate_carrying(FinalizeDrilldownRequestDecoder).unwrap();
	let DrilldownTerminalV1::Promote { promotion, .. } = admitted.payload else {
		panic!("promotion")
	};
	let policy = CampaignPolicyV2::default().canonical_bytes().unwrap();
	let profile_digest = *blake3::hash(b"{}").as_bytes();
	let manifest_entry = ManifestEntry::from_encoded(
		&marked::operator::identifier::<RawPathHexPolicy>("7372632e7273"),
		0o100644,
		&marked::operator::identifier::<loupe_core::review_metadata::CommitPolicy>(sha),
	)
	.unwrap();
	let mut manifest = ManifestHasher::new(sha, 1).unwrap();
	manifest.push(&manifest_entry).unwrap();
	let digest = manifest.finish().unwrap();
	offline.external_corruption(|conn| {
        conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','owner','repo','{\"kind\":\"manual\"}',0)")?;
        Ok(())
    }).unwrap();
	let worker_id = registry::register_worker(
		&db,
		&marked::operator_ingress(),
		&marked::operator::text("gap-worker"),
		&fingerprint,
		now,
	)
	.unwrap();
	offline.external_corruption(|conn| {
        conn.execute("INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,profile_version,generated_profile,generated_profile_digest,created_at,generated_profile_source) VALUES(1,1,?1,'active',?4,1,'{}',?2,0,'agent')", params![sha, profile_digest.as_slice(), now, WORKFLOW_CONTRACT_VERSION])?;
        conn.execute("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at) VALUES(1,1,'bootstrap','manual',?1,1,'active',?2,?3,?4,0)", params![sha,std::str::from_utf8(&policy).unwrap(),blake3::hash(&policy).as_bytes().as_slice(),now+3600])?;
        conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,1)",[])?;
        conn.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(1,1,'allocation','origin',zeroblob(32),'{}',zeroblob(32),?1,0)",[sha])?;
        conn.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,assigned_lead_id,head_sha,workflow_contract_version,recipe,enqueued_at) VALUES(1,1,'drilldown','succeeded',1,1,1,?1,?2,'{\"version\":1,\"phase\":\"drilldown\"}',0)",params![sha,WORKFLOW_CONTRACT_VERSION])?;
        conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,received_canonical_bytes,created_at,sealed_at) VALUES(1,1,1,1,1,?1,?2,0,1)",params![digest.as_slice(),manifest_entry.canonical_len().unwrap()])?;
        conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(1,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),sha])?;
        Ok(())
    }).unwrap();
	let (finding, intent) = common::with_repo(&db, 1, |scope| {
		let finding = review_findings::insert(
			scope,
			&review_findings::NewFinding {
				job_id: 1,
				origin_lead_id: 1,
				profile_version: 1,
				profile_digest: &profile_digest,
				reviewed_commit_sha: &marked::operator::text(sha),
				promotion: &promotion,
			},
			now,
		)?;
		loupe_storage::leads::close(
			scope,
			1,
			&loupe_storage::leads::Closure::Promoted { finding },
			now,
		)?;
		let intent = review_intents::ensure_verification_intent(
			scope,
			finding,
			1,
			AcceptedPriority { band: scheduler::Band::Normal, score: 0 },
			now,
		)?
		.unwrap();
		Ok((finding, intent))
	})
	.unwrap();
	offline.external_corruption(|conn| {
        conn.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,parent_job_id,target_finding_id,worker_id,attempts,lease_expires_at,hard_deadline_at,head_sha,job_capability_hash,prepared_attempt,prepared_capability_hash,prepared_at,workflow_contract_version,scheduling_band,recipe,enqueued_at) VALUES(2,1,'verify','leased',1,1,1,?1,?2,1,?3,?3,?4,?5,1,?5,?6,?7,'normal','{\"version\":1,\"phase\":\"verify\"}',?6)",params![finding,worker_id,now+3600,sha,hash.as_slice(),now,WORKFLOW_CONTRACT_VERSION])?;
        Ok(())
    }).unwrap();
	common::with_repo(&db, 1, |scope| {
		review_intents::admit_subject(
			scope,
			review_intents::Subject::Finding(finding),
			intent.revision,
			2,
			now,
		)
	})
	.unwrap();
	let mut state =
		AppState::new(db, ca, Arc::new(crate::reporters::GithubReporter::new().unwrap()));
	let stub = reporter::configure(&mut state, offline, finding).await;
	async fn capture(Extension(worker): Extension<AuthedWorker>) -> Response {
		let mut response = StatusCode::OK.into_response();
		response.extensions_mut().insert(worker);
		response
	}
	let mut auth = axum::Router::new()
		.route("/", axum::routing::get(capture))
		.layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::mtls_auth));
	let mut auth_request = axum::http::Request::builder().uri("/").body(Body::empty()).unwrap();
	auth_request.extensions_mut().insert(peer.clone());
	let mut authenticated = auth.call(auth_request).await.unwrap();
	assert_eq!(authenticated.status(), StatusCode::OK);
	let worker = authenticated.extensions_mut().remove::<AuthedWorker>().unwrap();
	let mut independent = evidence;
	independent["l2_argument"]["reachable_path"] = json!("Independent verifier trace");
	let input=marked::verification_terminal(&json!({"version":1,"verdict":"verified","established_rung":"L2","e2e_applicability":"not_applicable","e2e_rationale":"Source-only contract defect","evidence":independent}).to_string());
	let mut headers = HeaderMap::new();
	headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, token.parse().unwrap());
	headers.insert(loupe_proto::PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
	let mut escaped = None;
	let overflow = http::transaction(&state.db, &worker, &headers, 2, 1, |tx| {
		let value = tx
			.finalize_verification(&input, false, |context| {
				authority::policy(Phase::Verify, Access::Domain, context)
			})
			.map_err(error)?;
		escaped = Some(value.reporting);
		reply(value.receipt)
	});
	assert_eq!(overflow.unwrap_err().into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
	let Some(reports::Preparation::Ready(batch)) = escaped else { panic!("prepared report") };
	assert!(matches!(batch.check_committed(), Err(loupe_storage::Error::ReportReceipt)));
	common::with_repo(&state.db, 1, |scope| {
		assert_eq!(
			findings::get(scope, finding)?.unwrap().state,
			loupe_core::FindingState::Validating
		);
		assert!(matches!(terminal_payloads::get(scope, 2)?, StoredEvidence::Missing));
		Ok(())
	})
	.unwrap();
	assert!(stub.capture.calls.lock().unwrap().is_empty());
	let (response, dispatch) = finish(&state, &worker, &headers, 2, &input).unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(dispatch.as_ref().map(|dispatch| dispatch.finding_id), Some(finding));
	// Stop after the actual finalization transaction commits, without dispatch.
	assert!(stub.capture.calls.lock().unwrap().is_empty());
	common::with_repo(&state.db, 1, |scope| {
		assert_eq!(
			findings::get(scope, finding)?.unwrap().state,
			loupe_core::FindingState::Confirmed
		);
		assert!(matches!(terminal_payloads::get(scope, 2)?, StoredEvidence::Recorded(_)));
		assert!(matches!(
			finding_details::get_review_evidence(scope, finding)?,
			StoredEvidence::Recorded(_)
		));
		Ok(())
	})
	.unwrap();
	let mut replay = axum::http::Request::post("/v1/jobs/2/finalize-verification")
		.header(loupe_proto::PROTOCOL_VERSION_HEADER, "3")
		.header(loupe_proto::JOB_CAPABILITY_HEADER, token)
		.header("content-type", "application/json")
		.body(Body::from(json!({"protocol_version":3,"payload":input}).to_string()))
		.unwrap();
	replay.extensions_mut().insert(peer);
	assert_eq!(crate::router(state.clone()).call(replay).await.unwrap().status(), StatusCode::OK);
	assert!(
		stub.capture.calls.lock().unwrap().is_empty(),
		"receipt replay must not fill the dispatch gap"
	);
	assert_eq!(reporter::admin(&state, finding, "retry-report").await, StatusCode::NO_CONTENT);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	common::with_repo(&state.db, 1, |scope| {
		assert_eq!(
			findings::get(scope, finding)?.unwrap().state,
			loupe_core::FindingState::Reported
		);
		Ok(())
	})
	.unwrap();
}
