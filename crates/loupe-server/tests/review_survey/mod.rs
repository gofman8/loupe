//! Public router tests; only accepted checkpoints are seeded while their HTTP
//! producer is developed independently. No lease/terminal authorization bypass.
use loupe_storage::{generations, review_units, terminal_payloads, unit_holds, StoredEvidence};

use super::*;

fn payload(reason: &str) -> Value {
	json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":reason,
		"continuation":"Keep the remaining source work", "security_model_notes":"<script>literal</script>\n```notes```"}})
}

async fn ready() -> (Fixture, i64) {
	let f = fixture();
	let generation = prepare(&f).await;
	f.offline.external_corruption(|conn| {
		let policy = ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,std::str::from_utf8(&policy.canonical_bytes()?).unwrap(),loupe_core::canonical::digest(&policy.canonical_bytes()?).as_slice()])?;
		conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(?1,2,1)",[f.campaign])?;
		Ok(())
	}).unwrap();
	(f, generation)
}

fn source() -> Value {
	json!({"path":"z.rs","symbol":null})
}

// Accepted checkpoint fixtures are written to the fixture-owned encrypted
// database. The finalizer must admit their original SQL bytes and projections.
fn unit(f: &Fixture, generation: i64, key: &str, disposition: Option<&str>) -> (i64, Option<i64>) {
	let created=f.offline.external_corruption(|conn| {
        conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at,source) VALUES(?1,?2,'review','inspect boundary',?3,?4,?5,'agent')",
            params![generation,key,json!([source()]).to_string(),f.job,now()])?;
        let unit=conn.last_insert_rowid();
        let result=if let Some(disposition)=disposition {
            let mut value=json!({"format":"loupe.unit_result","version":1,"review_unit_id":unit,
                "assignment_epoch":0,"disposition":disposition,"inspected_refs":[source()],"created_lead_ids":[],
                "counterevidence":"none","proof_gaps":"none","notes":"accepted notes"});
            if disposition=="needs_follow_up" {
                value["follow_up"]=json!("remaining source work");
                value["continuation"]=json!("source_analysis_remaining");
            }
            let bytes=loupe_core::canonical::canonical_bytes(&value);
            let raw=std::str::from_utf8(&bytes).unwrap();
            conn.execute("INSERT INTO review_unit_results(review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,result_digest,created_at,source) VALUES(?1,?2,?3,1,?4,?5,NULL,NULL,?6,?7,?8,'agent')",
                params![unit,f.job,SHA,disposition,json!([source()]).to_string(),raw,loupe_core::canonical::digest(&bytes).as_slice(),now()])?;
            let result=conn.last_insert_rowid();
            if disposition=="needs_follow_up" {
                conn.execute("INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_result_id,producing_job_id,source_assignment_epoch,continuation_class,created_at,updated_at) VALUES(?1,?2,?3,?4,0,'source_analysis_remaining',?5,?5)",params![unit,generation,result,f.job,now()])?;
            }
            Some(result)
        } else {None};
        Ok((unit,result))
    }).unwrap();
	if let Some(result) = created.1 {
		assert!(
			matches!(
				common::with_repo(&f.state.db, 1, |scope| {
					loupe_storage::review_unit_results::get_evidence(scope, result)
				})
				.unwrap(),
				StoredEvidence::Recorded(_)
			),
			"fixture must be admitted canonical checkpoint evidence"
		);
	}
	created
}

fn scalar(f: &Fixture, sql: &str) -> i64 {
	f.offline.external_corruption(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

#[tokio::test]
async fn unrelated_damaged_result_is_incomplete_not_a_terminal_mutation_failure() {
	for damage in ["none", "digest", "malformed", "refs"] {
		let (f, generation) = ready().await;
		let (unit, result) = unit(&f, generation, "other-producer", Some("no_lead_found"));
		f.offline.external_corruption(|conn| {
			conn.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,head_sha,workflow_contract_version,enqueued_at) VALUES(1,'survey','succeeded',?1,?2,?3,2,0)",params![f.campaign,generation,SHA])?;
			let other=conn.last_insert_rowid();
			conn.execute("UPDATE review_unit_results SET produced_by_job_id=?2 WHERE review_unit_result_id=?1",params![result,other])?;
			conn.execute("UPDATE review_units SET created_by_job_id=?2 WHERE review_unit_id=?1",params![unit,other])?;
			conn.execute("UPDATE generation_inventory SET disposition='context'",[])?;
			conn.execute("UPDATE review_generations SET corroboration_state='satisfied'",[])?;
			match damage {
				"digest"=>{conn.execute("UPDATE review_unit_results SET result_digest=zeroblob(32)",[])?;},
				"malformed"=>{conn.execute("UPDATE review_unit_results SET result_payload='{'",[])?;},
				"refs"=>{conn.execute("UPDATE generation_inventory SET source_path='different.rs',raw_path=CAST('different.rs' AS BLOB) WHERE source_path='z.rs'",[])?;},
				_=>{},
			}
			Ok(())
		}).unwrap();
		let (status, reply) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(status,StatusCode::OK,"unrelated {damage} evidence must be non-covering, not prevent terminal progress: {reply}");
		assert_eq!(
			reply["receipt"]["summary"]["coverage"],
			if damage == "none" { "complete" } else { "partial" }
		);
		assert_eq!(reply["receipt"]["summary"]["missing_results"], i64::from(damage != "none"));
		assert_eq!(
			scalar(&f, "SELECT COUNT(*) FROM review_unit_results"),
			1,
			"damaged derived evidence is not silently deleted"
		);
	}
}

#[tokio::test]
async fn prepared_bootstrap_seals_partial_coverage_and_replays_the_exact_receipt() {
	let (f, generation) = ready().await;
	unit(&f, generation, "unassessed", None);
	let before = scalar(&f, "SELECT COUNT(*) FROM jobs");
	let request_body = payload("completed");
	let (status, first) = request(&f, f.job, "finalize-survey", request_body.clone()).await;
	assert_eq!(status, StatusCode::OK, "{first}");
	assert_eq!(first["receipt"]["summary"]["coverage"], "partial");
	assert_eq!(first["receipt"]["summary"]["missing_results"], 1);
	// The non-UTF-8 entry is explicitly excluded by host sealing; the two
	// addressable entries still need dispositions.
	assert_eq!(first["receipt"]["summary"]["unresolved_inventory"], 2);
	assert_eq!(scalar(&f,"SELECT COUNT(*) FROM review_generations WHERE state='active' AND corroboration_state='pending'"),1);
	assert_eq!(scalar(&f,"SELECT COUNT(*) FROM jobs WHERE state='succeeded' AND worker_id IS NOT NULL AND job_capability_hash IS NULL AND prepared_attempt IS NULL"),1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), before, "no speculative child jobs");
	{
		let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Survey(stored)) =
			common::with_repo(&f.state.db, 1, |scope| terminal_payloads::get(scope, f.job))
				.unwrap()
		else {
			panic!("typed terminal evidence")
		};
		assert_eq!(serde_json::to_value(stored).unwrap(), request_body["payload"]);
	}
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE review_campaigns SET state='cancelled'",[])?;
		conn.execute("UPDATE review_generations SET generated_profile='{}',generated_profile_digest=zeroblob(32)",[])?;
		Ok(())
	}).unwrap();
	assert_eq!(
		request(&f, f.job, "finalize-survey", request_body.clone()).await,
		(StatusCode::OK, first.clone())
	);
	f.offline
		.external_corruption(|conn| {
			conn.execute("DELETE FROM review_generations", [])?;
			Ok(())
		})
		.unwrap();
	{
		let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Survey(stored)) =
			common::with_repo(&f.state.db, 1, |scope| terminal_payloads::get(scope, f.job))
				.unwrap()
		else {
			panic!("full survey notes must survive generation purge")
		};
		assert_eq!(serde_json::to_value(stored).unwrap(), request_body["payload"]);
	}
	assert_eq!(request(&f, f.job, "finalize-survey", request_body).await, (StatusCode::OK, first));
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(
		request(&f, f.job, "finalize-survey", payload("partial")).await.0,
		StatusCode::CONFLICT
	);
}

#[tokio::test]
async fn existing_receipt_conflicts_without_committing_fresh_terminal_mutations() {
	let (f, generation) = ready().await;
	let (held, _) = unit(&f, generation, "held", Some("needs_follow_up"));
	let body = payload("partial");
	let digest =
		loupe_core::canonical::digest(&loupe_core::canonical::canonical_bytes(&body["payload"]));
	let summary = json!({"version":1,"coverage":"partial","corroboration_satisfied":false,
		"missing_results":1,"needs_follow_up":1,"unresolved_inventory":2,
		"follow_up_batches":1,"follow_up_units":1});
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO job_terminal_receipts(job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,result_counts,finishing_capability_hash,created_at)
		 SELECT id,'survey','partial',head_sha,'{}',?2,?3,job_capability_hash,?4 FROM jobs WHERE id=?1",
		 params![f.job,digest.as_slice(),summary.to_string(),now()])?;
		Ok(())
	}).unwrap();
	let receipt = common::with_repo(&f.state.db, 1, |scope| {
		loupe_storage::terminal_receipt::get(scope, f.job)
	})
	.unwrap()
	.unwrap();
	assert_eq!(receipt.result_digest, digest);
	assert_eq!(receipt.phase.as_str(), "survey");
	// A leased job is not eligible for terminal replay. Fresh authorization
	// therefore reaches the composite UNIQUE index after provisional mutation.
	let (status, value) = request(&f, f.job, "finalize-survey", body.clone()).await;
	assert_eq!(status, StatusCode::CONFLICT, "{value}");
	assert_eq!(value["error"]["code"], "terminal_conflict");
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building' AND activated_at IS NULL"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs WHERE state='leased' AND finished_at IS NULL AND worker_id IS NOT NULL AND job_capability_hash IS NOT NULL AND lease_expires_at IS NOT NULL AND prepared_attempt=attempts AND prepared_capability_hash=job_capability_hash AND prepared_at IS NOT NULL"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_payloads"), 0);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 0);
	common::with_repo(&f.state.db, 1, |scope| {
		let unchanged = loupe_storage::terminal_receipt::get(scope, f.job)?.unwrap();
		assert_eq!(unchanged.receipt_id, receipt.receipt_id);
		assert_eq!(unchanged.result_digest, receipt.result_digest);
		assert!(unit_holds::get_hold(scope, held)?.unwrap().pending_batch_id.is_none());
		Ok(())
	})
	.unwrap();
	// Exact positive neighbor: removing only the conflicting offline row lets
	// the same authenticated request commit its receipt, payload, and handoff.
	f.offline
		.external_corruption(|conn| {
			conn.execute("DELETE FROM job_terminal_receipts WHERE job_id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(request(&f, f.job, "finalize-survey", body).await.0, StatusCode::OK);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_payloads"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 1);
}

#[tokio::test]
async fn receipt_and_payload_failures_roll_back_activation_and_success() {
	for table in ["job_terminal_receipts", "job_terminal_payloads"] {
		let (f, generation) = ready().await;
		unit(&f, generation, "held", Some("needs_follow_up"));
		f.offline.external_corruption(|conn| {
			conn.execute_batch(&format!("CREATE TRIGGER fail_terminal BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected terminal failure'); END"))?;
			Ok(())
		}).unwrap();
		assert_eq!(
			request(&f, f.job, "finalize-survey", payload("partial")).await.0,
			StatusCode::INTERNAL_SERVER_ERROR
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building'"), 1);
		assert_eq!(scalar(&f,"SELECT COUNT(*) FROM jobs WHERE state='leased' AND job_capability_hash IS NOT NULL"),1);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_payloads"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 0);
	}
}

#[tokio::test]
async fn follow_up_batches_split_overflow_and_keep_exact_members_without_spend() {
	let (f, generation) = ready().await;
	f.offline.external_corruption(|conn| {
		let policy = loupe_storage::admission_policy::CampaignPolicyV2 {survey_units_per_job:2,..Default::default()};
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,std::str::from_utf8(&policy.canonical_bytes()?).unwrap(),loupe_core::canonical::digest(&policy.canonical_bytes()?).as_slice()])?;
		Ok(())
	}).unwrap();
	let expected: Vec<i64> = (0..5)
		.map(|i| unit(&f, generation, &format!("held-{i}"), Some("needs_follow_up")).0)
		.collect();
	let unheld = unit(&f, generation, "ordinary", None).0;
	let before = scalar(&f, "SELECT general_spent FROM campaign_admission_spending");
	let result = post(&f, "finalize-survey", payload("partial")).await;
	assert_eq!(result["receipt"]["summary"]["follow_up_batches"], 3);
	assert_eq!(result["receipt"]["summary"]["follow_up_units"], 5);
	assert_eq!(result["receipt"]["summary"]["missing_results"], 6);
	common::with_repo(&f.state.db, 1, |scope| {
		let batches = unit_holds::list_batches(scope, f.campaign, 0, 256)?;
		assert_eq!(
			batches.iter().map(|b| b.expected_unit_count).collect::<Vec<_>>(),
			vec![2, 2, 1]
		);
		let mut actual = Vec::new();
		for batch in batches {
			assert_eq!(batch.logical_sequence, 1);
			assert!(batch.not_before.unwrap() > now());
			assert!(batch.admitted_job_id.is_none());
			for hold in unit_holds::batch_holds(scope, batch.batch_id)? {
				actual.push(hold.unit_id);
			}
		}
		assert_eq!(actual, expected);
		assert!(unit_holds::get_hold(scope, unheld)?.is_none());
		Ok(())
	})
	.unwrap();
	assert_eq!(scalar(&f, "SELECT general_spent FROM campaign_admission_spending"), before);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 1);
	assert_eq!(post(&f, "finalize-survey", payload("partial")).await, result);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 3);
}

#[tokio::test]
async fn modern_conclusive_evidence_and_real_corroboration_are_both_required() {
	for historical in [false, true] {
		for corroborated in [false, true] {
			let (f, generation) = ready().await;
			let (_, result) = unit(&f, generation, "done", Some("no_lead_found"));
			f.offline.external_corruption(|conn| {
				conn.execute("UPDATE generation_inventory SET disposition='context'",[])?;
				if corroborated {conn.execute("UPDATE review_generations SET corroboration_state='satisfied'",[])?;}
				if historical {let raw="{}"; conn.execute("UPDATE review_unit_results SET result_payload=?2,result_digest=?3 WHERE review_unit_result_id=?1",params![result,raw,loupe_core::canonical::digest(raw.as_bytes()).as_slice()])?;}
				Ok(())
			}).unwrap();
			let value = post(&f, "finalize-survey", payload("deferred")).await;
			assert_eq!(
				value["receipt"]["summary"]["coverage"],
				if corroborated && !historical { "complete" } else { "partial" }
			);
			assert_eq!(value["receipt"]["summary"]["missing_results"], i64::from(historical));
		}
	}
}

#[tokio::test]
async fn missing_preparation_and_wrong_authority_never_seal() {
	for damage in [
		"unprepared",
		"expired",
		"deadline",
		"old_attempt",
		"wrong_token",
		"wrong_worker",
		"unsupported",
		"owner",
		"profile",
		"unsealed",
	] {
		let (mut f, _) = ready().await;
		match damage {
			"wrong_token" => f.token = "b".repeat(43),
			"wrong_worker" => f.peer = f.other_peer.clone(),
			_ => {
				f.offline.external_corruption(|conn| {
				let sql=match damage {
					"unprepared" => "UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL",
					"expired" => "UPDATE jobs SET lease_expires_at=0",
					"deadline" => "UPDATE jobs SET hard_deadline_at=0",
					"old_attempt" => "UPDATE jobs SET attempts=attempts+1",
					"unsupported" => "UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"reconciliation\",\"assignment_key\":\"ordinary\"}'",
					"owner" => "UPDATE generation_manifests SET owner_job_id=NULL",
					"profile" => "UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL",
					"unsealed" => "UPDATE generation_manifests SET sealed_at=NULL",
					_=>unreachable!()
				}; conn.execute(sql,[])?; Ok(())
			}).unwrap();
			},
		}
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{damage}: {value}");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building'"), 1);
	}
}

#[tokio::test]
async fn malformed_or_stale_modern_evidence_rolls_back_without_losing_checkpoint_data() {
	for damage in ["digest", "projection", "epoch", "missing_hold"] {
		let (f, generation) = ready().await;
		unit(&f, generation, "damaged", Some("needs_follow_up"));
		f.offline
			.external_corruption(|conn| {
				conn.execute(
					match damage {
						"digest" => "UPDATE review_unit_results SET result_digest=zeroblob(32)",
						"projection" => {
							"UPDATE review_unit_results SET disposition='no_lead_found'"
						},
						"epoch" => "UPDATE review_units SET assignment_epoch=1",
						"missing_hold" => "DELETE FROM review_unit_holds",
						_ => unreachable!(),
					},
					[],
				)?;
				Ok(())
			})
			.unwrap();
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(status, StatusCode::CONFLICT, "{damage}: {value}");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_unit_results"), 1);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs WHERE state='leased'"), 1);
	}
}

#[tokio::test]
async fn ordinary_partial_survey_never_reactivates_or_replaces_the_profile() {
	let (f, generation) = ready().await;
	unit(&f, generation, "unfinished", None);
	common::with_repo(&f.state.db, 1, |scope| generations::activate(scope, generation, 42))
		.unwrap();
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",[f.job])?;
		Ok(())
	}).unwrap();
	let value = post(&f, "finalize-survey", payload("partial")).await;
	assert_eq!(value["receipt"]["summary"]["coverage"], "partial");
	assert_eq!(scalar(&f, "SELECT activated_at FROM review_generations"), 42);
	f.offline
		.external_corruption(|conn| {
			let profile: String =
				conn.query_row("SELECT generated_profile FROM review_generations", [], |r| {
					r.get(0)
				})?;
			assert_eq!(profile, "{\"scope\":\"crate\"}");
			Ok(())
		})
		.unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		let receipt = loupe_storage::terminal_receipt::get(scope, f.job)?.unwrap();
		let audit: Value = serde_json::from_str(receipt.effective_recipe.expose()).unwrap();
		assert_eq!(audit["commit_sha"], SHA);
		assert_eq!(audit["policy"]["version"], 2);
		assert_eq!(audit["profile_version"], 1);
		assert_eq!(audit["manifest_entries"], 3);
		assert_eq!(audit["profile_digest"].as_str().unwrap().len(), 64);
		assert_eq!(audit["manifest_digest"].as_str().unwrap().len(), 64);
		Ok(())
	})
	.unwrap();
}

#[tokio::test]
async fn transport_is_strict_bounded_and_no_store_including_rejections() {
	let (f, _) = ready().await;
	let valid = payload("partial").to_string();
	let cases = [
		(
			valid.replace("\"protocol_version\":3", "\"protocol_version\":2"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"payload\":{\"inventory_dispositions\":[],"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"owner\":1,\"payload\":{"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(valid.clone(), "2", "identity", StatusCode::BAD_REQUEST),
		(valid.clone(), "3", "gzip", StatusCode::UNSUPPORTED_MEDIA_TYPE),
		(" ".repeat(128 * 1024) + &valid, "3", "identity", StatusCode::PAYLOAD_TOO_LARGE),
	];
	for (body, version, encoding, expected) in cases {
		let mut req = Request::post(format!("/v1/jobs/{}/finalize-survey", f.job))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("Content-Type", "application/json")
			.header("Content-Encoding", encoding)
			.body(Body::from(body))
			.unwrap();
		req.extensions_mut().insert(f.peer.clone());
		let response = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(response.status(), expected);
		assert_eq!(response.headers()["cache-control"], "no-store");
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"].is_object());
	}
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	let mut req = Request::post(format!("/v1/jobs/{}/finalize-survey", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("Content-Type", "application/json")
		.body(Body::from(valid))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "no-store");
	let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
	assert!(
		!String::from_utf8_lossy(&bytes).contains("script"),
		"accepted notes are retained, not reflected in bounded receipt"
	);
}

#[tokio::test]
async fn replay_does_not_disclose_existence_to_the_wrong_identity() {
	let (mut f, _) = ready().await;
	post(&f, "finalize-survey", payload("partial")).await;
	let correct_token = f.token.clone();
	f.token = "b".repeat(43);
	let wrong_token = request(&f, f.job, "finalize-survey", payload("deferred")).await;
	f.token = correct_token;
	f.peer = f.other_peer.clone();
	let wrong_worker = request(&f, f.job, "finalize-survey", payload("deferred")).await;
	let missing = request(&f, 999999, "finalize-survey", payload("deferred")).await;
	assert_eq!(wrong_token, wrong_worker);
	assert_eq!(wrong_worker, missing);
	assert_eq!(missing.0, StatusCode::FORBIDDEN);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
}

async fn exact_continuation(f: &mut Fixture) -> i64 {
	post(f, "finalize-survey", payload("partial")).await;
	let batch = common::with_repo(&f.state.db, 1, |scope| {
		unit_holds::list_batches(scope, f.campaign, 0, 256)
	})
	.unwrap()
	.remove(0);
	let job=f.offline.external_corruption(|conn| {
        conn.execute("UPDATE survey_continuation_batches SET not_before=?2 WHERE batch_id=?1",params![batch.batch_id,now()-1])?;
        conn.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,parent_job_id,continuation_of_job_id,worker_id,attempts,lease_expires_at,hard_deadline_at,job_capability_hash,workflow_contract_version,scheduling_band,recipe,enqueued_at)
            SELECT repo_id,'survey','leased',campaign_id,generation_id,id,id,worker_id,1,?2,?2,?3,?5,'normal','{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',?4 FROM jobs WHERE id=?1",
            params![f.job,now()+3600,blake3::hash(f.token.as_bytes()).as_bytes().as_slice(),now(),loupe_core::WORKFLOW_CONTRACT_VERSION])?;
        Ok(conn.last_insert_rowid())
    }).unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		unit_holds::admit_exact_batch(scope, batch.batch_id, job, now())
	})
	.unwrap();
	f.job = job;
	// Scheduling/claim integration is still closed. As in the original test,
	// seed only trusted host confirmation after exact admission; the actual
	// finalizer must independently grant Survey Domain authority.
	f.offline.external_corruption(|conn| {
        conn.execute("UPDATE jobs SET head_sha=?2,prepared_at=?3,prepared_attempt=attempts,prepared_capability_hash=job_capability_hash WHERE id=?1",params![job,SHA,now()])?;
        Ok(())
    }).unwrap();
	job
}

#[tokio::test]
async fn zero_progress_continuation_transfers_holds_atomically_with_receipt() {
	for inject in [true, false] {
		let (mut f, generation) = ready().await;
		let (unit, _) = unit(&f, generation, "held", Some("needs_follow_up"));
		let original_job = f.job;
		exact_continuation(&mut f).await;
		if inject {
			f.offline.external_corruption(|conn| {
			conn.execute_batch("CREATE TRIGGER fail_payload BEFORE INSERT ON job_terminal_payloads BEGIN SELECT RAISE(ABORT,'fail after hold movement'); END")?;
			Ok(())
		}).unwrap();
		}
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(
			status,
			if inject { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::OK },
			"{value}"
		);
		common::with_repo(&f.state.db, 1, |scope| {
			let holds = unit_holds::get_hold(scope, unit)?.unwrap();
			assert_eq!(holds.producing_job_id, original_job);
			assert_eq!(holds.source_assignment_epoch, 0);
			assert_eq!(review_units::get(scope, unit)?.unwrap().assignment_epoch, 1);
			let batches = unit_holds::list_batches(scope, f.campaign, 0, 256)?;
			assert_eq!(batches.len(), if inject { 1 } else { 2 });
			assert_eq!(
				batches[0].state,
				if inject {
					loupe_storage::review_intents::State::Admitted
				} else {
					loupe_storage::review_intents::State::Complete
				}
			);
			assert_eq!(holds.pending_batch_id, Some(batches.last().unwrap().batch_id));
			Ok(())
		})
		.unwrap();
		f.offline
			.external_corruption(|conn| {
				assert!(!conn.query_row(
					"SELECT completed FROM job_assigned_review_units WHERE job_id=?1",
					[f.job],
					|r| r.get::<_, bool>(0)
				)?);
				Ok(())
			})
			.unwrap();
		if !inject {
			assert_eq!(value["receipt"]["summary"]["coverage"], "partial");
			assert_eq!(value["receipt"]["summary"]["follow_up_units"], 1);
			assert_eq!(post(&f, "finalize-survey", payload("partial")).await, value);
		}
	}
}

#[tokio::test]
async fn ordinary_conclusive_results_need_exact_assignments_not_creator_identity() {
	let (f, generation) = ready().await;
	unit(&f, generation, "not-assigned", Some("no_lead_found"));
	common::with_repo(&f.state.db, 1, |scope| generations::activate(scope, generation, now()))
		.unwrap();
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",[f.job])?;
		Ok(())
	}).unwrap();
	let (status, value) = request(&f, f.job, "finalize-survey", payload("completed")).await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"ordinary survey creation is not exact assignment authority: {value}"
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
}
