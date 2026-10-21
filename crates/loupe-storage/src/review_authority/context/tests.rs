use super::*;
use crate::review_authority::{with_phase_transaction, PolicyDecision};

fn fixture() -> crate::Db {
	let db = crate::review_authority::tests::fixture();
	let policy = crate::admission_policy::CampaignPolicyV2::default();
	let bytes = policy.canonical_bytes().unwrap();
	let raw = std::str::from_utf8(&bytes).unwrap();
	db.with_conn(|conn| {
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2",params![raw,crate::canonical::digest(&bytes).as_slice()])?;
		conn.execute_batch("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,1); UPDATE jobs SET soft_deadline_at=700,submit_by=800,hard_deadline_at=900,token_budget=123 WHERE id=101;")?;
		Ok(())
	}).unwrap();
	db
}

#[test]
fn frozen_limits_use_checkout_authority_and_campaign_cutoff() {
	let db = fixture();
	crate::review_authority::tests::mutate(&db,"UPDATE review_campaigns SET deadline_at=750; INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(101,'submit_lead:a','submit_lead',zeroblob(32),'{}',0)");
	for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain] {
		with_phase_transaction(
			&db,
			crate::review_authority::tests::identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, access, |_| Ok(Some(PolicyDecision::Ordinary)))?
					.unwrap();
				if access != Access::Checkout {
					assert!(matches!(scope.limits_snapshot(), Err(Error::ScopeDenied)));
					return Ok::<_, Error>(());
				}
				let limits = scope.limits_snapshot()?;
				assert_eq!(
					(
						limits.soft_deadline_at,
						limits.submit_by,
						limits.hard_deadline_at,
						limits.remaining_seconds
					),
					(700, 750, 750, 650)
				);
				assert_eq!(limits.new_units, CapacitySnapshot { limit: 32, remaining: 32 });
				assert_eq!(limits.leads, CapacitySnapshot { limit: 16, remaining: 15 });
				assert_eq!(limits.siblings, CapacitySnapshot { limit: 0, remaining: 0 });
				assert_eq!(limits.candidate_queries, CapacitySnapshot { limit: 32, remaining: 32 });
				assert_eq!(
					(
						limits.campaign_jobs_limit,
						limits.campaign_jobs_admitted,
						limits.campaign_general_remaining,
						limits.campaign_urgent_remaining,
						limits.campaign_verification_remaining
					),
					(64, 1, 55, 4, 4)
				);
				assert_eq!(limits.token_budget, Some(123));
				Ok(())
			},
		)
		.unwrap();
	}
}

#[test]
fn bootstrap_limits_do_not_require_pinning_or_preparation() {
	let db = fixture();
	crate::review_authority::tests::mutate(&db,"DELETE FROM generation_manifests; UPDATE jobs SET generation_id=NULL,head_sha=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101; UPDATE review_campaigns SET generation_id=NULL; UPDATE jobs SET token_budget=NULL");
	with_phase_transaction(
		&db,
		crate::review_authority::tests::identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::Checkout, |_| {
					Ok(Some(PolicyDecision::Bootstrap))
				})?
				.unwrap();
			assert_eq!(scope.limits_snapshot()?.token_budget, None);
			Ok::<_, Error>(())
		},
	)
	.unwrap();
}

#[test]
fn every_phase_keeps_its_own_limits_and_candidate_purpose() {
	for phase in [Phase::Survey, Phase::Drilldown, Phase::Verify] {
		let db = fixture();
		db.with_conn(|conn| {
			conn.execute_batch("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(31,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0);
			 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES(51,1,101,'test','high','title','description','unique',0);")?;
			conn.execute("UPDATE jobs SET kind=?1,assigned_lead_id=?2,target_finding_id=?3 WHERE id=101",params![phase.job_kind().as_str(),(phase==Phase::Drilldown).then_some(31),(phase==Phase::Verify).then_some(51)])?;
			Ok(())
		}).unwrap();
		for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain]
		{
			with_phase_transaction(
				&db,
				crate::review_authority::tests::identity(),
				|| 100,
				|tx| {
					let scope = tx
						.authorize(phase, access, |_| Ok(Some(PolicyDecision::Ordinary)))?
						.unwrap();
					if access == Access::Checkout {
						let limits = scope.limits_snapshot()?;
						assert_eq!(
							limits.new_units.limit,
							if phase == Phase::Survey { 32 } else { 0 }
						);
						assert_eq!(limits.leads.limit, if phase == Phase::Survey { 16 } else { 0 });
						assert_eq!(
							limits.siblings.limit,
							if phase == Phase::Drilldown { 4 } else { 0 }
						);
						assert_eq!(
							limits.candidate_queries.limit,
							if phase == Phase::Verify { 0 } else { 32 }
						);
					}
					let query = CandidateQuery {
						query: crate::test_support::worker("missing", |raw, mark| {
							loupe_core::review_candidates::QueryText::new(mark, raw)
						})
						.unwrap(),
						limit: 20,
					};
					let result = scope.issue_candidates(&query);
					if access == Access::Domain && phase != Phase::Verify {
						assert!(result?.is_empty());
					} else {
						assert!(matches!(result, Err(Error::ScopeDenied)));
					}
					assert!(!scope.issued_candidate_target(CandidateKind::Finding, 51)?);
					Ok::<_, Error>(())
				},
			)
			.unwrap();
		}
	}
}

#[test]
fn malformed_limits_and_frozen_policy_fail_closed() {
	for sql in [
		"UPDATE jobs SET soft_deadline_at=801 WHERE id=101",
		"UPDATE jobs SET submit_by=901 WHERE id=101",
		"UPDATE jobs SET soft_deadline_at=x'01' WHERE id=101",
		"UPDATE jobs SET soft_deadline_at=NULL WHERE id=101",
		"UPDATE jobs SET token_budget=0 WHERE id=101",
		"UPDATE jobs SET token_budget=-1 WHERE id=101",
		"UPDATE jobs SET token_budget=x'01' WHERE id=101",
		"UPDATE review_campaigns SET effective_policy='{}'",
		"UPDATE review_campaigns SET effective_policy_digest=zeroblob(32)",
		"UPDATE campaign_admission_spending SET general_spent=57",
		"DELETE FROM campaign_admission_spending",
	] {
		let db = fixture();
		// Seed historical/corrupt scalar values deliberately; normal writes keep
		// the schema constraints, while this checks the read boundary itself.
		crate::review_authority::tests::mutate(&db, "PRAGMA ignore_check_constraints=ON");
		crate::review_authority::tests::mutate(&db, sql);
		crate::review_authority::tests::mutate(&db, "PRAGMA ignore_check_constraints=OFF");
		with_phase_transaction(
			&db,
			crate::review_authority::tests::identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, Access::Checkout, |_| {
						Ok(Some(PolicyDecision::Ordinary))
					})?
					.unwrap();
				assert!(
					scope.limits_snapshot().is_err(),
					"malformed retained limits must fail: {sql}"
				);
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
}

#[test]
fn invalid_limit_tuples_keep_their_closed_category() {
	for mutation in [
		"UPDATE jobs SET soft_deadline_at=801 WHERE id=101",
		"UPDATE jobs SET submit_by=901 WHERE id=101",
		"PRAGMA ignore_check_constraints=ON; UPDATE jobs SET token_budget=0 WHERE id=101; PRAGMA ignore_check_constraints=OFF",
	] {
		let db=fixture();
		crate::review_authority::tests::mutate(&db,mutation);
		let result=with_phase_transaction(&db,crate::review_authority::tests::identity(),||100,|tx| {
			let scope=tx.authorize(Phase::Survey,Access::Checkout,|_|Ok(Some(PolicyDecision::Ordinary)))?.unwrap();
			scope.limits_snapshot()
		});
		assert_eq!(format!("{:?}",result.unwrap_err()),"Conflict(Limits)","invalid limit tuple must retain its distinct closed category");
	}
}

#[test]
fn absent_admission_spending_keeps_compatibility_category() {
	let db = fixture();
	crate::review_authority::tests::mutate(&db, "DELETE FROM campaign_admission_spending");
	let result = with_phase_transaction(
		&db,
		crate::review_authority::tests::identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::Checkout, |_| Ok(Some(PolicyDecision::Ordinary)))?
				.unwrap();
			scope.limits_snapshot()
		},
	);
	assert_eq!(
		format!("{:?}", result.unwrap_err()),
		"Conflict(CompatibilityPolicy)",
		"missing admission spending must retain its distinct compatibility category"
	);
	crate::review_authority::tests::mutate(
		&db,
		"INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,57)",
	);
	let result = with_phase_transaction(
		&db,
		crate::review_authority::tests::identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::Checkout, |_| Ok(Some(PolicyDecision::Ordinary)))?
				.unwrap();
			scope.limits_snapshot()
		},
	);
	assert!(
		matches!(result, Err(Error::Conflict(Conflict::CampaignPolicy))),
		"invalid pool counters keep their existing policy category instead of being broadly remapped"
	);
}
