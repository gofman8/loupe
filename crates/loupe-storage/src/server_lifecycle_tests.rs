//! Server orchestration with explicit worker-state fixtures. Storage tests
//! exercise claims without a reverse dependency; review_public covers the HTTP lifecycle.
use loupe_core::text::policy::Payload;
use loupe_core::{JobKind, JobState};
use loupe_storage::{
	admission_candidates, admission_claim, campaigns, generations, jobs, review_unit_results,
	transaction,
};
use rusqlite::{params, Transaction};

use crate::admission_policy::CampaignPolicyV2 as ReviewPolicy;
use crate::server_campaign_support::{self as common, campaign};

// Pinning only accepts complete object ids.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// This orchestration fixture supplies only the worker state it needs.
// Public lease capabilities and terminal envelopes are covered in review_public.
fn lease_fixture(
	tx: &Transaction<'_>, job_id: i64, worker: i64,
) -> loupe_storage::Result<jobs::JobRow> {
	assert_eq!(
		tx.execute(
			"UPDATE jobs SET state='leased',worker_id=?2,attempts=1,head_sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=?1 AND state='queued'",
			params![job_id, worker],
		)?,
		1
	);
	Ok(jobs::get(&crate::test_support::scope(tx, 1), job_id)?.unwrap())
}

#[test]
fn bootstrap_to_coverage_preserves_the_profile_and_activation() {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		let worker=loupe_storage::workers::insert(tx,&common::marked::operator::text("lifecycle"),loupe_storage::workers::WorkerKind::Worker,&[7;32],0)?;
		let opened=campaign::open(&crate::test_support::scope(tx,1),&campaign::OpenCampaign{trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Branch(&common::marked::operator::text("main")),base_sha:None,kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),0).unwrap();
		let campaign::Opened::Created{campaign_id,job_id}=opened else {panic!("new campaign")};
		let generation=campaign::pin(&crate::test_support::scope(tx,1),campaign_id,job_id,&common::marked::repo::text(SHA),1).unwrap();
		let bootstrap=lease_fixture(tx,job_id,worker)?;
		assert_eq!(bootstrap.kind,JobKind::Survey);
		assert_eq!(bootstrap.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(bootstrap.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"bootstrap");
		common::assert_survey_recipe(tx, &bootstrap, "bootstrap");
		let payload=common::marked::agent::json::<Payload>("{}");
		crate::server_campaign_tests::ready(tx,generation)?;
		for (i,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_by_job_id,created_at) VALUES(?1,?2,?3,'t','o','[{\"path\":\"src.rs\"}]',?4,?5,?1)",params![i as i64+1,generation,format!("unit-{i}"),band,job_id])?;
		}
		let record=|unit,job|->loupe_storage::Result<()> {
			let epoch:i64=tx.query_row("SELECT assignment_epoch FROM review_units WHERE review_unit_id=?1",[unit],|r|r.get(0))?;
			let raw=serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":unit,"assignment_epoch":epoch,"disposition":"no_lead_found","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"Source guard is present","proof_gaps":"No remaining gap"}).to_string();
			let evidence=crate::test_support::agent(&raw,|raw,mark|loupe_core::review_payload::UnitResultPayloadV1::from_json(mark,raw))?;
			let result=review_unit_results::insert_evidence(&crate::test_support::scope(tx,1),&review_unit_results::NewResultEvidence{generation_id:generation,produced_by_job:job,commit_sha:&common::marked::repo::text(SHA),profile_version:1,payload:&evidence},3)?;
			loupe_storage::unit_holds::release_conclusive(&crate::test_support::scope(tx,1),unit,result,job,epoch,3)
		};
		for unit in [1,2] {record(unit,job_id)?;}
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",[campaign_id],|r|r.get::<_,i64>(0))?,1);
		assert_eq!(loupe_storage::admission::get_spending(&crate::test_support::scope(tx,1),campaign_id)?.unwrap().total()?,1);
		// Stand in for the terminal transition; public finalize is tested separately.
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=3 WHERE id=?1",[job_id])?;
		campaign::activate_generation(&crate::test_support::scope(tx,1),campaign_id,3).unwrap();
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),campaign_id,3)?,None);
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",[campaign_id],|r|r.get::<_,i64>(0))?,1);
		assert_eq!(loupe_storage::admission::get_spending(&crate::test_support::scope(tx,1),campaign_id)?.unwrap().total()?,1);
		let policy=crate::scheduler::ClaimPolicy::default();
		let req=admission_candidates::Request{worker_id:worker,legacy_kinds:&[],phase_kinds:&[JobKind::<loupe_provenance::Db>::Survey],now:3,policy:&policy,limit:1};
		let candidates=admission_candidates::ranked_raw(tx,&req)?;
		assert_eq!(candidates.len(),1);
		let admission_claim::Outcome::Uncommitted(claimed)=admission_claim::materialize(tx,&candidates[0],&req,&[5;32],900)? else {panic!("winning coverage candidate")};
		assert_eq!(claimed.assigned_units,vec![3,6,4,5]);
		let batch=claimed.job;
		let coverage=batch.id;
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",[campaign_id],|r|r.get::<_,i64>(0))?,2);
		assert_eq!(loupe_storage::admission::get_spending(&crate::test_support::scope(tx,1),campaign_id)?.unwrap().total()?,2);
		tx.execute("UPDATE jobs SET head_sha=?2 WHERE id=?1",params![coverage,SHA])?;
		assert_eq!(batch.kind,JobKind::Survey);
		assert_eq!(batch.generation_id,Some(generation));
		assert_eq!(batch.continuation_of_job_id,None,"ordinary work is not a logical continuation");
		let recipe:serde_json::Value=serde_json::from_str(batch.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		common::assert_survey_recipe(tx, &batch, "coverage");
		// Typed accepted results close exactly the real admission's four members.
		for unit in [3,6,4,5] {record(unit,coverage)?;}
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=5 WHERE id=?1",[coverage])?;
		assert!(generations::coverage_rollup(&crate::test_support::scope(tx,1),generation)?.complete());
		let after=generations::get(&crate::test_support::scope(tx,1),generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.activated_at,Some(3));
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),campaign_id,5).unwrap(),Some(campaign::Finish::Completed));
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",[campaign_id],|r|r.get::<_,i64>(0))?,2);
		assert_eq!(loupe_storage::admission::get_spending(&crate::test_support::scope(tx,1),campaign_id)?.unwrap().total()?,2);
		let row=campaigns::get(&crate::test_support::scope(tx,1),campaign_id)?.unwrap();
		assert_eq!(row.state,campaigns::State::Finished);
		assert!(row.terminal_counts.is_some());

		// The activated baseline survives campaign boundaries. The next
		// incremental survey reuses it, including profile and activation time.
		let opened=campaign::open(&crate::test_support::scope(tx,1),&campaign::OpenCampaign{trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Pinned(&common::marked::operator::text(SHA)),base_sha:Some(&common::marked::operator::text(SHA)),kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),6).unwrap();
		let campaign::Opened::Created{campaign_id:second,job_id:initial}=opened else {panic!("second campaign")};
		let row=campaigns::get(&crate::test_support::scope(tx,1),second)?.unwrap();
		assert_eq!(row.recipe,campaigns::Recipe::Incremental);
		assert_eq!(row.generation_id,Some(generation));
		let incremental=lease_fixture(tx,initial,worker)?;
		assert_eq!(incremental.kind,JobKind::Survey);
		assert_eq!(incremental.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(incremental.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"incremental");
		common::assert_survey_recipe(tx, &incremental, "incremental");
		// Storage's companion claim test checks that this baseline yields
		// an empty incremental batch after all units have been completed.
		let recipe=common::marked::agent::json::<Payload>(r#"{"version":1,"phase":"survey","recipe":"incremental","assignment_key":"ordinary"}"#);
		// Explicit queued retry fixture, not a speculative production preparation.
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,enqueued_at,recipe) VALUES(1,'survey','queued',?1,?2,7,?3)",params![second,generation,recipe.expose()])?;
		let queued=tx.last_insert_rowid();
		common::assert_survey_recipe(tx, &jobs::get(&crate::test_support::scope(tx,1), queued)?.unwrap(), "incremental");
		let deadline=row.deadline_at.unwrap();
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),second,deadline).unwrap(),None);
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),queued)?.unwrap().state,JobState::Cancelled);
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),initial)?.unwrap().state,JobState::Leased);
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=?2 WHERE id=?1",params![initial,deadline+1])?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),second,deadline+1).unwrap(),Some(campaign::Finish::DeadlineReached));
		let after=generations::get(&crate::test_support::scope(tx,1),generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.generated_profile.as_ref().map(|v| v.expose()),Some(payload.expose()));
		assert_eq!(after.activated_at,Some(3));
		Ok(())
	})).unwrap();
}
