//! Campaign completion must inspect durable work, not just materialized jobs.
use loupe_core::review_payload::{
	ContinuationClass, LeadEvidenceV1, PromotionV1, UnitResultPayloadV1,
};
use loupe_storage::admission_policy::AcceptedPriority;
use loupe_storage::{
	leads, review_findings, review_intents, review_unit_results, review_units, unit_holds,
};
use rusqlite::params;

use super::*;

fn priority() -> AcceptedPriority {
	AcceptedPriority { band: loupe_storage::scheduler::Band::Normal, score: 0 }
}

fn lead_evidence(
	tx: &rusqlite::Transaction<'_>, generation: i64, producer: i64, anchor: &str,
) -> loupe_storage::Result<i64> {
	let payload = crate::test_support::agent(
		&serde_json::json!({
			"format":"loupe.lead_evidence","version":1,"identity_family":"family",
			"identity_anchor":anchor,"hypothesis":"An unchecked request reaches the allocator",
			"source_refs":[{"path":"src.rs"}],"next_proof_step":"Inspect callers",
			"counterevidence":"Some callers validate the request","proof_gaps":"Review remaining callers"
		})
		.to_string(),
		|raw, mark| LeadEvidenceV1::from_json(mark, raw),
	)?;
	let leads::Submitted::Created(id) = leads::submit_evidence(
		&crate::test_support::scope(tx, 1),
		&leads::NewLeadEvidence {
			generation_id: generation,
			created_by_job: producer,
			commit_sha: &common::marked::repo::text(SHA),
			priority: review_units::Priority::Normal,
			payload: &payload,
		},
		0,
	)?
	else {
		panic!("new fixture lead")
	};
	Ok(id)
}

fn retained_drilldown(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, parent: i64, lead: i64,
) -> loupe_storage::Result<i64> {
	tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,parent_job_id,assigned_lead_id,head_sha,workflow_contract_version,scheduling_band,effective_priority,recipe,enqueued_at,finished_at) VALUES(1,'drilldown','succeeded',?1,?2,?3,?4,?5,?6,'normal',0,'{\"version\":1,\"phase\":\"drilldown\"}',0,0)",params![campaign,generation,parent,lead,SHA,WORKFLOW_CONTRACT_VERSION])?;
	Ok(tx.last_insert_rowid())
}

fn pending_lead(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64, due: Option<i64>,
) -> loupe_storage::Result<()> {
	let lead = lead_evidence(tx, generation, job, "pending boundary")?;
	review_intents::ensure_drilldown_intent(
		&crate::test_support::scope(tx, 1),
		lead,
		job,
		priority(),
		0,
	)?
	.unwrap();
	if let Some(due) = due {
		let producer = retained_drilldown(tx, campaign, generation, job, lead)?;
		leads::defer(
			&crate::test_support::scope(tx, 1),
			lead,
			&common::marked::operator::text("source_analysis_remaining"),
			None,
		)?;
		// The fixture starts at a retained logical revision; its producer must
		// be the terminal drilldown for this lead, never the original survey.
		tx.execute("UPDATE lead_drilldown_intents SET originating_job_id=?2,intent_kind='logical_continuation',continuation_class='source_analysis_remaining',logical_sequence=1,not_before=?3 WHERE lead_id=?1",params![lead,producer,due])?;
	}
	Ok(())
}

#[test]
fn campaign_creation_freezes_v2_and_charges_only_preparation_once() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, job) = created(campaign::open(
				&crate::test_support::scope(tx, 1),
				&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
				&ReviewPolicy::default(),
				0,
			)?);
			let stored = campaigns::get(&crate::test_support::scope(tx, 1), campaign)?.unwrap();
			let snapshot: serde_json::Value =
				serde_json::from_str(stored.effective_policy.expose()).unwrap();
			assert_eq!(snapshot["version"], 2, "new campaign must freeze V2 admission policy");
			assert_eq!(
				loupe_storage::admission::get_spending(
					&crate::test_support::scope(tx, 1),
					campaign
				)?
				.unwrap()
				.general,
				1
			);
			assert_eq!(
				tx.query_row(
					"SELECT COUNT(*) FROM job_admission_charges WHERE job_id=?1",
					[job],
					|r| r.get::<_, i64>(0)
				)?,
				1
			);
			assert_eq!(
				campaign::open(
					&crate::test_support::scope(tx, 1),
					&request(RequestedRef::Branch(&common::marked::operator::text("main"))),
					&ReviewPolicy::default(),
					1
				)?,
				Opened::Pending { campaign_id: campaign }
			);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [campaign], |r| {
					r.get::<_, i64>(0)
				})?,
				1
			);
			assert_eq!(
				loupe_storage::admission::get_spending(
					&crate::test_support::scope(tx, 1),
					campaign
				)?
				.unwrap()
				.total()?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn replenish_remains_operator_scoped_even_without_work() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		let (campaign,_)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
		let mut read_only=crate::test_support::scope(tx,1);
		read_only.operator=false;
		assert!(matches!(campaign::replenish(&read_only,campaign,1),Err(Error::ScopeDenied)));
		assert!(matches!(campaign::replenish(&crate::test_support::scope(tx,2),campaign,1),Err(Error::NotFound(crate::Entity::Campaign,id)) if id==campaign));
		assert!(matches!(campaign::replenish(&crate::test_support::scope(tx,1),campaign+100,1),Err(Error::NotFound(crate::Entity::Campaign,_))));
		let before=tx.total_changes();
		assert_eq!(campaign::replenish(&crate::test_support::scope(tx,1),campaign,1)?,None);
		assert_eq!(tx.total_changes(),before);
		Ok(())
	})).unwrap();
}

#[test]
fn blocked_metadata_rolls_back_with_failed_campaign_finish() {
	let db = fixture();
	let campaign=db.with_conn(|conn| transaction::immediate(conn,|tx| {
		let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
		let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
		pending_lead(tx,campaign,generation,job,None)?;
		held_batch(tx,campaign,generation,job)?;
		tx.execute("UPDATE campaign_admission_spending SET general_spent=56,urgent_spent=4,verification_spent=4 WHERE campaign_id=?1",[campaign])?;
		tx.execute_batch("CREATE TEMP TRIGGER reject_finish BEFORE UPDATE OF state ON review_campaigns BEGIN SELECT RAISE(ABORT,'test finish failure'); END")?;
		Ok(campaign)
	})).unwrap();
	assert_eq!(campaign::tick(&db, 1).unwrap().failed, 1);
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT state,block_reason FROM lead_drilldown_intents", [], |r| Ok((
				r.get::<_, String>(0)?,
				r.get::<_, Option<String>>(1)?
			)))?,
			("pending".into(), None)
		);
		assert_eq!(
			conn.query_row(
				"SELECT state,block_reason FROM survey_continuation_batches",
				[],
				|r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
			)?,
			("pending".into(), None)
		);
		assert_eq!(
			conn.query_row("SELECT block_reason FROM review_unit_holds", [], |r| r
				.get::<_, Option<String>>(0))?,
			None
		);
		assert_eq!(
			campaigns::get(&crate::test_support::scope(conn, 1), campaign)?.unwrap().state,
			campaigns::State::Active
		);
		conn.execute_batch("DROP TRIGGER reject_finish")?;
		Ok(())
	})
	.unwrap();
	let report = campaign::tick(&db, 2).unwrap();
	assert_eq!(report.failed, 0);
	assert_eq!(report.completed, 1);
	assert_eq!(report.budget_exhausted, 1);
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT state,block_reason FROM lead_drilldown_intents", [], |r| Ok((
				r.get::<_, String>(0)?,
				r.get::<_, String>(1)?
			)))?,
			("blocked".into(), "campaign_budget".into())
		);
		assert_eq!(
			conn.query_row(
				"SELECT expected_unit_count FROM survey_continuation_batches",
				[],
				|r| r.get::<_, i64>(0)
			)?,
			1
		);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM review_unit_results", [], |r| r.get::<_, i64>(0))?,
			1
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn coverage_replenishment_never_allocates_a_speculative_child() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, true)?;
			assert_eq!(
				campaign::replenish(&crate::test_support::scope(tx, 1), campaign, 1)?,
				None,
				"coverage work must compete at first claim, not consume a queued child"
			);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [campaign], |r| {
					r.get::<_, i64>(0)
				})?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn pending_handoff_without_workers_prevents_premature_completion() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			let job =
				tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| r.get(0))?;
			pending_lead(tx, campaign, generation, job, None)?;
			assert_eq!(
				campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 1)?,
				None,
				"accepted pending lead must remain schedulable without a connected worker"
			);
			assert_eq!(
				campaigns::get(&crate::test_support::scope(tx, 1), campaign)?.unwrap().state,
				campaigns::State::Active
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn delayed_pending_work_due_before_deadline_keeps_campaign_active() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			let job =
				tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| r.get(0))?;
			pending_lead(tx, campaign, generation, job, Some(100))?;
			assert_eq!(
				campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 1)?,
				None,
				"a delayed continuation must not need a speculative child to survive"
			);
			Ok(())
		})
	})
	.unwrap();
}

fn pending_finding(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64,
) -> loupe_storage::Result<()> {
	// Promotion closes a different origin lead, leaving the normal pending
	// lead available as the protected-pool negative control.
	let origin = lead_evidence(tx, generation, job, "promoted boundary")?;
	let producer = retained_drilldown(tx, campaign, generation, job, origin)?;
	let promotion = crate::test_support::agent(&serde_json::json!({
		"version":1,"severity":"high","title":"Canonical finding",
		"description":"Complete original evidence","identity_family":"family",
		"identity_anchor":"promoted boundary","evidence":{"version":1,
		"l2_argument":{"attacker_source":"request","control":"request length",
		"sink":"allocator","reachable_path":"handler to allocator","trust_boundary":"network to memory"},
		"material_locations":[{"role":"sink","file":"src.rs"}],
		"counterevidence":"Caller guard","assumptions_gaps":"Some callers omit the guard","confidence":"medium"}
	}).to_string(), |raw, mark| PromotionV1::from_json(mark, raw))?;
	let profile = common::marked::agent::json::<Payload>("{}");
	let finding = review_findings::insert(
		&crate::test_support::scope(tx, 1),
		&review_findings::NewFinding {
			job_id: producer,
			origin_lead_id: origin,
			profile_version: 1,
			profile_digest: profile.digest(),
			reviewed_commit_sha: &common::marked::repo::text(SHA),
			promotion: &promotion,
		},
		0,
	)?;
	leads::close(
		&crate::test_support::scope(tx, 1),
		origin,
		&leads::Closure::Promoted { finding },
		0,
	)?;
	review_intents::ensure_verification_intent(
		&crate::test_support::scope(tx, 1),
		finding,
		producer,
		priority(),
		0,
	)?
	.unwrap();
	Ok(())
}

#[test]
fn protected_capacity_blocks_normal_lead_but_keeps_verification_pending() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,true)?;
		let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
		pending_lead(tx,campaign,generation,job,None)?;
		pending_finding(tx,campaign,generation,job)?;
		let before_jobs=tx.query_row("SELECT COUNT(*) FROM jobs",[],|r|r.get::<_,i64>(0))?;
		tx.execute("UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,1)?,None);
		assert_eq!(tx.query_row("SELECT block_reason FROM lead_drilldown_intents",[],|r|r.get::<_,Option<String>>(0))?,Some("protected_capacity".into()));
		assert_eq!(tx.query_row("SELECT state FROM finding_verification_intents",[],|r|r.get::<_,String>(0))?,"pending");
		assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs",[],|r|r.get::<_,i64>(0))?,before_jobs,"no speculative verification child");
		tx.execute("UPDATE campaign_admission_spending SET urgent_spent=4,verification_spent=4 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,2)?,Some(campaign::Finish::Completed));
		assert_eq!(tx.query_row("SELECT block_reason FROM finding_verification_intents",[],|r|r.get::<_,String>(0))?,"campaign_budget");
		assert_eq!(tx.query_row("SELECT state,description FROM findings",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?,("validating".into(),"Complete original evidence".into()));
		let saved=campaigns::get(&crate::test_support::scope(tx, 1),campaign)?.unwrap();
		assert_eq!(saved.terminal_reason.unwrap().expose(),"campaign_budget");
		let summary:serde_json::Value=serde_json::from_str(saved.terminal_counts.unwrap().expose()).unwrap();
		assert_eq!(summary["pending_work"]["findings"][0]["count"],1);
		assert_eq!(summary["pending_work"]["findings"][0]["reason"],"campaign_budget");
		Ok(())
	})).unwrap();
}

#[test]
fn due_at_or_beyond_deadline_is_retained_as_blocked_not_polled() {
	for due in [21600, 21601] {
		let db = fixture();
		db.with_conn(|conn|transaction::immediate(conn,|tx| {
			let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
			let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
			pending_lead(tx,campaign,generation,job,Some(due))?;
			assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,1)?,Some(campaign::Finish::Completed));
			assert_eq!(tx.query_row("SELECT state,block_reason,intent_revision,logical_sequence FROM lead_drilldown_intents",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)))?,("blocked".into(),Some("campaign_deadline".into()),1,1));
			Ok(())
		})).unwrap();
	}
}

fn held_batch(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64,
) -> loupe_storage::Result<()> {
	assert_eq!(
		jobs::get(&crate::test_support::scope(tx, 1), job)?.unwrap().campaign_id,
		Some(campaign)
	);
	tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at) VALUES(1,?1,'held','unit','unfinished','[{\"path\":\"src.rs\"}]',?2,0)",params![generation,job])?;
	let payload = crate::test_support::agent(
		&serde_json::json!({
			"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,
			"disposition":"needs_follow_up","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],
			"counterevidence":"Guard found","proof_gaps":"Some callers remain","follow_up":"Review callers",
			"continuation":"source_analysis_remaining"
		})
		.to_string(),
		|raw, mark| UnitResultPayloadV1::from_json(mark, raw),
	)?;
	let result = review_unit_results::insert_evidence(
		&crate::test_support::scope(tx, 1),
		&review_unit_results::NewResultEvidence {
			generation_id: generation,
			produced_by_job: job,
			commit_sha: &common::marked::repo::text(SHA),
			profile_version: 1,
			payload: &payload,
		},
		0,
	)?;
	tx.execute("UPDATE jobs SET state='leased',finished_at=NULL WHERE id=?1", [job])?;
	unit_holds::record_follow_up(
		&crate::test_support::scope(tx, 1),
		1,
		result,
		job,
		0,
		ContinuationClass::SourceAnalysisRemaining,
		0,
	)?;
	tx.execute("UPDATE jobs SET state='succeeded',finished_at=0 WHERE id=?1", [job])?;
	let batches = unit_holds::freeze_survey_batches(&crate::test_support::scope(tx, 1), job, 0)?;
	assert_eq!(batches.len(), 1);
	assert!(batches[0].not_before.is_some_and(|due| due > 2));
	Ok(())
}

#[test]
fn cancellation_and_deadline_preserve_exact_holds_and_live_control_identity() {
	for cancel in [true, false] {
		let db = fixture();
		db.with_conn(|conn|transaction::immediate(conn,|tx| {
			let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
			let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
			pending_lead(tx,campaign,generation,job,None)?;
			pending_finding(tx,campaign,generation,job)?;
			held_batch(tx,campaign,generation,job)?;
			assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,1)?,None,"future exact batch is pending work");
			tx.execute("UPDATE jobs SET state='leased',job_capability_hash=zeroblob(32),lease_expires_at=22000 WHERE id=?1",[job])?;
			let reason=if cancel {
				campaign::cancel(&crate::test_support::scope(tx, 1),campaign,&common::marked::operator::text("operator"),2)?;
				"campaign_cancelled"
			} else {
				assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,21600)?,None);
				"campaign_deadline"
			};
			for table in ["lead_drilldown_intents","finding_verification_intents","survey_continuation_batches","review_unit_holds"] {
				assert_eq!(tx.query_row(&format!("SELECT block_reason FROM {table}"),[],|r|r.get::<_,String>(0))?,reason);
			}
			assert_eq!(tx.query_row("SELECT producing_job_id,producing_result_id,source_assignment_epoch,pending_batch_id,batch_position FROM review_unit_holds",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)))?,(job,1,0,1,0));
			assert_eq!(tx.query_row("SELECT state,length(job_capability_hash),lease_expires_at FROM jobs WHERE id=?1",[job],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?)))?,("leased".into(),32,22000));
			assert_eq!(tx.query_row("SELECT state FROM findings",[],|r|r.get::<_,String>(0))?,"validating");
			assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,reason);
			Ok(())
		})).unwrap();
	}
}

#[test]
fn historical_and_malformed_policies_are_held_without_fabricated_accounting() {
	for raw in [
		serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap(),
		"not json".into(),
	] {
		let db = fixture();
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let (campaign, generation) =
					idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
				let job =
					tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| {
						r.get(0)
					})?;
				pending_finding(tx, campaign, generation, job)?;
				tx.execute(
					"UPDATE review_campaigns SET effective_policy=?2 WHERE campaign_id=?1",
					params![campaign, raw],
				)?;
				assert_eq!(
					campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 1)?,
					Some(campaign::Finish::Completed)
				);
				assert_eq!(
					tx.query_row("SELECT terminal_reason FROM review_campaigns", [], |r| r
						.get::<_, String>(0))?,
					"compatibility_policy"
				);
				assert_eq!(
					tx.query_row("SELECT state FROM findings", [], |r| r.get::<_, String>(0))?,
					"validating"
				);
				assert_eq!(
					loupe_storage::admission::get_spending(
						&crate::test_support::scope(tx, 1),
						campaign
					)?
					.unwrap()
					.total()?,
					1
				);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn b8_reconciliation_is_explicitly_deferred_without_a_preparation_charge() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (previous, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			campaign::try_finish(&crate::test_support::scope(tx, 1), previous, 1)?;
			let reference = common::marked::operator::text("main");
			let mut new = request(RequestedRef::Branch(&reference));
			new.kind_hint = KindHint::FullReview;
			let opened = campaign::open(
				&crate::test_support::scope(tx, 1),
				&new,
				&ReviewPolicy::default(),
				2,
			)?;
			let Opened::Deferred { campaign_id } = opened else {
				panic!("B8 reconciliation must be deferred")
			};
			let row = campaigns::get(&crate::test_support::scope(tx, 1), campaign_id)?.unwrap();
			assert_eq!(row.target_commit_sha.expose(), "main");
			assert_eq!(row.recipe, campaigns::Recipe::Reconciliation);
			assert_eq!(row.terminal_reason.unwrap().expose(), "unsupported_recipe");
			assert_eq!(row.state, campaigns::State::Finished);
			assert_eq!(
				tx.query_row(
					"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",
					[campaign_id],
					|r| r.get::<_, i64>(0)
				)?,
				0
			);
			assert!(loupe_storage::admission::get_spending(
				&crate::test_support::scope(tx, 1),
				campaign_id
			)?
			.is_none());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn terminal_summary_downgrades_stale_complete_coverage_and_preserves_unknown() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, true)?;
			tx.execute(
				"UPDATE review_generations SET coverage='complete' WHERE generation_id=?1",
				[generation],
			)?;
			assert_eq!(
				campaigns::summarize(&crate::test_support::scope(tx, 1), campaign)?.coverage,
				generations::Coverage::Partial,
				"terminal summary cannot preserve stale complete coverage with uncovered units"
			);
			tx.execute(
				"UPDATE review_generations SET coverage='unknown' WHERE generation_id=?1",
				[generation],
			)?;
			assert_eq!(
				campaigns::summarize(&crate::test_support::scope(tx, 1), campaign)?.coverage,
				generations::Coverage::Unknown,
				"summary does not promote historical coverage"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn known_changed_target_is_deferred_without_a_preparation_job_or_charge() {
	for reference in [
		RequestedRef::Pinned(&common::marked::operator::text(DIFFERENT)),
		RequestedRef::Pinned(&common::marked::operator::text(SHA)),
		RequestedRef::Branch(&common::marked::operator::text("main")),
	] {
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let (previous, baseline) =
						idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
					campaign::try_finish(&crate::test_support::scope(tx, 1), previous, 1)?;
					let opened = campaign::open(
						&crate::test_support::scope(tx, 1),
						&request(reference),
						&ReviewPolicy::default(),
						2,
					)?;
					if matches!(reference, RequestedRef::Pinned(value) if value.expose() == DIFFERENT)
					{
						assert!(
							matches!(opened, Opened::Deferred { .. }),
							"known B8 target must not allocate preparation: {opened:?}"
						);
						let Opened::Deferred { campaign_id } = opened else { unreachable!() };
						let row = campaigns::get(&crate::test_support::scope(tx, 1), campaign_id)?
							.unwrap();
						assert_eq!(row.recipe, campaigns::Recipe::Incremental);
						assert_eq!(row.target_commit_sha.expose(), DIFFERENT);
						assert_eq!(row.state, campaigns::State::Finished);
						assert_eq!(row.terminal_reason.unwrap().expose(), "unsupported_recipe");
						assert_eq!(
							tx.query_row(
								"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",
								[campaign_id],
								|r| r.get::<_, i64>(0)
							)?,
							0
						);
						assert_eq!(
							tx.query_row(
								"SELECT COUNT(*) FROM job_admission_charges WHERE campaign_id=?1",
								[campaign_id],
								|r| r.get::<_, i64>(0)
							)?,
							0
						);
						assert!(loupe_storage::admission::get_spending(
							&crate::test_support::scope(tx, 1),
							campaign_id
						)?
						.is_none());
						assert_eq!(
							generations::get(&crate::test_support::scope(tx, 1), baseline)?
								.unwrap()
								.state,
							generations::State::Active
						);
					} else {
						let (campaign, job) = created(opened);
						assert_eq!(
							jobs::get(&crate::test_support::scope(tx, 1), job)?.unwrap().state,
							JobState::Queued
						);
						assert_eq!(
							loupe_storage::admission::get_spending(
								&crate::test_support::scope(tx, 1),
								campaign
							)?
							.unwrap()
							.total()?,
							1
						);
					}
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn exact_batch_alone_waits_then_preserves_members_on_protected_refusal() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
		let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
		held_batch(tx,campaign,generation,job)?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,1)?,None);
		tx.execute("UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx, 1),campaign,2)?,Some(campaign::Finish::Completed));
		assert_eq!(tx.query_row("SELECT state,block_reason,expected_unit_count FROM survey_continuation_batches",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?)))?,("blocked".into(),"protected_capacity".into(),1));
		assert_eq!(tx.query_row("SELECT block_reason FROM review_unit_holds",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM review_unit_results",[],|r|r.get::<_,i64>(0))?,1);
		assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		Ok(())
	})).unwrap();
}

#[test]
fn queued_execution_retry_remains_active_without_spending_again() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			tx.execute(
				"UPDATE jobs SET state='queued',finished_at=NULL,eligible_at=100,attempts=1,recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE campaign_id=?1",
				[campaign],
			)?;
			let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
			assert!(crate::scheduler::initialize_ordinary_batch(tx,job,0)?.units.is_empty());
			assert_eq!(
				campaign::try_finish(&crate::test_support::scope(tx, 1), campaign, 1)?,
				None
			);
			assert_eq!(
				loupe_storage::admission::get_spending(
					&crate::test_support::scope(tx, 1),
					campaign
				)?
				.unwrap()
				.total()?,
				1
			);
			assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, 1);
			Ok(())
		})
	})
	.unwrap();
}
