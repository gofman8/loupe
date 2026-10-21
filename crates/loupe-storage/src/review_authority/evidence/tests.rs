use super::*;
use crate::review_authority::tests::{fixture, identity, mutate};
use crate::review_authority::{with_phase_transaction, PolicyDecision};

fn ready() -> crate::Db {
	let db = fixture();
	db.with_conn(|conn| {
  let policy=admission_policy::CampaignPolicyV2::default().canonical_bytes()?;
  conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2",params![std::str::from_utf8(&policy).unwrap(),crate::canonical::digest(&policy).as_slice()])?;
  conn.execute_batch(r#"UPDATE generation_manifests SET expected_entry_count=1,received_entry_count=1 WHERE generation_id=11;
   INSERT INTO generation_inventory(generation_id,path,raw_path,source_path,manifest_position,git_mode,blob_sha,entry_kind,created_at)
   VALUES(11,'z.rs',CAST('z.rs' AS BLOB),'z.rs',0,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0);
   INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at)
   VALUES(31,11,'unit','title','objective','[{"path":"z.rs"}]',101,0);
   INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,0);"#)?;
  Ok(())
 }).unwrap();
	db
}
fn lead() -> LeadEvidenceV1<Agent> {
	crate::test_support::agent(r#"{"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":"entry","review_unit_id":31,"assignment_epoch":0,"hypothesis":"Boundary hypothesis","source_refs":[{"path":"z.rs"}],"next_proof_step":"Trace entry","counterevidence":"Guard absent","proof_gaps":"Need proof"}"#,|raw,mark|LeadEvidenceV1::from_json(mark,raw)).unwrap()
}
fn key() -> Identifier<ClientKey, Worker> {
	crate::test_support::worker("checkpoint", |raw, mark| Identifier::new(mark, raw)).unwrap()
}
fn rows(db: &crate::Db, table: &str) -> i64 {
	db.with_conn(|conn| {
		Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))?)
	})
	.unwrap()
}

#[test]
fn purpose_binding_and_callback_error_preserve_atomic_evidence() {
	let db = ready();
	let key = key();
	let evidence = lead();
	let request = LeadCheckpoint { key: &key, digest: &[1; 32], evidence: &evidence };
	for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost] {
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, access, |_| Ok(Some(PolicyDecision::Ordinary)))?
					.unwrap();
				assert!(matches!(scope.submit_lead_checkpoint(&request), Err(Error::ScopeDenied)));
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
	// debug-ok: a closed callback failure or the storage's redacted error.
	#[derive(Debug)]
	enum Failure {
		Storage(Error),
		Render,
	}
	impl From<Error> for Failure {
		fn from(error: Error) -> Self {
			Self::Storage(error)
		}
	}
	let result = with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::Domain, |_| Ok(Some(PolicyDecision::Ordinary)))?
				.unwrap();
			assert!(matches!(
				scope.submit_sibling_lead_checkpoint(&request),
				Err(Error::ScopeDenied)
			));
			let receipt = scope.submit_lead_checkpoint(&request)?;
			let raw=serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":0,"disposition":"lead_created","inspected_refs":[{"path":"z.rs"}],"created_lead_ids":[receipt.lead_id],"counterevidence":"Guard absent","proof_gaps":"Need proof"}).to_string();
			let payload = crate::test_support::agent(&raw, |raw, mark| {
				UnitResultPayloadV1::from_json(mark, raw)
			})
			.unwrap();
			scope.submit_unit_result_checkpoint(&UnitResultCheckpoint {
				key: &key,
				digest: &[2; 32],
				result: &payload,
			})?;
			Err::<(), Failure>(Failure::Render)
		},
	);
	match result {
		Err(Failure::Render) => {},
		Err(Failure::Storage(error)) => panic!("unexpected storage failure: {error}"),
		Ok(()) => panic!("expected rendering failure"),
	}
	for table in ["leads", "lead_drilldown_intents", "review_unit_results", "job_checkpoints"] {
		assert_eq!(rows(&db, table), 0, "{table}");
	}
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT completed FROM job_assigned_review_units WHERE job_id=101",
				[],
				|row| row.get::<_, i64>(0)
			)?,
			0
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn numeric_replay_precedes_fresh_policy_and_rejects_damaged_receipts() {
	let db = ready();
	let key = key();
	let evidence = lead();
	let request = LeadCheckpoint { key: &key, digest: &[1; 32], evidence: &evidence };
	let submit = || {
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				tx.authorize(Phase::Survey, Access::Domain, |_| Ok(Some(PolicyDecision::Ordinary)))?
					.unwrap()
					.submit_lead_checkpoint(&request)
			},
		)
	};
	let original = submit().unwrap();
	mutate(&db, "UPDATE review_campaigns SET effective_policy='{}'");
	assert_eq!(submit().unwrap(), original);
	for response in [
		r#"{"protocol_version":3,"lead_id":0,"outcome":"created","observation_id":null,"accepted_priority":{"band":"normal","score":0}}"#,
		r#"{"protocol_version":3,"lead_id":1,"lead_id":1,"outcome":"created","observation_id":null,"accepted_priority":{"band":"normal","score":0}}"#,
		r#"{"protocol_version":3,"lead_id":1,"outcome":"created","observation_id":null,"accepted_priority":{"band":"unknown","score":0}}"#,
	] {
		db.with_conn(|conn| {
			conn.execute("UPDATE job_checkpoints SET response=?1", [response])?;
			Ok(())
		})
		.unwrap();
		assert!(matches!(submit(), Err(Error::Conflict(Conflict::Checkpoint))));
	}
	assert_eq!(rows(&db, "leads"), 1);
}
