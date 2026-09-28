use loupe_core::review_payload::{LeadEvidenceV1, UnitResultPayloadV1};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection};
use serde_json::json;

use crate::review_tests::fixture;
use crate::review_units::Priority;
use crate::test_support::{self as input, scope, scoped};
use crate::{
	lead_observations as observations, leads, review_unit_results as results, transaction,
	StoredEvidence,
};

fn seed(conn: &Connection) {
	let policy = crate::canonical::canonical_bytes(
		&serde_json::to_value(crate::scheduler::CampaignPolicy::default()).unwrap(),
	);
	conn.execute(
		"UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2",
		params![
			std::str::from_utf8(&policy).unwrap(),
			crate::canonical::digest(&policy).as_slice()
		],
	)
	.unwrap();
	conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,11,'first','title','objective','[]',0),(32,11,'second','title','objective','[]',0),(41,21,'foreign','title','objective','[]',0)").unwrap();
}
pub(crate) fn lead() -> LeadEvidenceV1<Agent> {
	parse_lead(&json!({
		"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass",
		"identity_anchor":"request guard","identity_instance_key":"administrator route",
		"review_unit_id":31,"assignment_epoch":0,"hypothesis":"wrapper bypass",
		"invariant_or_boundary":"authentication boundary","source_refs":[{"path":"cafe\u{301}.rs","symbol":"cafe\u{301}"}],
		"next_proof_step":"trace wrapper","counterevidence":"guard exists","proof_gaps":"entry is uncertain",
		"priority_proposal":{"impact":"high","access":"remote","reachability":"traced",
			"boundary_refs":[{"path":"cafe\u{301}.rs"}],"rationale":"exposed boundary"}
	}).to_string()).unwrap()
}
pub(crate) fn result() -> UnitResultPayloadV1<Agent> {
	parse_result(
		&json!({
			"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":0,
			"disposition":"needs_follow_up","inspected_refs":[{"path":"cafe\u{301}.rs"}],
			"created_lead_ids":[],"counterevidence":"guard exists","proof_gaps":"entry is uncertain",
			"follow_up":"trace entry","notes":"retain all context","continuation":"source_analysis_remaining"
		})
		.to_string(),
	)
	.unwrap()
}
fn submit(conn: &mut Connection, payload: &LeadEvidenceV1<Agent>) -> leads::Submitted {
	submit_evidence(
		conn,
		&leads::NewLeadEvidence {
			generation_id: 11,
			created_by_job: 101,
			commit_sha: &input::db_text("copied-commit").unwrap(),
			priority: Priority::High,
			payload,
		},
		123,
	)
	.unwrap()
}
fn inserted_id(conn: &mut Connection, payload: &LeadEvidenceV1<Agent>) -> i64 {
	let leads::Submitted::Created(id) = submit(conn, payload) else { panic!("created") };
	id
}
fn insert_result(conn: &mut Connection, payload: &UnitResultPayloadV1<Agent>) -> i64 {
	insert_result_evidence(
		conn,
		&results::NewResultEvidence {
			generation_id: 11,
			produced_by_job: 101,
			commit_sha: &input::db_text("copied-commit").unwrap(),
			profile_version: 3,
			payload,
		},
		456,
	)
	.unwrap()
}

#[test]
fn typed_lead_round_trip_has_one_payload_and_exact_paths() {
	fixture().with_conn(|conn| {
		seed(conn);
		let payload = lead(); let id = inserted_id(conn,&payload);
		assert_eq!(leads::get_evidence(&scope(conn,1),id)?,StoredEvidence::Recorded(payload.clone()));
		let metadata = leads::get_metadata(&scope(conn,1),id)?.unwrap();
		assert_eq!(metadata.unit_id,Some(31)); assert_eq!(metadata.priority,Priority::High);
		assert_eq!(metadata.commit_sha.expose(),"copied-commit"); assert_eq!(metadata.created_by_job,Some(101));
		assert_eq!(metadata.created_at,123);
		let (raw,digest,proposal):(String,Vec<u8>,Option<String>) = conn.query_row("SELECT anchored_payload,anchored_digest,priority_proposal FROM leads WHERE lead_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
		assert_eq!(raw.as_bytes(),payload.canonical_bytes()?); assert_eq!(digest,payload.digest()?);
		assert!(raw.contains("cafe\u{301}.rs")); assert!(proposal.is_none());
		assert!(leads::get(&scope(conn,1),id).is_err());
		close(conn,id,&leads::Closure::Rejected,999)?;
		assert_eq!(leads::get_evidence(&scope(conn,1),id)?,StoredEvidence::Recorded(payload));
		assert_eq!(leads::get_metadata(&scope(conn,1),id)?.unwrap().disposition,Some(leads::Disposition::Rejected));
		Ok(())
	}).unwrap();
}

#[test]
fn duplicate_and_closed_identity_retain_complete_new_observations() {
	fixture().with_conn(|conn| {
		seed(conn);
		let original = lead(); let id = inserted_id(conn,&original);
		let mut attached = original.clone();
		attached.review_unit_id = Some(32); attached.assignment_epoch = Some(7);
		attached.hypothesis = input::text("different hypothesis").unwrap();
		attached.invariant_or_boundary = Some(input::text("different boundary").unwrap());
		attached.source_refs[0].path = input::path("café.rs").unwrap();
		attached.priority_proposal.as_mut().unwrap().impact = loupe_core::review_priority::Impact::Critical;
		attached.duplicate_hint = Some(loupe_core::review_payload::DuplicateLeadHint {lead_id:id,rationale:input::text("same identity").unwrap()});
		assert_eq!(submit(conn,&attached),leads::Submitted::Attached {lead_id:id,status:leads::Status::Open});
		close(conn,id,&leads::Closure::Hardening,200)?;
		assert!(matches!(submit(conn,&attached),leads::Submitted::ClosedExists {lead_id,disposition:leads::Disposition::Hardening,..} if lead_id==id));
		assert_eq!(leads::get_evidence(&scope(conn,1),id)?,StoredEvidence::Recorded(original));
		let rows = observations::list_evidence(&scope(conn,1),id)?;
		assert_eq!(rows.len(),2);
		assert!(rows[0].observation_id < rows[1].observation_id);
		for row in rows {
			assert_eq!(row.payload,StoredEvidence::Recorded(attached.clone()));
			assert_eq!(row.lead_id,id); assert_eq!(row.submitted_by_job,Some(101));
			assert_eq!(row.commit_sha.expose(),"copied-commit"); assert_eq!(row.created_at,123);
		}
		assert!(observations::list(&scope(conn,1),id).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn typed_result_round_trip_preserves_all_fields_and_provenance() {
	fixture().with_conn(|conn| {
		seed(conn); let payload = result(); let id = insert_result(conn,&payload);
		assert_eq!(results::get_evidence(&scope(conn,1),id)?,StoredEvidence::Recorded(payload.clone()));
		let rows = results::list_evidence(&scope(conn,1),31)?; assert_eq!(rows.len(),1);
		let row = &rows[0]; assert_eq!(row.result_id,id); assert_eq!(row.unit_id,31);
		assert_eq!(row.produced_by_job,Some(101)); assert_eq!(row.commit_sha.expose(),"copied-commit");
		assert_eq!(row.profile_version,3); assert_eq!(row.created_at,456);
		assert_eq!(row.payload,StoredEvidence::Recorded(payload.clone()));
		let (raw,digest,refs,counter,gaps):(String,Vec<u8>,String,Option<String>,Option<String>) = conn.query_row("SELECT result_payload,result_digest,inspected_refs,counterevidence,proof_gaps FROM review_unit_results WHERE review_unit_result_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
		assert_eq!(raw.as_bytes(),payload.canonical_bytes()?); assert_eq!(digest,payload.digest()?);
		assert!(refs.contains("cafe\u{301}.rs")); assert!(counter.is_none() && gaps.is_none());
		assert!(results::list(&scope(conn,1),31).is_err());
		invalidate(conn,id,&input::text("source changed").unwrap())?;
		let rows = results::list_evidence(&scope(conn,1),31)?; assert!(rows[0].invalidated);
		assert_eq!(rows[0].invalidated_reason.as_ref().unwrap().expose(),"source changed");
		assert_eq!(rows[0].payload,StoredEvidence::Recorded(payload));
		Ok(())
	}).unwrap();
}

#[test]
fn historical_payloads_stay_readable_and_missing_is_distinct() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			for raw in ["{}", "[]", "null", r#"{"format":"unrelated","version":99}"#] {
				let data = input::json(raw).unwrap();
				let identity = crate::identity::Identity {
					family: input::identifier("auth-bypass").unwrap(),
					anchor: input::anchor(&format!("boundary {}", raw.len())).unwrap(),
					instance: None,
				};
				let outcome = submit_historical(
					conn,
					&leads::NewLead {
						generation_id: 11,
						unit_id: None,
						identity: &identity,
						payload: &data,
						commit_sha: &input::db_text("base").unwrap(),
						priority: Priority::Normal,
						priority_proposal: None,
						supersedes: None,
						created_by_job: Some(101),
					},
					0,
				)?;
				let id = match outcome {
					leads::Submitted::Created(id) => id,
					leads::Submitted::Attached { lead_id, .. } => lead_id,
					_ => unreachable!(),
				};
				assert_eq!(leads::get_evidence(&scope(conn, 1), id)?, StoredEvidence::Historical);
				assert!(leads::get(&scope(conn, 1), id)?.is_some());
				insert_observation(
					conn,
					&observations::NewObservation {
						lead_id: id,
						submitted_by_job: Some(101),
						payload: &data,
						commit_sha: &input::db_text("base").unwrap(),
					},
					1,
				)?;
				assert!(observations::list(&scope(conn, 1), id)?
					.iter()
					.any(|row| row.payload == data));
				assert!(observations::list_evidence(&scope(conn, 1), id)?
					.iter()
					.all(|row| row.payload == StoredEvidence::Historical));
				let result_id = insert_historical_result(
					conn,
					&results::NewResult {
						generation_id: 11,
						unit_id: 31,
						produced_by_job: Some(101),
						commit_sha: &input::db_text("base").unwrap(),
						profile_version: 1,
						disposition: results::Disposition::NoLeadFound,
						inspected_refs: &input::refs::<64>(vec![]).unwrap(),
						counterevidence: None,
						proof_gaps: None,
						payload: &data,
						corroborates_result: None,
						corroborates_exclusion: None,
					},
					0,
				)?;
				assert_eq!(
					results::get_evidence(&scope(conn, 1), result_id)?,
					StoredEvidence::Historical
				);
			}
			assert_eq!(results::list(&scope(conn, 1), 31)?.len(), 4);
			assert_eq!(leads::get_evidence(&scope(conn, 1), 999)?, StoredEvidence::Missing);
			assert_eq!(results::get_evidence(&scope(conn, 1), 999)?, StoredEvidence::Missing);
			Ok(())
		})
		.unwrap();
}

#[test]
fn lead_digest_mismatch_keeps_checkpoint_conflict() {
	assert_digest_conflict("leads");
}

#[test]
fn observation_digest_mismatch_keeps_checkpoint_conflict() {
	assert_digest_conflict("lead_observations");
}

#[test]
fn result_digest_mismatch_keeps_checkpoint_conflict() {
	assert_digest_conflict("review_unit_results");
}

fn assert_digest_conflict(table: &str) {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let lead_id = inserted_id(conn, &lead());
			submit(conn, &lead());
			let result_id = insert_result(conn, &result());
			assert_eq!(
				leads::get_evidence(&scope(conn, 1), lead_id)?,
				StoredEvidence::Recorded(lead())
			);
			assert_eq!(
				observations::list_evidence(&scope(conn, 1), lead_id)?[0].payload,
				StoredEvidence::Recorded(lead())
			);
			assert_eq!(
				results::get_evidence(&scope(conn, 1), result_id)?,
				StoredEvidence::Recorded(result())
			);
			let (column, digest) = match table {
				"leads" => ("anchored_payload", "anchored_digest"),
				"lead_observations" => ("observation_payload", "observation_digest"),
				_ => ("result_payload", "result_digest"),
			};
			let original: (String, String) =
				conn.query_row(&format!("SELECT {column},source FROM {table}"), [], |row| {
					Ok((row.get(0)?, row.get(1)?))
				})?;
			for (value, mismatch) in [("zeroblob(32)", true), ("'wrong SQL type'", false)] {
				conn.execute(&format!("UPDATE {table} SET {digest}={value}"), [])?;
				let actual = match table {
					"leads" => leads::get_evidence(&scope(conn, 1), lead_id).map(|_| ()),
					"lead_observations" => {
						observations::list_evidence(&scope(conn, 1), lead_id).map(|_| ())
					},
					_ => results::get_evidence(&scope(conn, 1), result_id).map(|_| ()),
				};
				if mismatch {
					assert!(
						matches!(
							actual,
							Err(crate::Error::Conflict(crate::Conflict::CheckpointEvidence))
						),
						"digest mismatch must remain a checkpoint conflict for {table}: {actual:?}"
					);
				} else {
					assert!(
						matches!(actual, Err(crate::Error::Sqlite(_))),
						"SQL type errors must retain their category for {table}: {actual:?}"
					);
				}
				let retained: (String, String) =
					conn.query_row(&format!("SELECT {column},source FROM {table}"), [], |row| {
						Ok((row.get(0)?, row.get(1)?))
					})?;
				assert_eq!(
					retained, original,
					"a failed read must not rewrite canonical evidence or its source"
				);
			}
			Ok(())
		})
		.unwrap();
}

#[test]
fn typed_reads_reject_noncanonical_corrupt_and_future_evidence() {
	for bad_kind in
		["digest", "noncanonical", "future", "malformed", "wrong_format", "duplicate_format"]
	{
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let payload = lead();
				let id = inserted_id(conn, &payload);
				let raw = String::from_utf8(payload.canonical_bytes()?).unwrap();
				let bad = match bad_kind {
					"digest" => raw.clone(),
					"noncanonical" => format!(" {raw}"),
					"future" => raw.replace("\"version\":1", "\"version\":2"),
					"malformed" => r#"{"format":"loupe.lead_evidence","version":1}"#.into(),
					"wrong_format" => raw.replace("loupe.lead_evidence", "loupe.future_evidence"),
					_ => format!("{{\"format\":\"loupe.lead_evidence\",{}", &raw[1..]),
				};
				let digest = if bad_kind == "digest" {
					[0u8; 32]
				} else {
					crate::canonical::digest(bad.as_bytes())
				};
				conn.execute(
					"UPDATE leads SET anchored_payload=?2,anchored_digest=?3 WHERE lead_id=?1",
					params![id, bad, digest.as_slice()],
				)?;
				assert!(leads::get_evidence(&scope(conn, 1), id).is_err(), "{bad_kind}");
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn lead_projection_mismatches_are_not_independent_sources() {
	for update in [
		"review_unit_id=32",
		"identity_family='other-family'",
		"identity_anchor='other anchor'",
		"identity_instance_key=NULL",
		"identity_fingerprint=zeroblob(32)",
		"priority_proposal='{}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let id = inserted_id(conn, &lead());
				conn.execute(&format!("UPDATE leads SET {update} WHERE lead_id=?1"), [id])?;
				assert!(leads::get_evidence(&scope(conn, 1), id).is_err(), "{update}");
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn result_projection_and_digest_mismatches_are_rejected() {
	for update in [
		"review_unit_id=32",
		"disposition='no_lead_found'",
		"inspected_refs='[]'",
		"counterevidence='shadow'",
		"proof_gaps='shadow'",
		"result_digest=zeroblob(32)",
		"result_payload='{}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let id = insert_result(conn, &result());
				conn.execute(
					&format!(
						"UPDATE review_unit_results SET {update} WHERE review_unit_result_id=?1"
					),
					[id],
				)?;
				if update == "result_payload='{}'" {
					assert_eq!(
						results::get_evidence(&scope(conn, 1), id)?,
						StoredEvidence::Historical,
						"untagged historical evidence is never promoted to modern"
					);
				} else {
					assert!(results::get_evidence(&scope(conn, 1), id).is_err(), "{update}");
				}
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn observation_digest_and_identity_are_checked() {
	for update in [
		"observation_digest=zeroblob(32)",
		"observation_payload=' {\"format\":\"loupe.lead_evidence\"}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let payload = lead();
				let id = inserted_id(conn, &payload);
				submit(conn, &payload);
				conn.execute(
					&format!("UPDATE lead_observations SET {update} WHERE lead_id=?1"),
					[id],
				)?;
				assert!(observations::list_evidence(&scope(conn, 1), id).is_err(), "{update}");
				Ok(())
			})
			.unwrap();
	}
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			let id = inserted_id(conn, &payload);
			payload.identity_anchor = input::anchor("different identity").unwrap();
			assert!(insert_observation_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					payload: &payload
				},
				0
			)
			.is_err());
			Ok(())
		})
		.unwrap();
}

#[test]
fn typed_inserts_validate_scope_and_roll_back_atomically() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			payload.review_unit_id = Some(41);
			assert!(submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					priority: Priority::Normal,
					payload: &payload
				},
				0
			)
			.is_err());
			payload.review_unit_id = Some(31);
			assert!(submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 201,
					commit_sha: &input::db_text("base").unwrap(),
					priority: Priority::Normal,
					payload: &payload
				},
				0
			)
			.is_err());
			let result = transaction::immediate(conn, |tx| {
				leads::submit_evidence(
					&scope(tx, 1),
					&leads::NewLeadEvidence {
						generation_id: 11,
						created_by_job: 101,
						commit_sha: &input::db_text("base").unwrap(),
						priority: Priority::Normal,
						payload: &payload,
					},
					0,
				)?;
				Err::<(), _>(crate::Error::Conflict(crate::Conflict::Checkpoint))
			});
			assert!(result.is_err());
			assert_eq!(
				conn.query_row("SELECT count(*) FROM leads", [], |r| r.get::<_, i64>(0))?,
				0
			);
			let mut payload = result_payload_for_foreign_unit();
			assert!(insert_result_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			payload.review_unit_id = 31;
			assert!(insert_result_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 201,
					commit_sha: &input::db_text("base").unwrap(),
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			assert_eq!(
				conn.query_row("SELECT count(*) FROM review_unit_results", [], |r| r
					.get::<_, i64>(0))?,
				0
			);
			Ok(())
		})
		.unwrap();
}
fn result_payload_for_foreign_unit() -> UnitResultPayloadV1<Agent> {
	let mut payload = result();
	payload.review_unit_id = 41;
	payload
}

#[test]
fn typed_results_retain_created_leads_and_reject_foreign_links() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let lead_id = inserted_id(conn, &lead());
			let mut payload = result();
			payload.disposition = results::Disposition::LeadCreated;
			payload.created_lead_ids = vec![lead_id];
			payload.follow_up = None;
			payload.continuation = None;
			let id = insert_result(conn, &payload);
			assert_eq!(
				results::get_evidence(&scope(conn, 1), id)?,
				StoredEvidence::Recorded(payload.clone())
			);
			payload.created_lead_ids = vec![999];
			assert!(insert_result_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			let mut foreign = lead();
			foreign.review_unit_id = Some(41);
			let leads::Submitted::Created(foreign_id) = submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 21,
					created_by_job: 201,
					commit_sha: &input::db_text("foreign").unwrap(),
					priority: Priority::Normal,
					payload: &foreign,
				},
				0,
			)?
			else {
				panic!("foreign lead")
			};
			payload.created_lead_ids = vec![foreign_id];
			assert!(insert_result_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			assert_eq!(results::list_evidence(&scope(conn, 1), 31)?.len(), 1);
			Ok(())
		})
		.unwrap();
}

#[test]
fn evidence_and_priority_refs_use_exact_inventory_membership() {
	use crate::inventory::{self, NewEntry};
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let path = input::inventory_path("cafe\u{301}.rs".as_bytes());
			insert_inventory(
				conn,
				11,
				&[NewEntry {
					path: &path,
					blob_sha: Some(&input::db_text("blob").unwrap()),
					kind: inventory::EntryKind::Tracked,
					disposition: inventory::Disposition::Unresolved,
					reason: None::<
						&loupe_core::text::BoundedText<loupe_core::text::policy::Reason, Db>,
					>,
					highlighted: false,
				}],
				0,
			)?;
			let original = lead();
			let id = inserted_id(conn, &original);
			let mut bad = original.clone();
			bad.source_refs[0].path = input::path("café.rs").unwrap();
			assert!(submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					priority: Priority::Normal,
					payload: &bad
				},
				0
			)
			.is_err());
			bad = original.clone();
			bad.priority_proposal.as_mut().unwrap().boundary_refs[0].path =
				input::path("café.rs").unwrap();
			assert!(insert_observation_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					payload: &bad
				},
				0
			)
			.is_err());
			let mut bad = result();
			bad.inspected_refs[0].path = input::path("café.rs").unwrap();
			assert!(insert_result_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: &input::db_text("base").unwrap(),
					profile_version: 1,
					payload: &bad
				},
				0
			)
			.is_err());
			assert!(observations::list_evidence(&scope(conn, 1), id)?.is_empty());
			assert!(results::list_evidence(&scope(conn, 1), 31)?.is_empty());
			Ok(())
		})
		.unwrap();
}

#[test]
fn direct_typed_observation_retains_payload_and_provenance() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			let id = inserted_id(conn, &payload);
			payload.review_unit_id = Some(32);
			payload.assignment_epoch = Some(10);
			let observation_id = insert_observation_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: &input::db_text("observed-commit").unwrap(),
					payload: &payload,
				},
				300,
			)?;
			let rows = observations::list_evidence(&scope(conn, 1), id)?;
			assert_eq!(rows.len(), 1);
			assert_eq!(rows[0].observation_id, observation_id);
			assert_eq!(rows[0].commit_sha.expose(), "observed-commit");
			assert_eq!(rows[0].created_at, 300);
			assert_eq!(rows[0].submitted_by_job, Some(101));
			assert_eq!(rows[0].payload, StoredEvidence::Recorded(payload));
			// A changed relational identity must not reinterpret immutable observation bytes.
			conn.execute(
				"UPDATE leads SET identity_anchor='unrelated boundary' WHERE lead_id=?1",
				[id],
			)?;
			assert!(observations::list_evidence(&scope(conn, 1), id).is_err());
			Ok(())
		})
		.unwrap();
}

#[test]
fn result_and_observation_readers_reject_future_and_noncanonical_typed_bytes() {
	for noncanonical in [false, true] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let lead_payload = lead();
				let lead_id = inserted_id(conn, &lead_payload);
				submit(conn, &lead_payload);
				let result_payload = result();
				let result_id = insert_result(conn, &result_payload);
				for (table, column, digest, id_column, id, bytes) in [
					(
						"lead_observations",
						"observation_payload",
						"observation_digest",
						"lead_id",
						lead_id,
						lead_payload.canonical_bytes()?,
					),
					(
						"review_unit_results",
						"result_payload",
						"result_digest",
						"review_unit_result_id",
						result_id,
						result_payload.canonical_bytes()?,
					),
				] {
					let raw = String::from_utf8(bytes).unwrap();
					let bad = if noncanonical {
						format!(" {raw}")
					} else {
						raw.replace("\"version\":1", "\"version\":2")
					};
					conn.execute(
						&format!("UPDATE {table} SET {column}=?2,{digest}=?3 WHERE {id_column}=?1"),
						params![id, bad, crate::canonical::digest(bad.as_bytes()).as_slice()],
					)?;
				}
				assert!(observations::list_evidence(&scope(conn, 1), lead_id).is_err());
				assert!(results::get_evidence(&scope(conn, 1), result_id).is_err());
				Ok(())
			})
			.unwrap();
	}
}

fn parse_lead(raw: &str) -> Result<LeadEvidenceV1<Agent>, loupe_core::review_payload::Error> {
	input::agent(raw, |raw, mark| LeadEvidenceV1::from_json(mark, raw))
}
fn parse_result(
	raw: &str,
) -> Result<UnitResultPayloadV1<Agent>, loupe_core::review_payload::Error> {
	input::agent(raw, |raw, mark| UnitResultPayloadV1::from_json(mark, raw))
}
fn submit_evidence<S: Source>(
	conn: &mut Connection, new: &leads::NewLeadEvidence<'_, S>, now: i64,
) -> crate::Result<leads::Submitted> {
	let repo = if new.generation_id == 21 { 2 } else { 1 };
	scoped(conn, repo, |scope| leads::submit_evidence(scope, new, now))
}
fn submit_historical<S: Source>(
	conn: &mut Connection, new: &leads::NewLead<'_, S>, now: i64,
) -> crate::Result<leads::Submitted> {
	scoped(conn, 1, |scope| leads::submit(scope, new, now))
}
fn close(conn: &mut Connection, id: i64, closure: &leads::Closure, now: i64) -> crate::Result<()> {
	scoped(conn, 1, |scope| leads::close(scope, id, closure, now))
}
fn insert_observation_evidence<S: Source>(
	conn: &mut Connection, new: &observations::NewObservationEvidence<'_, S>, now: i64,
) -> crate::Result<i64> {
	scoped(conn, 1, |scope| observations::insert_evidence(scope, new, now))
}
fn insert_observation<S: Source>(
	conn: &mut Connection, new: &observations::NewObservation<'_, S>, now: i64,
) -> crate::Result<i64> {
	scoped(conn, 1, |scope| observations::insert(scope, new, now))
}
fn insert_result_evidence<S: Source>(
	conn: &mut Connection, new: &results::NewResultEvidence<'_, S>, now: i64,
) -> crate::Result<i64> {
	scoped(conn, 1, |scope| results::insert_evidence(scope, new, now))
}
fn insert_historical_result<S: Source>(
	conn: &mut Connection, new: &results::NewResult<'_, S>, now: i64,
) -> crate::Result<i64> {
	scoped(conn, 1, |scope| results::insert(scope, new, now))
}
fn invalidate<S: Source>(
	conn: &mut Connection, id: i64,
	reason: &loupe_core::text::BoundedText<loupe_core::text::policy::Reason, S>,
) -> crate::Result<()> {
	scoped(conn, 1, |scope| results::invalidate(scope, id, reason))
}
fn insert_inventory<P: Source, R: Source, T: Source>(
	conn: &mut Connection, generation: i64, entries: &[crate::inventory::NewEntry<'_, P, R, T>],
	now: i64,
) -> crate::Result<crate::inventory::Inserted> {
	scoped(conn, 1, |scope| crate::inventory::insert(scope, generation, entries, now))
}

#[test]
fn modern_checkpoint_rows_survive_reopen_without_rewriting_bytes() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("checkpoint.sqlite");
	let key = crate::secrets::MasterKey::for_tests();
	let db = crate::Db::open(&path, &key).unwrap();
	crate::review_tests::seed(&db);
	let (lead_id, result_id) = db
		.with_conn(|conn| {
			seed(conn);
			let lead_id = inserted_id(conn, &lead());
			submit(conn, &lead());
			let result_id = insert_result(conn, &result());
			crate::migrations::admission::validate(conn)?;
			Ok((lead_id, result_id))
		})
		.unwrap();
	drop(db);
	let db = crate::Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		assert_eq!(
			leads::get_evidence(&scope(conn, 1), lead_id)?,
			StoredEvidence::Recorded(lead())
		);
		assert_eq!(
			observations::list_evidence(&scope(conn, 1), lead_id)?[0].payload,
			StoredEvidence::Recorded(lead())
		);
		assert_eq!(
			results::get_evidence(&scope(conn, 1), result_id)?,
			StoredEvidence::Recorded(result())
		);
		assert_eq!(
			conn.query_row(
				"SELECT anchored_payload FROM leads WHERE lead_id=?1",
				[lead_id],
				|r| r.get::<_, String>(0)
			)?
			.as_bytes(),
			lead().canonical_bytes()?
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn foreign_malformed_checkpoint_rows_are_filtered_before_decoding() {
	fixture().with_conn(|conn|{
  seed(conn);
  let lead_id=inserted_id(conn,&lead());
  submit(conn,&lead());
  let result_id=insert_result(conn,&result());
  conn.execute_batch("UPDATE leads SET anchored_payload=x'ff',identity_family=x'ff'; UPDATE lead_observations SET observation_payload=x'ff'; UPDATE review_unit_results SET result_payload=x'ff'")?;
  assert_eq!(leads::get_evidence(&scope(conn,2),lead_id)?,StoredEvidence::Missing);
  assert!(leads::get_metadata(&scope(conn,2),lead_id)?.is_none());
  assert!(observations::list_evidence(&scope(conn,2),lead_id)?.is_empty());
  assert_eq!(results::get_evidence(&scope(conn,2),result_id)?,StoredEvidence::Missing);
  assert!(results::list_evidence(&scope(conn,2),31)?.is_empty());
  assert!(leads::get_evidence(&scope(conn,1),lead_id).is_err());
  assert!(leads::get_metadata(&scope(conn,1),lead_id).is_err());
  assert!(observations::list_evidence(&scope(conn,1),lead_id).is_err());
  assert!(results::get_evidence(&scope(conn,1),result_id).is_err());
  Ok(())
 }).unwrap();
}

#[test]
fn checkpoint_sources_are_guarded_and_never_relabelled() {
	for source in ["db", "worker", "repo", "future-owner"] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let lead_id = inserted_id(conn, &lead());
				submit(conn, &lead());
				let result_id = insert_result(conn, &result());
				for (table, column) in [
					("leads", "anchored_payload"),
					("lead_observations", "observation_payload"),
					("review_unit_results", "result_payload"),
				] {
					let original: String =
						conn.query_row(&format!("SELECT {column} FROM {table}"), [], |r| r.get(0))?;
					conn.execute(&format!("UPDATE {table} SET source=?1"), [source])?;
					match table {
						"leads" => {
							assert!(leads::get_evidence(&scope(conn, 1), lead_id).is_err());
							assert!(leads::get_metadata(&scope(conn, 1), lead_id).is_err());
							assert!(leads::validate_stored_rows(conn).is_err());
						},
						"lead_observations" => {
							assert!(observations::list_evidence(&scope(conn, 1), lead_id).is_err());
							assert!(observations::validate_stored_rows(conn).is_err());
						},
						_ => {
							assert!(results::get_evidence(&scope(conn, 1), result_id).is_err());
							assert!(results::validate_stored_rows(conn).is_err());
						},
					}
					let stored: (String, String) =
						conn.query_row(&format!("SELECT source,{column} FROM {table}"), [], |r| {
							Ok((r.get(0)?, r.get(1)?))
						})?;
					assert_eq!(stored, (source.to_owned(), original));
					conn.execute(&format!("UPDATE {table} SET source='agent'"), [])?;
				}
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn modern_admission_retains_legacy_metadata_and_projection_checks() {
	for (table, update) in [
		("leads", "defer_reason=x'ff'"),
		("leads", "carry_depth='invalid'"),
		("leads", "identity_fingerprint=zeroblob(32)"),
		("leads", "priority_proposal='{}'"),
		("lead_observations", "commit_sha=x'ff'"),
		("lead_observations", "observation_digest=zeroblob(32)"),
		("review_unit_results", "invalidated_reason=x'ff'"),
		("review_unit_results", "counterevidence='shadow'"),
		("review_unit_results", "result_digest=zeroblob(32)"),
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				inserted_id(conn, &lead());
				submit(conn, &lead());
				insert_result(conn, &result());
				crate::migrations::admission::validate(conn)?;
				conn.execute(&format!("UPDATE {table} SET {update}"), [])?;
				assert!(crate::migrations::admission::validate(conn).is_err(), "{table}: {update}");
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn typed_checkpoint_writes_do_not_grant_operator_authority() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let lead_id = inserted_id(conn, &lead());
			let mut worker = scope(conn, 1);
			worker.operator = false;
			let commit = input::db_text("base").unwrap();
			assert!(matches!(
				leads::submit_evidence(
					&worker,
					&leads::NewLeadEvidence {
						generation_id: 11,
						created_by_job: 101,
						commit_sha: &commit,
						priority: Priority::High,
						payload: &lead()
					},
					0
				),
				Err(crate::Error::ScopeDenied)
			));
			assert!(matches!(
				observations::insert_evidence(
					&worker,
					&observations::NewObservationEvidence {
						lead_id,
						submitted_by_job: 101,
						commit_sha: &commit,
						payload: &lead()
					},
					0
				),
				Err(crate::Error::ScopeDenied)
			));
			assert!(matches!(
				results::insert_evidence(
					&worker,
					&results::NewResultEvidence {
						generation_id: 11,
						produced_by_job: 101,
						commit_sha: &commit,
						profile_version: 1,
						payload: &result()
					},
					0
				),
				Err(crate::Error::ScopeDenied)
			));
			assert!(observations::list_evidence(&scope(conn, 1), lead_id)?.is_empty());
			assert!(results::list_evidence(&scope(conn, 1), 31)?.is_empty());
			Ok(())
		})
		.unwrap();
}
