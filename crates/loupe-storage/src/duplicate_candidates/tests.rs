use super::*;
use crate::secrets::MasterKey;
use crate::{review_tests, transaction, Db};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn query(text: &str, limit: u8) -> CandidateQuery<Worker> {
	CandidateQuery {
		query: crate::test_support::worker(text, |raw, mark| {
			loupe_core::review_candidates::QueryText::new(mark, raw)
		})
		.unwrap(),
		limit,
	}
}

fn add_lead(conn: &Connection, id: i64, generation: i64, job: i64, anchor: &str) -> Result<()> {
	let identity = Identity {
		family: crate::test_support::identifier("auth-bypass")?,
		anchor: crate::test_support::anchor(anchor)?,
		instance: None,
	};
	conn.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_by_job_id,created_at) VALUES(?1,?2,?3,?4,?5,'{}',zeroblob(32),?6,?7,0)",params![id,generation,identity.family.expose(),identity.anchor.expose(),identity.fingerprint().as_slice(),SHA,job])?;
	Ok(())
}

fn source_guard(table: &str, column: &str, id: i64, kind: CandidateKind) {
	for source in ["db", "worker", "operator", "unknown"] {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		seed(&db);
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				add_lead(tx, 31, 11, 101, "entry lead")?;
				let initial: Vec<Candidate<Agent, loupe_provenance::Db>> =
					issue(tx, 101, 1, &query("auth", 20), 0)?;
				assert_eq!(initial.len(), 2);
				tx.execute(
					&format!("UPDATE {table} SET source=?1 WHERE {column}=?2"),
					params![source, id],
				)?;
				assert_eq!(
					issue(tx, 101, 1, &query("auth", 20), 1)?,
					initial,
					"a prior exact typed snapshot remains frozen"
				);
				assert!(
					issue(tx, 101, 1, &query("entry", 20), 1).is_err(),
					"fresh candidate must reject non-Agent durable source: {table} {source}"
				);
				assert!(
					issued_target(tx, 101, 1, kind, id).is_err(),
					"issued target must recheck its durable source"
				);
				assert_eq!(
					checkpoints::accepted_count_raw(
						tx,
						1,
						101,
						Operation::IssueDuplicateCandidates
					)?,
					1
				);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn candidate_findings_require_agent_source() {
	source_guard("finding_review_details", "finding_id", 1, CandidateKind::Finding);
}

#[test]
fn candidate_leads_require_agent_source() {
	source_guard("leads", "lead_id", 31, CandidateKind::Lead);
}

#[test]
fn foreign_malformed_rows_are_excluded_before_source_and_content_decoding() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		add_lead(tx,31,21,201,"entry foreign")?;
		tx.execute_batch("UPDATE leads SET source='operator',identity_anchor=x'ff',commit_sha='bad' WHERE lead_id=31;
		 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES(2,2,201,'review','high','title','private body','foreign',0);
		 INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at,source) VALUES(2,2,1,1,'bad','auth-bypass',x'ff',zeroblob(32),'{}','counter','gaps','high','L2',0,'operator');")?;
		let candidates=issue(tx,101,1,&query("auth",20),0)?;
		assert_eq!(candidates.len(),1);
		assert_eq!((candidates[0].kind,candidates[0].id),(CandidateKind::Finding,1));
		assert!(!issued_target(tx,101,1,CandidateKind::Lead,31)?);
		assert!(!issued_target(tx,101,1,CandidateKind::Finding,2)?);
		Ok(())
	})).unwrap();
}

#[test]
fn exact_replay_precedes_exhausted_quota_and_current_target_decoding() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let initial = issue(tx, 101, 1, &query("auth", 20), 0)?;
			for index in 1..QUERY_LIMIT {
				assert!(issue(tx, 101, 1, &query(&format!("no-match-{index}"), 20), 0)?.is_empty());
			}
			tx.execute("UPDATE finding_review_details SET identity_fingerprint=zeroblob(32)", [])?;
			assert_eq!(issue(tx, 101, 1, &query("auth", 20), 1)?, initial);
			assert!(matches!(
				issue(tx, 101, 1, &query("entry", 20), 1),
				Err(Error::Conflict(Conflict::CheckpointLimit))
			));
			assert_eq!(
				checkpoints::accepted_count_raw(tx, 1, 101, Operation::IssueDuplicateCandidates)?,
				32
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn replay_binding_is_checked_before_stored_response_content() {
	for mutation in ["operation='submit_lead'", "payload_digest=zeroblob(32)"] {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		seed(&db);
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert_eq!(issue(tx, 101, 1, &query("auth", 20), 0)?.len(), 1);
				tx.execute(&format!("UPDATE job_checkpoints SET {mutation},response=x'ff'"), [])?;
				assert!(
					matches!(
						issue(tx, 101, 1, &query("auth", 20), 1),
						Err(Error::Conflict(Conflict::Checkpoint))
					),
					"wrong binding must not attempt malformed snapshot decoding"
				);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn search_limits_are_exact_and_results_have_stable_kind_id_order() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			for id in 10..34 {
				add_lead(tx, id, 11, 101, &format!("handler {id}"))?;
			}
			let candidates = issue(tx, 101, 1, &query("auth", 20), 0)?;
			assert_eq!(candidates.len(), 20);
			assert_eq!(candidates[0].kind, CandidateKind::Finding);
			assert_eq!(
				candidates[1..].iter().map(|c| c.id).collect::<Vec<_>>(),
				(10..29).collect::<Vec<_>>()
			);
			for limit in [0, 21, u8::MAX] {
				assert!(issue(tx, 101, 1, &query("auth", limit), 0).is_err());
			}
			assert_eq!(
				checkpoints::accepted_count_raw(tx, 1, 101, Operation::IssueDuplicateCandidates)?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

fn seed(db: &Db) {
	review_tests::seed(db);
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let identity=Identity {family:crate::test_support::identifier("auth-bypass")?,anchor:crate::test_support::anchor("entry boundary")?,instance:None};
		tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES(1,1,101,'review','high','title','private body','test',0)",[])?;
		tx.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at) VALUES(1,1,1,1,?1,?2,?3,?4,'{}','counter','gaps','high','L2',0)",params![SHA,identity.family.expose(),identity.anchor.expose(),identity.fingerprint().as_slice()])?;
		Ok(())
	})).unwrap();
}

#[test]
fn issuance_and_immutable_finding_identity_survive_reopening() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("candidates.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	let query = CandidateQuery {
		query: crate::test_support::worker("auth", |raw, mark| {
			loupe_core::review_candidates::QueryText::new(mark, raw)
		})
		.unwrap(),
		limit: 20,
	};
	let initial = db
		.with_conn(|conn| transaction::immediate(conn, |tx| issue(tx, 101, 1, &query, 1)))
		.unwrap();
	assert_eq!(initial.len(), 1);
	assert_eq!(initial[0].kind, CandidateKind::Finding);
	assert!(!serde_json::to_string(&initial).unwrap().contains("private"));
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(issue(tx, 101, 1, &query, 2)?, initial);
			assert_eq!(
				checkpoints::accepted_count_raw(tx, 1, 101, Operation::IssueDuplicateCandidates)?,
				1
			);
			assert!(issued_target(tx, 101, 1, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 101, 2, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 101, 1, CandidateKind::Finding, 999)?);
			tx.execute(
				"UPDATE findings SET description='changed body',state='dismissed' WHERE id=1",
				[],
			)?;
			assert!(
				issued_target(tx, 101, 1, CandidateKind::Finding, 1)?,
				"mutable status/body do not replace immutable identity"
			);
			tx.execute(
				"UPDATE finding_review_details SET reviewed_commit_sha=?1 WHERE finding_id=1",
				["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
			)?;
			assert!(
				!issued_target(tx, 101, 1, CandidateKind::Finding, 1)?,
				"retargeting provenance revokes issued authority"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn refused_bad_or_rolled_back_queries_do_not_consume_issuance() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	let query = CandidateQuery {
		query: crate::test_support::worker("auth", |raw, mark| {
			loupe_core::review_candidates::QueryText::new(mark, raw)
		})
		.unwrap(),
		limit: 20,
	};
	db.with_conn(|conn| {
		let result:Result<()>=transaction::immediate(conn,|tx| {
			assert_eq!(issue(tx,101,1,&query,0)?.len(),1);
			Err(Error::Conflict(Conflict::Candidate))
		});
		assert!(result.is_err());
		transaction::immediate(conn,|tx| {
			assert_eq!(checkpoints::accepted_count_raw(tx,1,101,Operation::IssueDuplicateCandidates)?,0);
			assert!(issue(tx,101,2,&query,0).is_err());
			tx.execute("UPDATE finding_review_details SET identity_fingerprint=zeroblob(32) WHERE finding_id=1",[])?;
			assert!(issue(tx,101,1,&query,0).is_err());
			assert_eq!(checkpoints::accepted_count_raw(tx,1,101,Operation::IssueDuplicateCandidates)?,0);
			Ok(())
		})
	}).unwrap();
}

#[test]
fn unissued_targets_are_denied_before_decoding_their_contents() {
	let mut leaks = Vec::new();
	for mutation in
		["identity_fingerprint=zeroblob(32)", "identity_anchor=x'00'", "reviewed_commit_sha='bad'"]
	{
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		seed(&db);
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let query = CandidateQuery {
					query: crate::test_support::worker("auth", |raw, mark| {
						loupe_core::review_candidates::QueryText::new(mark, raw)
					})?,
					limit: 20,
				};
				assert_eq!(issue(tx, 101, 1, &query, 0)?.len(), 1);
				assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 1)?);
				tx.execute(
					&format!("UPDATE finding_review_details SET {mutation} WHERE finding_id=1"),
					[],
				)?;
				let result = issued_target(tx, 102, 1, CandidateKind::Finding, 1);
				if !matches!(result, Ok(false)) {
					leaks.push(format!("{mutation}: {result:?}"));
				}
				assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 999)?);
				assert!(!issued_target(tx, 102, 2, CandidateKind::Finding, 1)?);
				assert!(
					issued_target(tx, 101, 1, CandidateKind::Finding, 1).is_err(),
					"issued corrupted evidence must still fail closed"
				);
				Ok(())
			})
		})
		.unwrap();
	}
	assert!(leaks.is_empty(), "unissued targets must never be decoded: {leaks:?}");
}
