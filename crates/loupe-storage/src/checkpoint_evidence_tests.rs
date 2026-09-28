use loupe_provenance::Agent;
use rusqlite::params;

use crate::identity::Identity;
use crate::review_tests::{fixture, payload};
use crate::review_units::Priority;
use crate::test_support::{self as fixture_input, scope, scoped};
use crate::{lead_observations, leads, review_unit_results, Result};

thread_local! {
	static FORMAT_PARSE_LENGTHS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}
pub(crate) fn observe_format_parse(length: usize) {
	FORMAT_PARSE_LENGTHS.with_borrow_mut(|lengths| lengths.push(length));
}

#[test]
fn checkpoint_routing_keeps_the_exact_original_byte_boundary_and_marker_rules() {
	use loupe_core::text::policy::Payload;
	use loupe_core::text::JsonPolicy;
	let conn = rusqlite::Connection::open_in_memory().unwrap();
	for (suffix, modern) in [
		("{}", false),
		("[]", false),
		("null", false),
		(r#"{"format":"unrelated","version":99}"#, false),
		(r#"{"format":"loupe.lead_evidence","version":1}"#, true),
		(r#"{"format":"loupe.unit_result","version":2}"#, true),
		(r#"{"format":"loupe.future_evidence"}"#, true),
	] {
		let raw = format!("{}{suffix}", " ".repeat(Payload::MAX_BYTES - suffix.len()));
		FORMAT_PARSE_LENGTHS.with_borrow_mut(Vec::clear);
		let actual = conn
			.query_row("SELECT ?1", [&raw], |row| crate::ingress::checkpoint::is_modern(row, 0))
			.unwrap();
		assert_eq!(actual, modern);
		FORMAT_PARSE_LENGTHS
			.with_borrow(|lengths| assert_eq!(lengths.as_slice(), &[Payload::MAX_BYTES]));
		if !modern {
			conn.query_row("SELECT ?1", [&raw], |row| {
				crate::ingress::checkpoint::historical_payload(row, 0)
			})
			.unwrap();
		}
		let oversized = format!(" {raw}");
		FORMAT_PARSE_LENGTHS.with_borrow_mut(Vec::clear);
		assert!(conn
			.query_row("SELECT ?1", [&oversized], |row| crate::ingress::checkpoint::is_modern(
				row, 0
			))
			.is_err());
		FORMAT_PARSE_LENGTHS.with_borrow(|lengths| {
			assert!(lengths.is_empty(), "MAX_BYTES + 1 must not enter the format parser")
		});
	}
	for malformed in [
		r#"{"format":"loupe.lead_evidence","format":"loupe.unit_result"}"#,
		r#"{"format":"loupe.lead_evidence""#,
	] {
		assert!(conn
			.query_row("SELECT ?1", [malformed], |row| crate::ingress::checkpoint::is_modern(
				row, 0
			))
			.is_err());
	}
}

#[test]
fn over_budget_sql_checkpoint_routing_refuses_before_json_parse() {
	use loupe_core::text::policy::Payload;
	use loupe_core::text::JsonPolicy;
	for modern in [false, true] {
		for table in ["leads", "lead_observations", "review_unit_results"] {
			fixture().with_conn(|conn| {
				let lead_id=historical_lead(conn);
				unit(conn)?;
				conn.execute("INSERT INTO lead_observations(lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES(?1,'{}',zeroblob(32),'base',0)",[lead_id])?;
				conn.execute_batch("INSERT INTO review_unit_results(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(31,'base',1,'no_lead_found','[]','{}',zeroblob(32),0)")?;
				let (column,format)=match table {
					"leads"=>("anchored_payload","loupe.lead_evidence"),
					"lead_observations"=>("observation_payload","loupe.lead_evidence"),
					_=>("result_payload","loupe.unit_result"),
				};
				let prefix=if modern {format!(r#"{{"format":"{format}","padding":""#)} else {r#"{"padding":""#.to_owned()};
				let raw=format!("{prefix}{}{}", "x".repeat(Payload::MAX_BYTES), r#""}"#);
				conn.execute(&format!("UPDATE {table} SET {column}=?1"),[&raw])?;
				for admission in [false,true] {
					FORMAT_PARSE_LENGTHS.with_borrow_mut(Vec::clear);
					let rejected=match (table,admission) {
						("leads",false)=>leads::get_evidence(&scope(conn,1),lead_id).is_err(),
						("leads",true)=>leads::validate_stored_rows(conn).is_err(),
						("lead_observations",false)=>lead_observations::list_evidence(&scope(conn,1),lead_id).is_err(),
						("lead_observations",true)=>lead_observations::validate_stored_rows(conn).is_err(),
						(_,false)=>review_unit_results::get_evidence(&scope(conn,1),1).is_err(),
						(_,true)=>review_unit_results::validate_stored_rows(conn).is_err(),
					};
					assert!(rejected);
					FORMAT_PARSE_LENGTHS.with_borrow(|lengths|assert!(lengths.is_empty(),"over-budget original SQL bytes reached JSON format parsing: {table}, modern={modern}, admission={admission}, lengths={lengths:?}"));
				}
				Ok(())
			}).unwrap();
		}
	}
}

fn identity() -> Identity<Agent> {
	Identity {
		family: fixture_input::identifier("auth-bypass").unwrap(),
		anchor: fixture_input::anchor("token boundary").unwrap(),
		instance: None,
	}
}
fn historical_lead(conn: &mut rusqlite::Connection) -> i64 {
	let leads::Submitted::Created(id) = scoped(conn, 1, |scope| {
		leads::submit(
			scope,
			&leads::NewLead {
				generation_id: 11,
				unit_id: None,
				identity: &identity(),
				payload: &payload(),
				commit_sha: &fixture_input::db_text("base").unwrap(),
				priority: Priority::Normal,
				priority_proposal: None,
				supersedes: None,
				created_by_job: Some(101),
			},
			0,
		)
	})
	.unwrap() else {
		panic!("new identity")
	};
	id
}

#[test]
fn legacy_lead_reader_rejects_modern_marker() {
	fixture()
		.with_conn(|conn| {
			let id = historical_lead(conn);
			conn.execute(
				"UPDATE leads SET anchored_payload=?2 WHERE lead_id=?1",
				params![id, r#"{"format":"loupe.lead_evidence","version":1}"#],
			)?;
			assert!(
				leads::get(&scope(conn, 1), id).is_err(),
				"modern lead evidence must not traverse generic JSON normalization"
			);
			Ok(())
		})
		.unwrap();
}
#[test]
fn legacy_observation_reader_rejects_modern_marker() {
	fixture().with_conn(|conn| {
		let id=historical_lead(conn);
		conn.execute("INSERT INTO lead_observations(lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES (?1,?2,zeroblob(32),'base',0)",params![id,r#"{"format":"loupe.lead_evidence","version":1}"#])?;
		assert!(lead_observations::list(&scope(conn,1),id).is_err(),"modern observation evidence must not traverse generic JSON normalization");
		Ok(())
	}).unwrap();
}
fn unit(conn: &rusqlite::Connection) -> Result<()> {
	conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(31,11,'unit','title','objective','[]',0)")?;
	Ok(())
}
#[test]
fn legacy_result_reader_rejects_modern_marker() {
	fixture().with_conn(|conn| {
		unit(conn)?;
		conn.execute("INSERT INTO review_unit_results(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(31,'base',1,'no_lead_found','[]',?1,zeroblob(32),0)",[r#"{"format":"loupe.unit_result","version":1}"#])?;
		assert!(review_unit_results::list(&scope(conn,1),31).is_err(),"modern result evidence must not traverse generic JSON normalization");
		Ok(())
	}).unwrap();
}
#[test]
fn closing_lead_does_not_decode_unrelated_evidence() {
	fixture()
		.with_conn(|conn| {
			let id = historical_lead(conn);
			conn.execute("UPDATE leads SET anchored_payload=x'00' WHERE lead_id=?1", [id])?;
			assert!(
				scoped(conn, 1, |scope| leads::close(scope, id, &leads::Closure::Rejected, 1))
					.is_ok(),
				"scope-only closure must not decode the lead payload"
			);
			Ok(())
		})
		.unwrap();
}
#[test]
fn duplicate_identity_attachment_does_not_decode_original_evidence() {
	fixture().with_conn(|conn| {
		let id=historical_lead(conn);
		conn.execute("UPDATE leads SET anchored_payload=x'00' WHERE lead_id=?1",[id])?;
		let data=fixture_input::json(r#"{"observation":"new evidence"}"#).unwrap();
		let result=scoped(conn,1,|scope|leads::submit(scope,&leads::NewLead{
			generation_id:11,unit_id:None,identity:&identity(),payload:&data,
			commit_sha:&fixture_input::db_text("base").unwrap(),priority:Priority::High,
			priority_proposal:None,supersedes:None,created_by_job:Some(101),
		},1));
		assert!(matches!(result,Ok(leads::Submitted::Attached{lead_id,..}) if lead_id==id),"identity attachment must preserve new evidence without decoding unrelated original payload: {result:?}");
		assert_eq!(lead_observations::list(&scope(conn,1),id)?[0].payload,data);
		Ok(())
	}).unwrap();
}
#[test]
fn generic_lead_insertion_rejects_reserved_evidence_formats() {
	fixture()
		.with_conn(|conn| {
			let tagged =
				fixture_input::json(r#"{"format":"loupe.lead_evidence","version":1}"#).unwrap();
			let result = scoped(conn, 1, |scope| {
				leads::submit(
					scope,
					&leads::NewLead {
						generation_id: 11,
						unit_id: None,
						identity: &identity(),
						payload: &tagged,
						commit_sha: &fixture_input::db_text("base").unwrap(),
						priority: Priority::Normal,
						priority_proposal: None,
						supersedes: None,
						created_by_job: Some(101),
					},
					0,
				)
			});
			assert!(result.is_err(), "generic writes must not claim a typed evidence format");
			Ok(())
		})
		.unwrap();
}
#[test]
fn generic_observation_insertion_rejects_reserved_evidence_formats() {
	fixture()
		.with_conn(|conn| {
			let lead_id = historical_lead(conn);
			let tagged =
				fixture_input::json(r#"{"format":"loupe.lead_evidence","version":1}"#).unwrap();
			let result = scoped(conn, 1, |scope| {
				lead_observations::insert(
					scope,
					&lead_observations::NewObservation {
						lead_id,
						submitted_by_job: Some(101),
						payload: &tagged,
						commit_sha: &fixture_input::db_text("base").unwrap(),
					},
					0,
				)
			});
			assert!(result.is_err(), "generic writes must not claim a typed observation format");
			Ok(())
		})
		.unwrap();
}
#[test]
fn generic_result_insertion_rejects_reserved_evidence_formats() {
	fixture()
		.with_conn(|conn| {
			unit(conn)?;
			let tagged =
				fixture_input::json(r#"{"format":"loupe.unit_result","version":1}"#).unwrap();
			let result = scoped(conn, 1, |scope| {
				review_unit_results::insert(
					scope,
					&review_unit_results::NewResult {
						generation_id: 11,
						unit_id: 31,
						produced_by_job: Some(101),
						commit_sha: &fixture_input::db_text("base").unwrap(),
						profile_version: 1,
						disposition: review_unit_results::Disposition::NoLeadFound,
						inspected_refs: &fixture_input::refs(vec![]).unwrap(),
						counterevidence: None,
						proof_gaps: None,
						payload: &tagged,
						corroborates_result: None,
						corroborates_exclusion: None,
					},
					0,
				)
			});
			assert!(result.is_err(), "generic writes must not claim a typed result format");
			Ok(())
		})
		.unwrap();
}
