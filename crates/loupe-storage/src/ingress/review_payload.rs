//! Canonical phase evidence carried from its original live SQLite TEXT column.
//! The DAO checks the row's fixed Agent designation before invoking these exits.
use loupe_core::review_payload::{
	DrilldownTerminalV1, FindingEvidenceV1, LeadEvidenceV1, SurveyTerminalV1, UnitResultPayloadV1,
	VerificationTerminalV1,
};

use super::*;

macro_rules! evidence {
	($stored:ident, $validator:ident, $read:ident, $value:ident) => {
		pub(super) struct $stored;
		struct $validator;
		impl<'a> ValidateCarrying<&'a [u8], Db> for $stored {
			type Output = $value<Agent>;
			type Error = loupe_core::review_payload::Error;
			fn validate(
				self, u: Unvalidated<'_, &'a [u8], Db>,
			) -> Result<Self::Output, Self::Error> {
				#[cfg(test)]
				tests::observe("column", stringify!($validator), u.get());
				let value = u
					.carry::<Agent>(0..u.get().len())
					.ok_or(loupe_core::review_payload::Error::Json)?
					.validate($validator)?;
				if value.canonical_bytes()?.as_slice() != *u.get() {
					return Err(loupe_core::review_payload::Error::Json);
				}
				Ok(value)
			}
		}
		impl Validate<&[u8], Agent> for $validator {
			type Output = $value<Agent>;
			type Error = loupe_core::review_payload::Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
			) -> Result<Self::Output, Self::Error> {
				#[cfg(test)]
				tests::observe("agent", stringify!($validator), u.get());
				#[cfg(test)]
				super::coverage::observe("agent", u.get());
				$value::from_json(&mark, utf8(u.get())?)
			}
		}
		pub(crate) fn $read(row: &Row<'_>, index: usize) -> rusqlite::Result<$value<Agent>> {
			column(row, index)?
				.validate_carrying($stored)
				.map_err(|_| sql_error(index, ReadError::Syntax))
		}
	};
}
evidence!(StoredFindingEvidence, AgentFindingEvidence, finding_evidence, FindingEvidenceV1);
evidence!(StoredLeadEvidence, AgentLeadEvidence, lead_evidence, LeadEvidenceV1);
evidence!(StoredUnitResult, AgentUnitResult, unit_result, UnitResultPayloadV1);
evidence!(StoredSurveyTerminal, AgentSurveyTerminal, survey_terminal, SurveyTerminalV1);
evidence!(StoredDrilldownTerminal, AgentDrilldownTerminal, drilldown_terminal, DrilldownTerminalV1);
evidence!(
	StoredVerificationTerminal,
	AgentVerificationTerminal,
	verification_terminal,
	VerificationTerminalV1
);

#[cfg(test)]
mod tests {
	use std::cell::RefCell;

	use super::*;
	thread_local! {
		static OBSERVATIONS: RefCell<Vec<(&'static str, usize, usize)>> = const { RefCell::new(Vec::new()) };
	}
	pub(super) fn observe(source: &'static str, _field: &'static str, bytes: &[u8]) {
		OBSERVATIONS
			.with_borrow_mut(|events| events.push((source, bytes.as_ptr() as usize, bytes.len())));
	}
	#[test]
	fn checkpoint_source_guards_precede_original_column_carry() {
		use crate::test_support::{db_text, scope, scoped};
		use crate::{lead_observations, leads, review_unit_results};
		crate::review_tests::fixture().with_conn(|conn| {
			conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(31,11,'unit','title','objective','[]',0)")?;
			let payload=crate::checkpoint_evidence_feature_tests::lead();
			let revision=db_text("base").unwrap();
			let new=leads::NewLeadEvidence{generation_id:11,created_by_job:101,commit_sha:&revision,priority:crate::review_units::Priority::High,payload:&payload};
			let leads::Submitted::Created(lead_id)=scoped(conn,1,|scope|leads::submit_evidence(scope,&new,0))? else {panic!("created lead")};
			scoped(conn,1,|scope|leads::submit_evidence(scope,&new,0))?;
			let result=crate::checkpoint_evidence_feature_tests::result();
			let result_id=scoped(conn,1,|scope|review_unit_results::insert_evidence(scope,&review_unit_results::NewResultEvidence{generation_id:11,produced_by_job:101,commit_sha:&revision,profile_version:1,payload:&result},0))?;
			for table in ["leads","lead_observations","review_unit_results"] {
				conn.execute(&format!("UPDATE {table} SET source='worker'"),[])?;
				OBSERVATIONS.with_borrow_mut(Vec::clear);
				match table {
					"leads"=>assert!(leads::get_evidence(&scope(conn,1),lead_id).is_err()),
					"lead_observations"=>assert!(lead_observations::list_evidence(&scope(conn,1),lead_id).is_err()),
					_=>assert!(review_unit_results::get_evidence(&scope(conn,1),result_id).is_err()),
				}
				OBSERVATIONS.with_borrow(|events|assert!(events.is_empty(),"source refusal must precede evidence ingress and carry"));
				conn.execute(&format!("UPDATE {table} SET source='agent'"),[])?;
			}
			Ok(())
		}).unwrap();
	}
	#[test]
	fn canonical_evidence_carries_the_live_whole_sql_column() {
		let conn = rusqlite::Connection::open_in_memory().unwrap();
		let mut cases = vec![(
			"finding".to_owned(),
			crate::evidence_tests::evidence().canonical_bytes().unwrap(),
		)];
		cases.extend(
			crate::evidence_tests::terminals()
				.iter()
				.map(|value| (value.phase().as_str().to_owned(), value.canonical_bytes().unwrap())),
		);
		cases.push((
			"lead".to_owned(),
			crate::checkpoint_evidence_feature_tests::lead().canonical_bytes().unwrap(),
		));
		cases.push((
			"result".to_owned(),
			crate::checkpoint_evidence_feature_tests::result().canonical_bytes().unwrap(),
		));
		for (kind, bytes) in cases {
			let raw = std::str::from_utf8(&bytes).unwrap();
			conn.query_row("SELECT ?1", [raw], |row| {
				let ValueRef::Text(original) = row.get_ref(0)? else {
					panic!("actual TEXT column")
				};
				OBSERVATIONS.with_borrow_mut(Vec::clear);
				let actual = match kind.as_str() {
					"finding" => finding_evidence(row, 0)?.canonical_bytes(),
					"survey" => survey_terminal(row, 0)?.canonical_bytes(),
					"drilldown" => drilldown_terminal(row, 0)?.canonical_bytes(),
					"lead" => lead_evidence(row, 0)?.canonical_bytes(),
					"result" => unit_result(row, 0)?.canonical_bytes(),
					_ => verification_terminal(row, 0)?.canonical_bytes(),
				}
				.unwrap();
				assert_eq!(actual, original, "canonical paths and bytes must stay exact");
				OBSERVATIONS.with_borrow(|events| {
					assert_eq!(
						events.as_slice(),
						&[
							("column", original.as_ptr() as usize, original.len()),
							("agent", original.as_ptr() as usize, original.len())
						]
					)
				});
				Ok(())
			})
			.unwrap();
		}
	}
}
