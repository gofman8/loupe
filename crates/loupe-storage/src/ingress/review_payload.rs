//! Canonical phase evidence carried from its original live SQLite TEXT column.
//! The DAO checks the row's fixed Agent designation before invoking these exits.
use loupe_core::review_payload::{
	DrilldownTerminalV1, FindingEvidenceV1, SurveyTerminalV1, VerificationTerminalV1,
};

use super::*;

macro_rules! evidence {
	($stored:ident, $validator:ident, $read:ident, $value:ident) => {
		struct $stored;
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
