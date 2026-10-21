use std::cell::RefCell;

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection};

use super::*;

thread_local! {
	static OBSERVATIONS: RefCell<Vec<(&'static str, usize, usize)>> = const { RefCell::new(Vec::new()) };
}
pub(super) fn observe(source: &'static str, bytes: &[u8]) {
	OBSERVATIONS
		.with_borrow_mut(|events| events.push((source, bytes.as_ptr() as usize, bytes.len())));
}

#[test]
fn frozen_profile_carries_original_sql_bytes_after_source_check() {
	let conn = Connection::open_in_memory().unwrap();
	let profile = crate::test_support::json::<loupe_core::text::policy::GeneratedProfile>(
		"{\"summary\":\"exact profile\"}",
	)
	.unwrap();
	conn.query_row(
		"SELECT 1,?1,?2,'agent'",
		params![profile.expose(), profile.digest().as_slice()],
		|row| {
			let ValueRef::Text(original) = row.get_ref(1)? else { panic!("TEXT column") };
			OBSERVATIONS.with_borrow_mut(Vec::clear);
			let frozen = frozen_profile(row, 0, 1, 2, 3)?.unwrap();
			assert_eq!(frozen.profile.canonical(), original);
			assert_eq!(frozen.version.get(), 1);
			assert_eq!(
				frozen.digest.expose(),
				profile.digest().iter().map(|byte| format!("{byte:02x}")).collect::<String>()
			);
			OBSERVATIONS.with_borrow(|events| {
				assert_eq!(
					events.as_slice(),
					&[
						("column", original.as_ptr() as usize, original.len()),
						("agent", original.as_ptr() as usize, original.len()),
					]
				)
			});
			Ok(())
		},
	)
	.unwrap();
	for source in ["operator", "db", "server", "unknown", "Agent"] {
		OBSERVATIONS.with_borrow_mut(Vec::clear);
		assert!(conn
			.query_row(
				"SELECT 1,?1,?2,?3",
				params![profile.expose(), profile.digest().as_slice(), source],
				|row| frozen_profile(row, 0, 1, 2, 3)
			)
			.is_err());
		OBSERVATIONS.with_borrow(|events| {
			assert!(events.is_empty(), "source classification must precede Agent carry")
		});
	}
}

#[test]
fn frozen_profile_refuses_partial_noncanonical_or_incompatible_state() {
	let conn = Connection::open_in_memory().unwrap();
	let hash = loupe_core::canonical::digest(b"{}");
	for sql in [
		"SELECT 0,'{}',?1,'agent'",
		"SELECT 4294967296,'{}',?1,'agent'",
		"SELECT 1.5,'{}',?1,'agent'",
		"SELECT 1,NULL,?1,'agent'",
		"SELECT 1,'{}',NULL,'agent' WHERE ?1 IS NOT NULL",
		"SELECT 1,' {} ',?1,'agent'",
		"SELECT 1,'{\"a\":1,\"a\":1}',?1,'agent'",
		"SELECT 1,'{}',zeroblob(32),'agent' WHERE ?1 IS NOT NULL",
		"SELECT 1,x'7b7d',?1,'agent'",
	] {
		assert!(
			conn.query_row(sql, [hash.as_slice()], |row| frozen_profile(row, 0, 1, 2, 3)).is_err(),
			"{sql}"
		);
	}
	assert!(conn
		.query_row("SELECT 0,NULL,NULL,'agent'", [], |row| frozen_profile(row, 0, 1, 2, 3))
		.unwrap()
		.is_none());
}

#[test]
fn review_identifiers_admit_actual_sql_storage_types() {
	let conn = Connection::open_in_memory().unwrap();
	let sha = "a".repeat(40);
	let parsed = conn.query_row("SELECT ?1", [&sha], |row| commit(row, 0)).unwrap();
	assert_eq!(parsed.expose(), sha);
	for raw in ["A".repeat(40), "g".repeat(40), "a".repeat(41)] {
		assert!(conn.query_row("SELECT ?1", [&raw], |row| commit(row, 0)).is_err());
	}
	assert!(conn.query_row("SELECT ?1", [sha.as_bytes()], |row| commit(row, 0)).is_err());
	assert_eq!(
		conn.query_row("SELECT zeroblob(32)", [], |row| digest(row, 0)).unwrap().expose(),
		"0".repeat(64)
	);
	for sql in
		["SELECT zeroblob(31)", "SELECT zeroblob(33)", "SELECT '00000000000000000000000000000000'"]
	{
		assert!(conn.query_row(sql, [], |row| digest(row, 0)).is_err());
	}
}
