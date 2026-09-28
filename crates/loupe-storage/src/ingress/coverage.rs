//! Fixed-source, original-argument validation for read-only SQL coverage.
//! These pure functions classify damaged derived content as non-covering;
//! failures to execute the surrounding SQL are never swallowed here.
use loupe_core::review_payload::UnitResultPayloadV1;
use loupe_provenance::Agent;
use rusqlite::functions::Context;
use rusqlite::types::ValueRef;

use super::function_text;
use super::profile::StoredProfile;
use super::review_payload::StoredUnitResult;

#[cfg(test)]
type Observation = (&'static str, usize, usize);
#[cfg(test)]
thread_local! {
	static OBSERVATIONS: std::cell::RefCell<Option<Vec<Observation>>> =
		const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn observe(stage: &'static str, bytes: &[u8]) {
	OBSERVATIONS.with_borrow_mut(|events| {
		if let Some(events) = events {
			events.push((stage, bytes.as_ptr() as usize, bytes.len()));
		}
	});
}

fn agent_source(ctx: &Context<'_>, index: usize) -> bool {
	matches!(ctx.get_raw(index), ValueRef::Text(b"agent"))
}

pub(crate) fn unit_refs_contain(ctx: &Context<'_>) -> bool {
	if !agent_source(ctx, 2) {
		return false;
	}
	let (ValueRef::Text(raw), ValueRef::Text(path)) = (ctx.get_raw(0), ctx.get_raw(1)) else {
		return false;
	};
	if raw.len() > 65536 {
		return false;
	}
	let Some(column) = function_text(ctx, 0) else { return false };
	let Ok(refs) = super::refs::stored_refs::<32>(column) else { return false };
	refs.as_slice().iter().any(|reference| reference.path.expose().as_bytes() == path)
}

pub(crate) fn profile_valid(ctx: &Context<'_>) -> bool {
	if !agent_source(ctx, 2) {
		return false;
	}
	let (ValueRef::Text(raw), ValueRef::Blob(digest)) = (ctx.get_raw(0), ctx.get_raw(1)) else {
		return false;
	};
	if raw.len() > 32 * 1024 || digest.len() != 32 {
		return false;
	}
	let Some(column) = function_text(ctx, 0) else { return false };
	let Ok(profile) = column.validate_carrying(StoredProfile) else { return false };
	profile.digest().as_slice() == digest
}

pub(crate) fn unit_result_epoch(ctx: &Context<'_>) -> rusqlite::Result<Option<i64>> {
	if !agent_source(ctx, 9) {
		return Ok(None);
	}
	let (
		ValueRef::Text(raw),
		ValueRef::Blob(digest),
		ValueRef::Integer(unit),
		ValueRef::Text(disposition),
		ValueRef::Text(refs),
	) = (ctx.get_raw(0), ctx.get_raw(1), ctx.get_raw(2), ctx.get_raw(3), ctx.get_raw(4))
	else {
		return Ok(None);
	};
	// Preflight the original bytes and projections before any owned decode.
	if raw.len() > UnitResultPayloadV1::<Agent>::MAX_BYTES
		|| refs.len() > UnitResultPayloadV1::<Agent>::MAX_BYTES
		|| digest.len() != 32
	{
		return Ok(None);
	}
	let Some(column) = function_text(ctx, 0) else { return Ok(None) };
	let Ok(value) = column.validate_carrying(StoredUnitResult) else { return Ok(None) };
	if crate::canonical::digest(raw).as_slice() != digest {
		return Ok(None);
	}
	let (Ok(disposition), Ok(refs)) = (std::str::from_utf8(disposition), std::str::from_utf8(refs))
	else {
		return Ok(None);
	};
	match crate::review_unit_results::projection_matches(
		&value,
		unit,
		disposition,
		refs,
		(5..9).all(|index| matches!(ctx.get_raw(index), ValueRef::Null)),
	) {
		Ok(true) => Ok(Some(value.assignment_epoch)),
		Ok(false)
		| Err(
			crate::Error::ReviewPayload(_)
			| crate::Error::Validation(_)
			| crate::Error::Conflict(crate::Conflict::CheckpointEvidence),
		) => Ok(None),
		Err(error) => Err(rusqlite::Error::UserFunctionError(Box::new(error))),
	}
}

#[cfg(test)]
mod tests {
	use rusqlite::{params, Connection};

	use super::*;

	fn observed<T>(f: impl FnOnce() -> T) -> (T, Vec<Observation>) {
		OBSERVATIONS.with_borrow_mut(|events| *events = Some(Vec::new()));
		let value = f();
		let events = OBSERVATIONS.with_borrow_mut(Option::take).unwrap();
		(value, events)
	}

	#[test]
	fn scalar_profile_carries_the_original_argument_only_after_source_and_bound_checks() {
		let conn = Connection::open_in_memory().unwrap();
		crate::review_coverage::register(&conn).unwrap();
		let sql = "SELECT loupe_review_profile_valid(?1,?2,?3)";
		let digest = crate::canonical::digest(b"{}");
		let (valid, events) = observed(|| {
			conn.query_row(sql, params!["{}", digest.as_slice(), "agent"], |r| r.get::<_, bool>(0))
				.unwrap()
		});
		assert!(valid);
		assert_eq!(events.len(), 2);
		assert_eq!(events[0].0, "argument");
		assert_eq!(events[1], ("agent", events[0].1, events[0].2));
		for source in ["worker", "operator", "db", "server", "Agent", "unknown"] {
			let (valid, events) = observed(|| {
				conn.query_row(sql, params!["{}", digest.as_slice(), source], |r| {
					r.get::<_, bool>(0)
				})
				.unwrap()
			});
			assert!(!valid);
			assert!(events.is_empty(), "source refusal must precede issuance and carry");
		}
		for raw in [" ".repeat(32769), " { }".into(), "{".into()] {
			let hash = crate::canonical::digest(raw.as_bytes());
			let (valid, events) = observed(|| {
				conn.query_row(sql, params![raw, hash.as_slice(), "agent"], |r| r.get::<_, bool>(0))
					.unwrap()
			});
			assert!(!valid);
			if raw.len() > 32768 {
				assert!(events.is_empty(), "raw cap precedes owned decode");
			}
		}
	}

	#[test]
	fn scalar_evidence_carries_original_bytes_and_rejects_source_before_materialization() {
		let conn = Connection::open_in_memory().unwrap();
		crate::review_coverage::register(&conn).unwrap();
		let value = crate::checkpoint_evidence_feature_tests::result();
		let bytes = value.canonical_bytes().unwrap();
		let raw = std::str::from_utf8(&bytes).unwrap();
		let digest = crate::canonical::digest(&bytes);
		let refs = crate::review::checkpoint_refs(&value.inspected_refs).unwrap();
		let sql = "SELECT loupe_unit_result_epoch(?1,?2,?3,?4,?5,NULL,NULL,NULL,NULL,?6)";
		for source in ["agent", "worker"] {
			let (epoch, events) = observed(|| {
				conn.query_row(
					sql,
					params![
						raw,
						digest.as_slice(),
						value.review_unit_id,
						value.disposition.as_str(),
						refs,
						source
					],
					|r| r.get::<_, Option<i64>>(0),
				)
				.unwrap()
			});
			if source == "agent" {
				assert_eq!(epoch, Some(value.assignment_epoch));
				assert_eq!(events.len(), 2);
				assert_eq!(events[0].0, "argument");
				assert_eq!(events[1], ("agent", events[0].1, bytes.len()));
				assert_eq!(events[0].2, bytes.len());
			} else {
				assert_eq!(epoch, None);
				assert!(events.is_empty());
			}
		}
		let raw = " ".repeat(UnitResultPayloadV1::<Agent>::MAX_BYTES + 1);
		let (epoch, events) = observed(|| {
			conn.query_row(
				sql,
				params![
					raw,
					digest.as_slice(),
					value.review_unit_id,
					value.disposition.as_str(),
					refs,
					"agent"
				],
				|r| r.get::<_, Option<i64>>(0),
			)
			.unwrap()
		});
		assert_eq!(epoch, None);
		assert!(events.is_empty(), "payload cap precedes owned decode");
	}

	#[test]
	fn scalar_refs_preserve_exact_nested_tokens_and_check_actual_source() {
		let conn = Connection::open_in_memory().unwrap();
		crate::review_coverage::register(&conn).unwrap();
		let raw = r#"[ {"path":"cafe\u0301.rs"} ]"#;
		let sql = "SELECT loupe_unit_refs_contain(?1,?2,?3)";
		let (valid, events) = observed(|| {
			conn.query_row(sql, params![raw, "cafe\u{301}.rs", "agent"], |r| r.get::<_, bool>(0))
				.unwrap()
		});
		assert!(valid);
		assert_eq!(events.len(), 2);
		assert_eq!(events[0].0, "argument");
		assert_eq!(events[0].2, raw.len());
		// The path token begins at its own opening quote, not at the key.
		let start = raw.find(r#""cafe"#).unwrap();
		assert_eq!(events[1].0, "agent_path");
		assert_eq!(events[1].1 - events[0].1, start);
		assert_eq!(events[1].2, r#""cafe\u0301.rs""#.len());
		assert!(!conn
			.query_row(sql, params![raw, "café.rs", "agent"], |r| r.get::<_, bool>(0))
			.unwrap());
		for source in ["worker", "db", "Agent"] {
			let (valid, events) = observed(|| {
				conn.query_row(sql, params![raw, "cafe\u{301}.rs", source], |r| r.get::<_, bool>(0))
					.unwrap()
			});
			assert!(!valid);
			assert!(events.is_empty());
		}
		let (valid, events) = observed(|| {
			conn.query_row(sql, params![" ".repeat(65537), "a.rs", "agent"], |r| {
				r.get::<_, bool>(0)
			})
			.unwrap()
		});
		assert!(!valid);
		assert!(events.is_empty());
	}
}
