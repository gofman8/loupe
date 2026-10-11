//! Byte zero selects the 32/64-item policy; the rest is UTF-8 JSON. Input is
//! capped at 128 KiB so both sides of the 64 KiB raw/canonical limits are tested.

use loupe_core::text::policy::Symbol;
use loupe_core::text::{BoundedText, SourceRef};
use loupe_storage::source_refs::SourceRefs;
use serde::Deserialize;
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::utils::test_logger;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef {
	path: String,
	symbol: Option<String>,
}

pub fn do_test(data: &[u8]) {
	let Some((&policy, bytes)) = data.split_first() else { return };
	if bytes.len() > 128 * 1024 {
		return;
	}
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	if policy & 1 == 0 {
		check::<32>(raw);
	} else {
		check::<64>(raw);
	}
}

fn valid_path(path: &str) -> bool {
	!path.is_empty()
		&& path.len() <= 512
		&& !path.contains('\\')
		&& path.split('/').all(|piece| !piece.is_empty() && piece != "." && piece != "..")
		&& path.chars().all(|character| {
			let point = u32::from(character);
			!matches!(
				get_general_category(character),
				GeneralCategory::Control
					| GeneralCategory::Format
					| GeneralCategory::Unassigned
					| GeneralCategory::PrivateUse
					| GeneralCategory::LineSeparator
					| GeneralCategory::ParagraphSeparator
			) && !(0xfdd0..=0xfdef).contains(&point)
				&& !matches!(point % 65536, 65534 | 65535)
		})
}

fn check<const MAX: usize>(raw: &str) {
	let decoded = serde_json::from_str::<Vec<RawRef>>(raw);
	let expected_items = decoded.as_ref().ok().and_then(|refs| {
		refs.iter()
			.map(|entry| {
				if !valid_path(&entry.path) {
					return None;
				}
				let symbol =
					entry.symbol.as_deref().map(BoundedText::<Symbol>::new).transpose().ok()?;
				Some(
					serde_json::json!({"path": entry.path, "symbol": symbol.as_ref().map(BoundedText::expose)}),
				)
			})
			.collect::<Option<Vec<_>>>()
	});
	let expected = expected_items.map(|items| {
		let count = items.len();
		(count, loupe_core::canonical::canonical_bytes(&serde_json::Value::Array(items)))
	});
	let bounded =
		expected.as_ref().is_some_and(|(count, bytes)| *count <= MAX && bytes.len() <= 65536);
	let parsed = raw.parse::<SourceRefs<MAX>>();
	assert_eq!(
		parsed.is_ok(),
		bounded && raw.len() <= 65536,
		"source reference admission disagrees with oracle"
	);
	if let Ok(value) = &parsed {
		check_output(value, &decoded, &expected);
	}

	// new() must enforce the serialized byte budget even when its caller already
	// owns typed items; this does not share FromStr's raw-byte guard.
	if let Ok(items) = serde_json::from_str::<Vec<SourceRef>>(raw) {
		let built = SourceRefs::<MAX>::new(items);
		assert_eq!(built.is_ok(), bounded, "source reference constructor disagrees with oracle");
		if let Ok(value) = &built {
			check_output(value, &decoded, &expected);
		}
		if raw.len() <= 65536 {
			assert_eq!(built, parsed, "constructor and FromStr must agree within raw budget");
		}
	}
}

fn check_output<const MAX: usize>(
	value: &SourceRefs<MAX>, decoded: &Result<Vec<RawRef>, serde_json::Error>,
	expected: &Option<(usize, Vec<u8>)>,
) {
	let Some((count, bytes)) = expected else { panic!("accepted refs need a valid oracle value") };
	assert_eq!(value.expose().as_bytes(), bytes);
	assert_eq!(value.as_slice().len(), *count);
	assert!(*count <= MAX && bytes.len() <= 65536);
	assert_eq!(format!("{value:?}"), format!("SourceRefs(count={count})"));
	let refs = decoded.as_ref().unwrap_or_else(|_| panic!("accepted refs must decode"));
	for (original, stored) in refs.iter().zip(value.as_slice()) {
		assert_eq!(original.path, stored.path.expose(), "repository path bytes must be preserved");
	}
	let replay = value.expose().parse::<SourceRefs<MAX>>();
	assert_eq!(replay.as_ref().ok(), Some(value), "stored source references must round-trip");
}

pub fn storage_source_refs_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_source_refs_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
