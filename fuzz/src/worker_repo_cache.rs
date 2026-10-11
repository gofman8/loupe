//! Raw bytes exercise the actual persisted-cursor and git-origin decoders.
//! Origin strings intentionally remain opaque, including lossy UTF-8; this
//! target does not impose a new URL or SHA grammar on the legacy cache.

use loupe_worker::repo_cache::fuzz_support;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let decoded = fuzz_support::decode_cursor(data);
	let expected = data
		.strip_prefix(b"LOUPE\x01\n")
		.and_then(|body| std::str::from_utf8(body).ok())
		.map(str::trim)
		.filter(|sha| !sha.is_empty());
	assert_eq!(decoded.as_deref(), expected, "cursor magic/version/body contract changed");
	if let Some(sha) = decoded {
		let encoded = fuzz_support::encode_cursor(&sha);
		assert_eq!(fuzz_support::decode_cursor(&encoded).as_deref(), Some(sha.as_str()));
	}

	assert_eq!(fuzz_support::parse_origin_output(false, data), None);
	let origin = fuzz_support::parse_origin_output(true, data);
	let text = String::from_utf8_lossy(data);
	let trimmed = text.trim();
	assert_eq!(origin.as_deref(), (!trimmed.is_empty()).then_some(trimmed));
	if let Some(origin) = origin {
		assert_eq!(
			fuzz_support::parse_origin_output(true, origin.as_bytes()).as_deref(),
			Some(origin.as_str()),
			"origin normalization must be idempotent"
		);
	}
}

pub fn worker_repo_cache_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_repo_cache_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
