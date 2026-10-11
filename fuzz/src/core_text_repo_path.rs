//! Strict paths plus the two legacy validators: disagreements are D17 inputs,
//! not a demand to tighten legacy behavior during S1.

use loupe_core::text::RepoPath;
use loupe_proto::{validate_llm_finding_submission, LlmFindingSubmission, PROTOCOL_VERSION};

use crate::utils::test_logger;

pub fn legacy_acceptance(path: &str) -> (bool, bool) {
	let finding = LlmFindingSubmission {
		protocol_version: PROTOCOL_VERSION,
		severity: loupe_core::Severity::High,
		title: "A valid example title".into(),
		description: "description ".repeat(10),
		file_path: path.into(),
		line_start: 1,
		line_end: 1,
		cwe: None,
		poc_unified: "--- a/src.rs\n+++ b/src.rs\n@@ -1 +1 @@\n-old\n+new\n".into(),
		fingerprint: "a".repeat(64),
	};
	(
		validate_llm_finding_submission(&finding).is_ok(),
		loupe_worker::mcp::normalize_path_component_rules(path).is_ok(),
	)
}

pub fn do_test(data: &[u8]) {
	let Ok(path) = std::str::from_utf8(data) else { return };
	if let Ok(strict) = RepoPath::new(path) {
		assert_eq!(strict.expose(), path);
		assert!(path.len() <= 512);
		assert!(!path.contains(['\\', '\0']));
		assert!(path.split('/').all(|part| !matches!(part, "" | "." | "..")));
	}
	let proto_expected = !path.trim().is_empty()
		&& !path.starts_with('/')
		&& path != "."
		&& !path.starts_with("./")
		&& !path.split('/').any(|part| part == "..");
	let stripped = path.strip_prefix("/workdir/").unwrap_or(path);
	let parts: Vec<_> =
		stripped.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	let mcp_expected = !stripped.trim().is_empty()
		&& !stripped.starts_with('/')
		&& !parts.is_empty()
		&& !parts.contains(&"..");
	assert_eq!(legacy_acceptance(path), (proto_expected, mcp_expected));
}

pub fn core_text_repo_path_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_repo_path_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn recorded_legacy_disagreements_stay_explicit() {
		for path in ["a//b", "a/./b", "a/", "a\\b", "a\0b", "a\nb"] {
			assert!(RepoPath::new(path).is_err());
			assert_eq!(legacy_acceptance(path), (true, true), "{path:?}");
		}
		for path in ["./a", "/workdir/a"] {
			assert!(RepoPath::new(path).is_err());
			assert_eq!(legacy_acceptance(path), (false, true), "{path:?}");
		}
		let long = "a".repeat(513);
		assert!(RepoPath::new(&long).is_err());
		assert_eq!(legacy_acceptance(&long), (true, true));
	}
}
