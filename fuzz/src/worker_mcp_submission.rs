//! Independent lexical, containment, symlink, and line-range oracles.

use std::path::{Component, Path};

use loupe_worker::mcp::{fuzz_support, normalize_path_component_rules};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let start = input.u32().unwrap_or_default();
	let end = input.u32().unwrap_or_default();
	let Some(path_bytes) = input.len_prefixed(2048) else { return };
	let Ok(path) = std::str::from_utf8(path_bytes) else { return };
	let workdir = tempfile::tempdir().unwrap_or_else(|e| panic!("worktree: {e}"));
	let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("outside: {e}"));
	std::fs::create_dir(workdir.path().join("src")).unwrap_or_else(|e| panic!("source dir: {e}"));
	let contents = input.rest();
	std::fs::write(workdir.path().join("src/lib.rs"), contents)
		.unwrap_or_else(|e| panic!("source: {e}"));
	std::fs::write(outside.path().join("file"), "outside\n")
		.unwrap_or_else(|e| panic!("outside source: {e}"));
	#[cfg(unix)]
	{
		std::os::unix::fs::symlink(outside.path(), workdir.path().join("escape"))
			.unwrap_or_else(|e| panic!("escape: {e}"));
		std::os::unix::fs::symlink("src", workdir.path().join("inside"))
			.unwrap_or_else(|e| panic!("inside: {e}"));
	}
	let stripped = path.strip_prefix("/workdir/").unwrap_or(path);
	let parts: Vec<_> =
		stripped.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	let expected = !stripped.trim().is_empty()
		&& !stripped.starts_with('/')
		&& !parts.is_empty()
		&& !parts.contains(&"..");
	let lexical = normalize_path_component_rules(path);
	assert_eq!(lexical.is_ok(), expected);
	if let Ok(relative) = lexical {
		assert_eq!(relative, parts.join("/"));
		assert!(Path::new(&relative).components().all(|part| matches!(part, Component::Normal(_))));
		let candidate = workdir.path().join(&relative);
		// Materialize fuzzed names only below the fresh worktree and
		// outside the deliberately external symlink's subtree.
		if !relative.starts_with("escape/") && relative != "escape" && !candidate.exists() {
			if let Some(parent) = candidate.parent() {
				let _ = std::fs::create_dir_all(parent);
			}
			let _ = std::fs::write(&candidate, contents);
		}
		let normalized = fuzz_support::normalize(workdir.path(), path);
		if candidate.exists() {
			let canonical = candidate.canonicalize().unwrap_or_else(|e| panic!("candidate: {e}"));
			let root = workdir.path().canonicalize().unwrap_or_else(|e| panic!("root: {e}"));
			assert_eq!(normalized.is_ok(), canonical.starts_with(root));
		} else {
			assert!(normalized.is_ok());
		}
		if let Ok(relative) = normalized {
			let fingerprint = fuzz_support::fingerprint(workdir.path(), &relative, start, end);
			assert_eq!(fingerprint.len(), 64);
			if let Ok(source) = std::fs::read_to_string(&candidate) {
				let window = source
					.lines()
					.enumerate()
					.filter_map(|(index, line)| {
						let number = index as u64 + 1;
						(number + 2 >= u64::from(start)
							&& number <= u64::from(end.saturating_add(2)))
						.then_some(line)
					})
					.collect::<Vec<_>>()
					.join("\n");
				assert_eq!(
					fingerprint,
					loupe_worker::fingerprint::compute(
						loupe_worker::scanners::llm_code_review::SCANNER_ID,
						&relative,
						&window
					)
				);
			}
			let args = serde_json::json!({"severity":"high","title":"title","file":path,
				"line_start":start,"line_end":end,"description":"description","poc_unified":"diff"});
			let finding = fuzz_support::finding(workdir.path(), &args)
				.unwrap_or_else(|e| panic!("finding: {e}"));
			assert_eq!(finding.line_start, Some(start));
			assert_eq!(finding.line_end, Some(end));
		}
	}
	#[cfg(unix)]
	assert!(fuzz_support::normalize(workdir.path(), "escape/file").is_err());
}

pub fn worker_mcp_submission_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_submission_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
