//! Legacy report admission; containment gaps are committed escape seeds for S3.
use loupe_core::Finding;
use loupe_server::reporters::{github, ReportFinding};

use crate::server_common;
use crate::utils::test_logger;

/// Find payload occurrences that are not wholly inside a backtick code fence.
/// A payload containing its own closing fence cannot be considered contained.
pub fn escapes_fences(body: &str, payload: &str) -> bool {
	if payload.is_empty() {
		return false;
	}
	let mut ranges = Vec::new();
	let mut opening = None;
	let mut offset = 0;
	for line in body.split_inclusive('\n') {
		let ticks = line.bytes().take_while(|b| *b == b'`').count();
		if let Some((width, start)) = opening {
			if ticks >= width && line.get(ticks..).is_some_and(|s| s.trim().is_empty()) {
				ranges.push(start..offset);
				opening = None;
			}
		} else if ticks >= 3 {
			opening = Some((ticks, offset + line.len()));
		}
		offset += line.len();
	}
	body.match_indices(payload).any(|(start, _)| {
		!ranges.iter().any(|range| start >= range.start && start + payload.len() <= range.end)
	})
}

pub fn do_test(data: &[u8]) {
	let Ok(finding) = serde_json::from_slice::<Finding>(data) else { return };
	let title = github::render_title(&finding);
	assert!(title.chars().count() <= 100, "GitHub title exceeds its character cap");
	assert!(!title.contains(['\r', '\n']));
	assert!(!title.is_empty());
	let compact = finding.title.split_whitespace().collect::<Vec<_>>().join(" ");
	if compact.is_empty() {
		assert_eq!(title, "Untitled finding");
	} else if compact.chars().count() <= 100 {
		assert_eq!(title, compact);
	} else {
		assert!(title.ends_with("..."));
		assert!(compact.starts_with(title.trim_end_matches('.')));
	}
	let report = ReportFinding { id: 1, finding, reviewed_revision: Some("reviewed-sha".into()) };
	let body = github::render_body(&server_common::repo(), &report);
	assert_eq!(
		github::validate_body(&body).is_ok(),
		body.chars().count() <= 65_536,
		"GitHub body admission must count characters"
	);
	for payload in [
		Some(report.finding.title.as_str()),
		Some(report.finding.description.as_str()),
		report.finding.poc_unified.as_deref(),
		report.finding.patch_unified.as_deref(),
	]
	.into_iter()
	.flatten()
	{
		// Observe the deferred S3 property without writing to the source corpus.
		std::hint::black_box(escapes_fences(&body, payload));
	}
}

pub fn server_report_github_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_report_github_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn containment_distinguishes_plain_text_and_embedded_closing_fences() {
		assert!(!escapes_fences("```diff\nsafe\n```\n", "safe"));
		assert!(escapes_fences("description outside a fence", "outside"));
		assert!(escapes_fences("```diff\n```\nescape\n```\n", "```\nescape"));
	}
}
