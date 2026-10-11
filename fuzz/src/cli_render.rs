//! An eight-byte little-endian timestamp, then arbitrary UTF-8 finding text.
//! Both styles exercise every externally supplied text field and both diffs.

use loupe_cli::render::{
	finding, finding_list_row, finding_search_row, format_unix, Style, TerminalText,
};
use loupe_core::{FindingState, Severity};
use loupe_proto::{FindingDetail, FindingSummary, PROTOCOL_VERSION};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 16 * 1024 {
		return;
	}
	let Some((time, text)) = data.split_at_checked(8) else { return };
	let timestamp = i64::from_le_bytes(time.try_into().unwrap_or_else(|_| unreachable!()));
	let formatted = format_unix(timestamp);
	assert!(formatted.ends_with(" UTC"));
	assert!(!formatted.contains(":-"));
	let Ok(text) = std::str::from_utf8(text) else { return };
	let detail = FindingDetail {
		protocol_version: PROTOCOL_VERSION,
		id: 42,
		repo_id: 1,
		job_id: 7,
		scanner_id: text.into(),
		severity: Severity::High,
		title: text.into(),
		description: text.into(),
		file_path: Some(text.into()),
		line_start: Some(1),
		line_end: Some(2),
		cwe: Some(text.into()),
		poc_unified: Some(text.into()),
		patch_unified: Some(text.into()),
		fingerprint: text.into(),
		state: FindingState::AwaitingApproval,
		verification_required: false,
		created_at: timestamp,
		approved_at: Some(timestamp),
		approved_by_cn: Some(text.into()),
		rejected_at: Some(timestamp),
		rejected_by_cn: Some(text.into()),
	};
	let plain = finding(&detail, Style::Plain);
	let colored = finding(&detail, Style::Color);
	let mut unstyled = String::new();
	let mut remaining = colored.as_str();
	while let Some((index, character)) = remaining.char_indices().next() {
		assert_eq!(index, 0);
		if character == '\x1b' {
			let code =
				["\x1b[0m", "\x1b[1m", "\x1b[2m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m"]
					.into_iter()
					.find(|code| remaining.starts_with(code))
					.unwrap_or_else(|| panic!("renderer emitted a foreign escape sequence"));
			remaining = remaining.get(code.len()..).unwrap_or_else(|| unreachable!());
		} else {
			assert!(
				!character.is_control() || character == '\n',
				"renderer emitted a foreign control"
			);
			unstyled.push(character);
			remaining = remaining.get(character.len_utf8()..).unwrap_or_else(|| unreachable!());
		}
	}
	assert_eq!(unstyled, plain, "styling must not change visible content");
	assert!(!plain.chars().any(|c| c.is_control() && c != '\n'));
	// Title is single-line data: each input control has a literal spelling,
	// including CR and LF, even though description/diff lines are structural.
	let mut visible = String::new();
	for character in text.chars() {
		if character.is_control() {
			visible.extend(character.escape_default());
		} else {
			visible.push(character);
		}
	}
	assert!(plain.contains(&format!("[high] — {visible}\n")), "title lost or injected a row");
	assert!(colored.len() <= text.len().saturating_mul(120).saturating_add(4096));
	assert_eq!(TerminalText(text).to_string(), visible, "terminal boundary changed visible text");
	let summary = FindingSummary {
		id: 42,
		repo_id: 1,
		job_id: 7,
		scanner_id: text.into(),
		severity: Severity::High,
		title: text.into(),
		file_path: Some(text.into()),
		line_start: Some(1),
		fingerprint: text.into(),
		state: FindingState::AwaitingApproval,
		verification_required: false,
		created_at: timestamp,
		approved_at: None,
		approved_by_cn: None,
		rejected_at: None,
		rejected_by_cn: None,
	};
	for (row, tabs) in [(finding_list_row(&summary), 7), (finding_search_row(&summary), 5)] {
		assert_eq!(row.matches('\t').count(), tabs, "finding text injected a column");
		assert!(
			!row.chars().any(|c| c.is_control() && c != '\t'),
			"finding text injected a control"
		);
		assert!(row.ends_with(&format!("\t{visible}:1\t{visible}")), "location or title lost");
		assert!(row.contains(&format!("\t{visible}\tstate=")), "scanner identity lost");
	}
}

pub fn cli_render_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_render_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
