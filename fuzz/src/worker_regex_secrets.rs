//! Raw file bytes reach the scanner's actual synchronous walk. Byte zero
//! selects cancellation (bit 0), cap+1 (bit 1), or exact cap (bit 2). A byte
//! recognizer independent of regex computes every match and source line.
//! The input cap is 64 KiB; boundary modes pad with non-matching bytes.

use std::fs;
use std::sync::OnceLock;

use loupe_core::Severity;
use loupe_worker::scanners::RegexSecretsScanner;

use crate::utils::redact::{assert_redacted, Redaction};
use crate::utils::test_logger;

const FILE_CAP: usize = 1_048_576;

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let (&mode, body) = data.split_first().unwrap_or((&0, &[]));
	let mut content = body.to_vec();
	if mode & 2 != 0 {
		content.resize(FILE_CAP + 1, b'x');
	} else if mode & 4 != 0 {
		content.resize(FILE_CAP, b'x');
	}
	// Hostile file names matter too: Finding's description and file_path carry
	// them. Keep the fixture name a bounded single safe filesystem component.
	let name: String =
		body.iter().copied().filter(u8::is_ascii_alphanumeric).take(80).map(char::from).collect();
	let leaf = format!("source-{name}.rs");
	let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("create regex fixture"));
	let root = temp.path().join("repo");
	fs::create_dir_all(root.join(".git"))
		.unwrap_or_else(|_| panic!("create regex fixture directories"));
	fs::write(root.join(&leaf), &content).unwrap_or_else(|_| panic!("write regex source"));
	fs::write(root.join(".git/ignored.rs"), b"AKIAIOSFODNN7EXAMPLE")
		.unwrap_or_else(|_| panic!("write metadata fixture"));
	fs::write(temp.path().join("outside.rs"), b"AKIAIOSFODNN7EXAMPLE")
		.unwrap_or_else(|_| panic!("write outside fixture"));
	#[cfg(unix)]
	std::os::unix::fs::symlink(temp.path().join("outside.rs"), root.join("linked.rs"))
		.unwrap_or_else(|_| panic!("create regex symlink"));
	static SCANNER: OnceLock<RegexSecretsScanner> = OnceLock::new();
	let findings = SCANNER
		.get_or_init(RegexSecretsScanner::new)
		.fuzz_walk(&root, mode & 1 != 0)
		.unwrap_or_else(|_| panic!("scan regex fixture"));
	let expected = if mode & 1 != 0 { Vec::new() } else { match_lines(&content) };
	assert_eq!(findings.len(), expected.len(), "scanner match count differs from byte oracle");
	for (finding, line) in findings.iter().zip(expected) {
		assert_eq!(finding.scanner_id, "regex-secrets");
		assert_eq!(finding.severity, Severity::High);
		assert_eq!(finding.file_path.as_deref(), Some(leaf.as_str()));
		assert_eq!(finding.line_start, Some(line), "finding starts at wrong source line");
		assert_eq!(finding.line_end, Some(line), "finding ends at wrong source line");
		let line_count = content.iter().filter(|byte| **byte == b'\n').count() + 1;
		assert!(line > 0 && line as usize <= line_count, "finding line is outside file");
		let baseline = Redaction::baseline(format!(
			"Finding {{ severity: High, line_start: Some({line}), line_end: Some({line}), .. }}"
		));
		assert_redacted(&format!("{finding:?}"), &content, &baseline);
	}
}

fn match_lines(bytes: &[u8]) -> Vec<u32> {
	if bytes.is_empty()
		|| bytes.len() > FILE_CAP
		|| bytes.iter().take(8192).any(|byte| *byte == 0)
		|| std::str::from_utf8(bytes).is_err()
	{
		return Vec::new();
	}
	let mut out = Vec::new();
	let mut offset = 0;
	let mut line = 1;
	while offset < bytes.len() {
		let matched = bytes.get(offset..offset + 20).is_some_and(|window| {
			window.starts_with(b"AKIA")
				&& window[4..].iter().all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z'))
		});
		if matched {
			out.push(line);
			offset += 20;
		} else {
			line += u32::from(bytes[offset] == b'\n');
			offset += 1;
		}
	}
	out
}

pub fn worker_regex_secrets_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_regex_secrets_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::match_lines;

	#[test]
	fn byte_oracle_distinguishes_matches_lines_and_rejections() {
		assert_eq!(match_lines(b"\nAKIAIOSFODNN7EXAMPLE AKIA0000000000000000\r\n"), [2, 2]);
		assert!(match_lines(b"AKIAshort").is_empty());
		assert!(match_lines(b"AKIA000000000000000x").is_empty());
		assert!(match_lines(b"\0AKIAIOSFODNN7EXAMPLE").is_empty());
		assert!(match_lines(b"\xffAKIAIOSFODNN7EXAMPLE").is_empty());
	}
}
