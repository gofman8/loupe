use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// Human-facing reference to a stored finding. The numeric ID remains
/// unchanged in storage and HTTP APIs; the prefix distinguishes Loupe
/// findings from issue numbers in a reporting repository.
pub fn format_finding_id(id: i64) -> String {
	format!("LUP-{id}")
}

/// A single security finding produced by a `Scanner` and ferried back to
/// the server. The wire format intentionally mirrors the `findings` table
/// columns one-for-one so the worker can construct one without consulting
/// the storage layer.
///
/// `fingerprint` is the server-side dedup key. Scanners treat it as
/// opaque; the built-in implementations currently hash scanner id,
/// file path, and a normalized source window.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<String>,
	/// Unified diff that adds a regression test demonstrating the
	/// vulnerability — fails on HEAD, passes after a fix is applied.
	/// Distinct from `patch_unified` which carries a candidate *fix*.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<String>,
	pub fingerprint: String,
}

// Findings contain repository and agent text, including paths that can embed
// secrets. Diagnostics expose only severity and source line numbers; serde
// remains the explicit transport for the complete finding.
impl std::fmt::Debug for Finding {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Finding")
			.field("severity", &self.severity)
			.field("line_start", &self.line_start)
			.field("line_end", &self.line_end)
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample() -> Finding {
		Finding {
			scanner_id: "regex-secrets".into(),
			severity: Severity::High,
			title: "AWS access key".into(),
			description: "Found AKIA-prefixed token in source".into(),
			file_path: Some("src/config.rs".into()),
			line_start: Some(42),
			line_end: Some(42),
			cwe: Some("CWE-798".into()),
			patch_unified: None,
			poc_unified: None,
			fingerprint: "deadbeef".into(),
		}
	}

	#[test]
	fn debug_contains_only_severity_and_line_metadata() {
		let mut f = sample();
		let baseline = "Finding { severity: High, line_start: Some(42), line_end: Some(42), .. }";
		for payload in ["private-repository-secret", "Finding", "redacted", ""] {
			f.scanner_id = payload.into();
			f.title = payload.into();
			f.description = payload.into();
			f.file_path = Some(payload.into());
			f.cwe = Some(payload.into());
			f.patch_unified = Some(payload.into());
			f.poc_unified = Some(payload.into());
			f.fingerprint = payload.into();
			assert_eq!(format!("{f:?}"), baseline, "Finding Debug must be independent of text");
		}
	}

	#[test]
	fn round_trips_through_json() {
		let f = sample();
		let s = serde_json::to_string(&f).unwrap();
		let back: Finding = serde_json::from_str(&s).unwrap();
		assert_eq!(f, back);
	}

	#[test]
	fn omits_none_fields_in_serialization() {
		let f = Finding {
			scanner_id: "x".into(),
			severity: Severity::Info,
			title: "t".into(),
			description: "d".into(),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: "fp".into(),
		};
		let s = serde_json::to_string(&f).unwrap();
		assert!(!s.contains("file_path"));
		assert!(!s.contains("cwe"));
		assert!(!s.contains("patch_unified"));
		assert!(!s.contains("poc_unified"));
	}

	#[test]
	fn poc_unified_round_trips_when_present() {
		let mut f = sample();
		f.poc_unified = Some("--- a/src/x.rs\n+++ b/src/x.rs\n@@ ...".into());
		let s = serde_json::to_string(&f).unwrap();
		assert!(s.contains("poc_unified"));
		let back: Finding = serde_json::from_str(&s).unwrap();
		assert_eq!(back.poc_unified.as_deref(), f.poc_unified.as_deref());
	}
}
