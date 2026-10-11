//! Byte zero selects one of 36 public DTO types; the rest is raw JSON.
//! Inputs are capped at 512 KiB, allowing report-budget and PoC boundaries.
//! Capability equality uses subtle; the product's ordinary Eq is not invoked
//! on secrets. Other fields still use the DTO's derived PartialEq.

use std::fmt::Debug;

use loupe_proto::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::utils::test_logger;

fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Option<(T, T)> {
	let value: T = serde_json::from_slice(raw).ok()?;
	let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| panic!("DTO serialization failed"));
	let back: T = serde_json::from_slice(&encoded)
		.unwrap_or_else(|_| panic!("serialized DTO could not be decoded"));
	Some((value, back))
}

fn roundtrip<T: DeserializeOwned + Serialize + PartialEq + Debug>(raw: &[u8]) {
	if let Some((value, back)) = decode::<T>(raw) {
		assert_eq!(value, back, "DTO round trip changed a field");
	}
}

fn capability(value: &JobCapability, back: &JobCapability) {
	assert!(
		bool::from(value.expose_secret().as_bytes().ct_eq(back.expose_secret().as_bytes())),
		"capability changed during wire round trip"
	);
	assert_eq!(format!("{value:?}"), "JobCapability([REDACTED])");
	assert_eq!(format!("{back:?}"), "JobCapability([REDACTED])");
}

fn scrub_envelope(value: &mut LeaseEnvelope) {
	let debug = format!("{value:?}");
	value.job_capability = JobCapability::from_secret("fixed debug baseline");
	// Only the capability changes. A coincidental secret match in another
	// public field cannot cause a false positive in this comparison.
	assert_eq!(debug, format!("{value:?}"), "envelope Debug exposes capability");
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, raw)) = data.split_first() else { return };
	if raw.len() > 512 * 1024 {
		return;
	}
	match selector % 36 {
		0 => roundtrip::<LeaseRequest>(raw),
		1 => {
			if let Some((mut value, mut back)) = decode::<LeaseResponse>(raw) {
				if let (LeaseResponse::Lease(a), LeaseResponse::Lease(b)) = (&mut value, &mut back)
				{
					capability(&a.job_capability, &b.job_capability);
					scrub_envelope(a);
					scrub_envelope(b);
				}
				assert_eq!(value, back, "lease response round trip changed a field");
			}
		},
		2 => {
			if let Some((mut value, mut back)) = decode::<LeaseEnvelope>(raw) {
				capability(&value.job_capability, &back.job_capability);
				scrub_envelope(&mut value);
				scrub_envelope(&mut back);
				assert_eq!(value, back, "lease envelope round trip changed a field");
			}
		},
		3 => roundtrip::<LeasePayload>(raw),
		4 => roundtrip::<HeartbeatRequest>(raw),
		5 => roundtrip::<HeartbeatResponse>(raw),
		6 => roundtrip::<FindingsBatch>(raw),
		7 => {
			if let Some((value, back)) = decode::<LlmFindingSubmission>(raw) {
				assert_eq!(value, back);
				assert_eq!(
					validate_llm_finding_submission(&value).is_ok(),
					submission_allowed(&value),
					"LLM submission acceptance disagrees with independent oracle"
				);
			}
		},
		8 => roundtrip::<VerdictSubmission>(raw),
		9 => roundtrip::<CompleteRequest>(raw),
		10 => roundtrip::<ScanRequest>(raw),
		11 => roundtrip::<ScanResponse>(raw),
		12 => roundtrip::<JobInfo>(raw),
		13 => roundtrip::<ReportingSetup>(raw),
		14 => roundtrip::<RegisterRepoRequest>(raw),
		15 => roundtrip::<RegisterRepoResponse>(raw),
		16 => roundtrip::<RotateRepoPatRequest>(raw),
		17 => roundtrip::<SetRepoGithubReportingRequest>(raw),
		18 => roundtrip::<SetGithubAppRequest>(raw),
		19 => roundtrip::<GithubAppSummary>(raw),
		20 => roundtrip::<GithubAppResponse>(raw),
		21 => roundtrip::<UpdateRepoRequest>(raw),
		22 => roundtrip::<ListReposResponse>(raw),
		23 => roundtrip::<GithubReportingAuth>(raw),
		24 => roundtrip::<ReportingSummary>(raw),
		25 => roundtrip::<RepoSummary>(raw),
		26 => roundtrip::<RegisterWorkerRequest>(raw),
		27 => roundtrip::<RegisterWorkerResponse>(raw),
		28 => roundtrip::<ListFindingsResponse>(raw),
		29 => roundtrip::<RetryVerifyRequest>(raw),
		30 => roundtrip::<RetryVerifyResponse>(raw),
		31 => roundtrip::<FindingSummary>(raw),
		32 => roundtrip::<FindingDetail>(raw),
		33 => roundtrip::<CompleteOutcome>(raw),
		34 => {
			if let Some((value, back)) = decode::<JobCapability>(raw) {
				capability(&value, &back);
			}
		},
		35 => roundtrip::<ProtocolMismatch>(raw),
		_ => unreachable!(),
	}
}

fn submission_allowed(value: &LlmFindingSubmission) -> bool {
	let title_chars = value.title.trim().chars().count();
	let description_chars = value.description.trim().chars().count();
	let content_chars = value.description.chars().count() + value.poc_unified.chars().count();
	let cwe_valid = value.cwe.as_ref().is_none_or(|cwe| {
		cwe.as_bytes().starts_with(b"CWE-")
			&& cwe.len() > 4
			&& cwe.as_bytes().iter().skip(4).all(u8::is_ascii_digit)
	});
	let fingerprint_valid = value.fingerprint.len() == 64
		&& value.fingerprint.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
	(8..=100).contains(&title_chars)
		&& (80..=16_384).contains(&description_chars)
		&& content_chars <= 60_000
		&& value.line_start > 0
		&& value.line_end >= value.line_start
		&& relative_path_allowed(&value.file_path)
		&& cwe_valid
		&& fingerprint_valid
		&& value.poc_unified.len() <= 262_144
		&& diff_allowed(&value.poc_unified)
}

// Independent lexical recognizer for the Unix Path::components behavior the
// validator currently accepts: inner dots and repeated/trailing slashes fold,
// a leading dot component or any parent component does not. NUL and backslash
// are ordinary bytes here; this target records existing behavior, not a policy
// change. Keep a platform-equivalent fallback for non-Unix corpus replay.
#[cfg(unix)]
fn relative_path_allowed(path: &str) -> bool {
	!path.trim().is_empty()
		&& !path.starts_with('/')
		&& path.split('/').next() != Some(".")
		&& path.split('/').all(|component| component != "..")
}

#[cfg(not(unix))]
fn relative_path_allowed(path: &str) -> bool {
	let parsed = std::path::Path::new(path);
	!path.trim().is_empty()
		&& !parsed.is_absolute()
		&& parsed.components().all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn diff_allowed(poc: &str) -> bool {
	// Partition at the first hunk before inspecting headers and additions;
	// this oracle has no mutable in-hunk state shared with production.
	let Some(hunk) = poc.lines().position(|line| line.starts_with("@@ ")) else { return false };
	let old = poc.lines().take(hunk).any(|line| line.starts_with("--- "));
	let new = poc.lines().take(hunk).any(|line| line.starts_with("+++ "));
	let added = poc.lines().skip(hunk + 1).any(|line| {
		line.strip_prefix('+')
			.is_some_and(|tail| !tail.starts_with("++") && !tail.trim().is_empty())
	});
	old && new && added
}

pub fn proto_dto_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_dto_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
