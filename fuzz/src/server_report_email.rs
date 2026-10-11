//! Header injection checks for validated operator fields and arbitrary findings.
use loupe_core::Finding;
use loupe_server::reporters::{email, ReportFinding};
use serde::Deserialize;

use crate::server_common;
use crate::utils::test_logger;

#[derive(Deserialize)]
struct Input {
	from: String,
	to: Vec<String>,
	subject: String,
	finding: Finding,
}

pub fn do_test(data: &[u8]) {
	let Ok(input) = serde_json::from_slice::<Input>(data) else { return };
	let mut accepted = true;
	for (name, value) in [("From", &input.from), ("Subject", &input.subject)]
		.into_iter()
		.chain(input.to.iter().map(|value| ("To", value)))
	{
		let valid = !value.contains(['\r', '\n']);
		assert_eq!(
			email::validate_header_value(name, value).is_ok(),
			valid,
			"email header admission differs"
		);
		accepted &= valid;
	}
	if !accepted {
		return;
	}
	let report = ReportFinding { id: 1, finding: input.finding, reviewed_revision: None };
	let message = email::render_message(
		&input.from,
		&input.to,
		&input.subject,
		&server_common::repo(),
		&[report],
	);
	let Some((headers, body)) = message.split_once("\r\n\r\n") else {
		panic!("email header boundary missing")
	};
	let expected = format!("From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8",
		input.from, input.to.join(", "), input.subject);
	assert_eq!(headers, expected, "finding content escaped into email headers");
	// Main has no body cap. Keep a known oversize seed for S3 rather than
	// introducing a cap or dynamically modifying committed test cases here.
	std::hint::black_box(body.len() > 65_536);
}

pub fn server_report_email_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_report_email_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
