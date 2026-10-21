use loupe_provenance::{Agent, Worker};
use serde_json::{json, Value};

use super::*;
use crate::test_support::worker_request;

fn payload() -> Value {
	json!({
		"protocol_version": crate::PROTOCOL_VERSION, "client_review_unit_key": "proposal",
		"title": "Inspect boundary", "objective": "Trace callers", "priority_band": "urgent",
		"priority_rationale": "Sensitive sink", "source_refs": [{"path": "e\u{301}.rs", "symbol": "check"}],
		"depends_on_review_unit_ids": [1], "closure_criteria": "Account for callers",
		"semantic_context": "Caller context"
	})
}
fn decode(
	raw: &str,
) -> Result<ReviewUnitRequest<Agent, Worker>, loupe_core::review_payload::Error> {
	worker_request(raw.as_bytes()).validate_carrying(ReviewUnitRequestDecoder)
}

#[test]
fn original_spans_preserve_mixed_sources_wire_defaults_and_exact_paths() {
	let raw = payload();
	let request = decode(&raw.to_string()).unwrap();
	let _: &Identifier<ClientKey, Worker> = &request.client_review_unit_key;
	let _: &BoundedText<Title, Agent> = &request.title;
	let _: &BoundedText<Reason, Agent> = request.closure_criteria.as_ref().unwrap();
	assert_eq!(serde_json::to_value(&request).unwrap(), raw);
	assert_eq!(request.source_refs.as_slice()[0].path.expose(), "e\u{301}.rs");
	let mut composed = raw.clone();
	composed["source_refs"][0]["path"] = json!("é.rs");
	assert_ne!(request.digest().unwrap(), decode(&composed.to_string()).unwrap().digest().unwrap());
	let mut missing = raw;
	for key in
		["depends_on_review_unit_ids", "priority_rationale", "closure_criteria", "semantic_context"]
	{
		missing.as_object_mut().unwrap().remove(key);
	}
	let request = decode(&missing.to_string()).unwrap();
	assert!(request.depends_on_review_unit_ids.as_slice().is_empty());
	assert!(
		request.priority_rationale.is_none()
			&& request.closure_criteria.is_none()
			&& request.semantic_context.is_none()
	);
	assert!(!format!("{request:?}").contains("Inspect boundary"));
}

#[test]
fn bounds_unknown_duplicates_and_dependencies_are_strict() {
	for (field, value) in [
		("title", json!("a".repeat(201))),
		("closure_criteria", json!("a".repeat(1001))),
		("closure_criteria", json!("first\nsecond")),
		("semantic_context", json!("a".repeat(4001))),
		("client_review_unit_key", json!("a".repeat(129))),
		("source_refs", json!([])),
		("source_refs", json!((0..33).map(|_| json!({"path":"a.rs"})).collect::<Vec<_>>())),
		("depends_on_review_unit_ids", json!([1, 1])),
		("depends_on_review_unit_ids", json!([0])),
		("depends_on_review_unit_ids", json!((1..=9).collect::<Vec<_>>())),
		("protocol_version", json!(crate::PROTOCOL_VERSION + 1)),
		("job_id", json!(1)),
	] {
		let mut raw = payload();
		raw[field] = value;
		assert!(decode(&raw.to_string()).is_err(), "{field}");
	}
	let raw = payload().to_string().replace("\"title\":", "\"title\":\"duplicate\",\"title\":");
	assert!(decode(&raw).is_err());
	let mut maximum = payload();
	maximum["closure_criteria"] = json!("a".repeat(1000));
	maximum["source_refs"] =
		json!((0..32).map(|n| json!({"path":format!("{n}.rs")})).collect::<Vec<_>>());
	assert!(decode(&maximum.to_string()).is_ok());
	assert!(decode(&" ".repeat(256 * 1024 + 1)).is_err());
}

#[test]
fn source_parameters_add_no_incidental_traits() {
	fn traits<T: Clone + Eq + serde::Serialize + std::fmt::Debug>() {}
	fn check<C: Source, K: Source>() {
		traits::<ReviewUnitRequest<C, K>>();
	}
	check::<Agent, Worker>();
}
