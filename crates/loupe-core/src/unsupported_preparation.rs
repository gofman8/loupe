//! The exact mixed-source audit and follow-up document for an unsupported
//! successor checkout. This owner composes existing values; it mints no source.

use loupe_provenance::{Db, Worker};

use crate::review_metadata::ReviewCommit;
use crate::text::json::CheckedJson;
use crate::text::policy::{Payload, RevisionText};
use crate::text::{BoundedJson, BoundedText, Error, Rule};

pub struct UnsupportedPreparation<'a> {
	_recipe: &'a BoundedJson<Payload, Db>,
	_policy: &'a BoundedJson<Payload, Db>,
	_previous: Option<&'a BoundedJson<Payload, Db>>,
	_requested_ref: &'a BoundedText<RevisionText, Db>,
	_resolved_commit: &'a ReviewCommit<Worker>,
	audit: CheckedJson,
	follow_up: CheckedJson,
}
impl<'a> UnsupportedPreparation<'a> {
	pub fn new(
		recipe: &'a BoundedJson<Payload, Db>, policy: &'a BoundedJson<Payload, Db>,
		previous: Option<&'a BoundedJson<Payload, Db>>,
		requested_ref: &'a BoundedText<RevisionText, Db>,
		resolved_commit: &'a ReviewCommit<Worker>, campaign: i64, job: i64,
	) -> Result<Self, Error> {
		let parse = |raw: &str| {
			serde_json::from_str::<serde_json::Value>(raw)
				.map_err(|_| Error::new("unsupported_preparation", Rule::JsonSyntax))
		};
		let audit = serde_json::json!({"version":1,"recipe":parse(recipe.expose())?,
			"policy":parse(policy.expose())?,"requested_ref":requested_ref,
			"resolved_commit":resolved_commit,"requires":"successor_generation"});
		let mut follow_up = previous
			.map(|value| parse(value.expose()))
			.transpose()?
			.unwrap_or_else(|| serde_json::json!({}));
		let object = follow_up
			.as_object_mut()
			.ok_or_else(|| Error::new("unsupported_preparation", Rule::JsonSyntax))?;
		object.insert(
			"unsupported_review".to_owned(),
			serde_json::json!({"campaign_id":campaign,
			"job_id":job,"reason":"requires_successor","requested_ref":requested_ref,
			"resolved_commit":resolved_commit}),
		);
		Ok(Self {
			_recipe: recipe,
			_policy: policy,
			_previous: previous,
			_requested_ref: requested_ref,
			_resolved_commit: resolved_commit,
			audit: CheckedJson::parse::<Payload>(&audit.to_string())?,
			follow_up: CheckedJson::parse::<Payload>(&follow_up.to_string())?,
		})
	}
	pub fn audit(&self) -> &str {
		self.audit.expose()
	}
	pub fn follow_up(&self) -> &str {
		self.follow_up.expose()
	}
}
impl std::fmt::Debug for UnsupportedPreparation<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("UnsupportedPreparation<Db, Worker>([redacted])")
	}
}

#[cfg(test)]
use crate::marked;
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn composition_preserves_prior_fields_and_distinct_owners() {
		let recipe = marked::fixture::<Db, _>(r#"{"recipe":"incremental"}"#, |raw, mark| {
			BoundedJson::new(mark, raw)
		})
		.unwrap();
		let policy =
			marked::fixture::<Db, _>(r#"{"limit":7}"#, |raw, mark| BoundedJson::new(mark, raw))
				.unwrap();
		let previous = marked::fixture::<Db, _>(
			r#"{"existing":{"unknown":true},"triggers":[1],"unsupported_review":{"old":true}}"#,
			|raw, mark| BoundedJson::new(mark, raw),
		)
		.unwrap();
		let requested = marked::fixture::<Db, _>("refs/heads/private-branch", |raw, mark| {
			BoundedText::new(mark, raw)
		})
		.unwrap();
		let resolved =
			marked::fixture::<Worker, _>(&"a".repeat(40), |raw, mark| ReviewCommit::new(mark, raw))
				.unwrap();
		let value = UnsupportedPreparation::new(
			&recipe,
			&policy,
			Some(&previous),
			&requested,
			&resolved,
			5,
			7,
		)
		.unwrap();
		let audit: serde_json::Value = serde_json::from_str(value.audit()).unwrap();
		assert_eq!(audit["recipe"]["recipe"], "incremental");
		assert_eq!(audit["policy"]["limit"], 7);
		assert_eq!(audit["requested_ref"], requested.expose());
		assert_eq!(audit["resolved_commit"], resolved.expose());
		let follow: serde_json::Value = serde_json::from_str(value.follow_up()).unwrap();
		assert_eq!(follow["existing"]["unknown"], true);
		assert_eq!(follow["triggers"], serde_json::json!([1]));
		assert_eq!(follow["unsupported_review"]["job_id"], 7);
		assert!(follow["unsupported_review"].get("old").is_none());
		assert!(!format!("{value:?}").contains("private-branch"));
		let nonobject =
			marked::fixture::<Db, _>("[]", |raw, mark| BoundedJson::new(mark, raw)).unwrap();
		assert!(UnsupportedPreparation::new(
			&recipe,
			&policy,
			Some(&nonobject),
			&requested,
			&resolved,
			5,
			7
		)
		.is_err());
	}
}
