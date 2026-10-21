//! Minimal duplicate-search projections. Identity is Agent content; checkout
//! metadata retains its actual source. These records confer no authority.
//! ```compile_fail,E0277
//! use loupe_core::review_candidates::Candidate;
//! use loupe_provenance::{Agent, Db};
//! let _: Candidate<Agent, Db> = serde_json::from_str("{}").unwrap();
//! ```
use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

use crate::review_metadata::ReviewCommit;
use crate::text::policy::{AnchorText, Family, InstanceKey};
use crate::text::{Anchor, BoundedText, Identifier, TextPolicy};

// debug-ok: a content-free policy marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPolicy;
impl TextPolicy for QueryPolicy {
	const FIELD: &'static str = "query";
	const MAX_CHARS: usize = 500;
	const MAX_BYTES: usize = 1000;
	const MULTILINE: bool = false;
}
pub type QueryText<S> = BoundedText<QueryPolicy, S>;

// debug-ok: closed candidate kind, not supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
	Lead,
	Finding,
}

/// Immutable identity copied at issuance; mutable lifecycle state is absent.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct Candidate<C: Source, M: Source> {
	pub kind: CandidateKind,
	pub id: i64,
	pub producer_job_id: i64,
	pub commit_sha: ReviewCommit<M>,
	pub created_at: i64,
	pub identity_family: Identifier<Family, C>,
	pub identity_anchor: Anchor<AnchorText, C>,
	pub identity_instance_key: Option<Anchor<InstanceKey, C>>,
}
impl<C: Source, M: Source> Candidate<C, M> {
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.id <= 0 || self.producer_job_id <= 0 {
			Err("candidate IDs must be positive")
		} else {
			Ok(())
		}
	}
}
impl<C: Source, M: Source> Clone for Candidate<C, M> {
	fn clone(&self) -> Self {
		Self {
			kind: self.kind,
			id: self.id,
			producer_job_id: self.producer_job_id,
			commit_sha: self.commit_sha.clone(),
			created_at: self.created_at,
			identity_family: self.identity_family.clone(),
			identity_anchor: self.identity_anchor.clone(),
			identity_instance_key: self.identity_instance_key.clone(),
		}
	}
}
impl<C: Source, M: Source> PartialEq for Candidate<C, M> {
	fn eq(&self, other: &Self) -> bool {
		self.kind == other.kind
			&& self.id == other.id
			&& self.producer_job_id == other.producer_job_id
			&& self.commit_sha == other.commit_sha
			&& self.created_at == other.created_at
			&& self.identity_family == other.identity_family
			&& self.identity_anchor == other.identity_anchor
			&& self.identity_instance_key == other.identity_instance_key
	}
}
impl<C: Source, M: Source> Eq for Candidate<C, M> {}
impl<C: Source, M: Source> std::fmt::Debug for Candidate<C, M> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("Candidate([redacted])")
	}
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct CandidateQuery<S: Source> {
	pub query: QueryText<S>,
	pub limit: u8,
}
impl<S: Source> CandidateQuery<S> {
	pub fn validate(&self) -> Result<(), &'static str> {
		if (1..=20).contains(&self.limit) {
			Ok(())
		} else {
			Err("candidate limit must be between 1 and 20")
		}
	}
}
impl<S: Source> Clone for CandidateQuery<S> {
	fn clone(&self) -> Self {
		Self { query: self.query.clone(), limit: self.limit }
	}
}
impl<S: Source> PartialEq for CandidateQuery<S> {
	fn eq(&self, other: &Self) -> bool {
		self.query == other.query && self.limit == other.limit
	}
}
impl<S: Source> Eq for CandidateQuery<S> {}
impl<S: Source> std::fmt::Debug for CandidateQuery<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("CandidateQuery([redacted])")
	}
}

#[cfg(test)]
use crate::marked;
#[cfg(test)]
mod tests {
	use loupe_provenance::{Agent, Db, Worker};

	use super::*;

	#[test]
	fn source_parameters_need_no_incidental_traits() {
		fn traits<T: Clone + Eq + std::fmt::Debug + Serialize>() {}
		traits::<Candidate<Agent, Db>>();
		traits::<CandidateQuery<Worker>>();
	}

	#[test]
	fn query_limits_preserve_the_original_contract() {
		let text =
			marked::fixture::<Worker, _>("private query", |raw, mark| QueryText::new(mark, raw))
				.unwrap();
		for limit in [0, 1, 10, 20, 21, u8::MAX] {
			let query = CandidateQuery { query: text.clone(), limit };
			assert_eq!(query.validate().is_ok(), (1..=20).contains(&limit));
			assert!(!format!("{query:?}").contains("private query"));
		}
		for (raw, valid) in [
			("x".repeat(500), true),
			("x".repeat(501), false),
			("é".repeat(500), true),
			("a\nb".into(), false),
		] {
			assert_eq!(
				marked::fixture::<Worker, _>(&raw, |raw, mark| QueryText::new(mark, raw)).is_ok(),
				valid
			);
		}
	}

	#[test]
	fn candidate_wire_retains_identity_and_metadata_without_debug_disclosure() {
		let mut candidate = Candidate {
			kind: CandidateKind::Lead,
			id: 7,
			producer_job_id: 11,
			commit_sha: marked::fixture::<Db, _>(&"a".repeat(40), |raw, mark| {
				ReviewCommit::new(mark, raw)
			})
			.unwrap(),
			created_at: 23,
			identity_family: marked::fixture::<Agent, _>("private-family", |raw, mark| {
				Identifier::new(mark, raw)
			})
			.unwrap(),
			identity_anchor: marked::fixture::<Agent, _>("private anchor", |raw, mark| {
				Anchor::new(mark, raw)
			})
			.unwrap(),
			identity_instance_key: None,
		};
		assert_eq!(candidate, candidate.clone());
		assert!(candidate.validate().is_ok());
		assert_eq!(
			serde_json::to_value(&candidate).unwrap(),
			serde_json::json!({"kind":"lead","id":7,"producer_job_id":11,"commit_sha":"a".repeat(40),"created_at":23,"identity_family":"private-family","identity_anchor":"private anchor","identity_instance_key":null})
		);
		assert!(!format!("{candidate:?}").contains("private"));
		candidate.id = 0;
		assert!(candidate.validate().is_err());
		candidate.id = 7;
		candidate.producer_job_id = 0;
		assert!(candidate.validate().is_err());
	}
}
