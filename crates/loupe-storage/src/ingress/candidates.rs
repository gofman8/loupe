//! Fixed mixed-source duplicate issuance snapshots. Only identity tokens are
//! carried as Agent; commit metadata remains from this actual SQL column.
use loupe_core::review_candidates::{Candidate, CandidateKind};
use loupe_core::review_metadata::ReviewCommit;
use loupe_core::text::policy::{AnchorText, Family, InstanceKey};
use loupe_core::text::{decode_json_string_bounded, Anchor, Error, IdentPolicy, Identifier};
use loupe_provenance::{Agent, Db, Mark, Unvalidated, Validate, ValidateCarrying};
use rusqlite::Row;
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{admission_error, column, invalid, utf8};

pub(crate) const MAX_BYTES: usize = 64 * 1024;

trait AgentIdentity: Sized {
	// Whitespace-folding anchors retain the enclosing document's allowance.
	const DECODE_MAX: usize = MAX_BYTES;
	fn admit(mark: &Mark<'_, Agent>, value: &str) -> Result<Self, Error>;
}
impl AgentIdentity for Identifier<Family, Agent> {
	const DECODE_MAX: usize = Family::MAX_LEN;
	fn admit(mark: &Mark<'_, Agent>, value: &str) -> Result<Self, Error> {
		Self::new(mark, value)
	}
}
impl AgentIdentity for Anchor<AnchorText, Agent> {
	fn admit(mark: &Mark<'_, Agent>, value: &str) -> Result<Self, Error> {
		Self::new(mark, value)
	}
}
impl AgentIdentity for Anchor<InstanceKey, Agent> {
	fn admit(mark: &Mark<'_, Agent>, value: &str) -> Result<Self, Error> {
		Self::new(mark, value)
	}
}
struct IdentityToken<T>(std::marker::PhantomData<T>);
impl<T: AgentIdentity> Validate<&[u8], Agent> for IdentityToken<T> {
	type Output = T;
	type Error = Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>) -> Result<T, Error> {
		let raw = utf8(u.get())?;
		let value =
			decode_json_string_bounded(raw, "candidate_identity", T::DECODE_MAX, T::DECODE_MAX)?;
		#[cfg(test)]
		if let std::borrow::Cow::Owned(decoded) = &value {
			tests::observe_identity_decode(decoded.len());
		}
		T::admit(&mark, &value)
	}
}
fn identity<T: AgentIdentity>(u: &Unvalidated<'_, &[u8], Db>, raw: &RawValue) -> Result<T, Error> {
	let start =
		(raw.get().as_ptr() as usize).checked_sub(u.get().as_ptr() as usize).ok_or_else(invalid)?;
	let end = start.checked_add(raw.get().len()).ok_or_else(invalid)?;
	u.carry::<Agent>(start..end)
		.ok_or_else(invalid)?
		.validate(IdentityToken(std::marker::PhantomData))
}

struct Snapshot;
impl<'a> ValidateCarrying<&'a [u8], Db> for Snapshot {
	type Output = Vec<Candidate<Agent, Db>>;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], Db>) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Raw<'a> {
			kind: CandidateKind,
			id: i64,
			producer_job_id: i64,
			#[serde(borrow)]
			commit_sha: &'a RawValue,
			created_at: i64,
			#[serde(borrow)]
			identity_family: &'a RawValue,
			#[serde(borrow)]
			identity_anchor: &'a RawValue,
			#[serde(borrow)]
			identity_instance_key: Option<&'a RawValue>,
		}
		if u.get().len() > MAX_BYTES {
			return Err(invalid());
		}
		struct Rows<'a>(Vec<Raw<'a>>);
		impl<'de> Deserialize<'de> for Rows<'de> {
			fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
				struct BoundedRows;
				impl<'de> serde::de::Visitor<'de> for BoundedRows {
					type Value = Rows<'de>;
					fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
						f.write_str("at most twenty candidate snapshots")
					}
					fn visit_seq<A: serde::de::SeqAccess<'de>>(
						self, mut sequence: A,
					) -> Result<Self::Value, A::Error> {
						let mut rows = Vec::with_capacity(20);
						for _ in 0..20 {
							let Some(row) = sequence.next_element()? else { return Ok(Rows(rows)) };
							rows.push(row);
						}
						if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
							return Err(serde::de::Error::custom("candidate count exceeds twenty"));
						}
						Ok(Rows(rows))
					}
				}
				deserializer.deserialize_seq(BoundedRows)
			}
		}
		let rows: Rows<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		rows.0
			.into_iter()
			.map(|row| {
				let commit =
					decode_json_string_bounded(row.commit_sha.get(), "commit_sha", 64, 64)?;
				let value = Candidate {
					kind: row.kind,
					id: row.id,
					producer_job_id: row.producer_job_id,
					commit_sha: ReviewCommit::new(&u.mark(), &commit)?,
					created_at: row.created_at,
					identity_family: identity(&u, row.identity_family)?,
					identity_anchor: identity(&u, row.identity_anchor)?,
					identity_instance_key: row
						.identity_instance_key
						.filter(|raw| raw.get() != "null")
						.map(|raw| identity(&u, raw))
						.transpose()?,
				};
				value.validate().map_err(|_| invalid())?;
				Ok(value)
			})
			.collect()
	}
}

/// Caller must check the fixed issuance operation and job scope before reading.
pub(crate) fn snapshot(row: &Row<'_>, index: usize) -> rusqlite::Result<Vec<Candidate<Agent, Db>>> {
	column(row, index)?.validate_carrying(Snapshot).map_err(|error| admission_error(index, error))
}

#[cfg(test)]
mod tests;
