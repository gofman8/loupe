//! Frozen profile content is carried only from its original live SQLite TEXT
//! after checking durable Agent classification. Identifiers retain Db origin.
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::Error;
use loupe_provenance::{Agent, Db, Mark, Unvalidated, Validate, ValidateCarrying};
use rusqlite::Row;

use super::{admission_error, blob, column, invalid, is_null, require_agent_source, utf8};
use crate::generations::FrozenProfile;

struct Commit;
impl Validate<&[u8], Db> for Commit {
	type Output = ReviewCommit<Db>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		ReviewCommit::new(&mark, utf8(u.get())?)
	}
}
pub(crate) fn commit(row: &Row<'_>, index: usize) -> rusqlite::Result<ReviewCommit<Db>> {
	column(row, index)?.validate(Commit).map_err(|error| admission_error(index, error))
}

struct Digest;
impl Validate<&[u8], Db> for Digest {
	type Output = ReviewDigest<Db>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		if u.get().len() != 32 {
			return Err(invalid());
		}
		let hex: String = u.get().iter().map(|byte| format!("{byte:02x}")).collect();
		ReviewDigest::new(&mark, &hex)
	}
}
pub(crate) fn digest(row: &Row<'_>, index: usize) -> rusqlite::Result<ReviewDigest<Db>> {
	blob(row, index)?.validate(Digest).map_err(|error| admission_error(index, error))
}

pub(super) struct StoredProfile;
struct AgentProfile;
impl<'a> ValidateCarrying<&'a [u8], Db> for StoredProfile {
	type Output = GeneratedProfile<Agent>;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], Db>) -> Result<Self::Output, Error> {
		#[cfg(test)]
		tests::observe("column", u.get());
		let profile =
			u.carry::<Agent>(0..u.get().len()).ok_or_else(invalid)?.validate(AgentProfile)?;
		if profile.canonical() != *u.get() {
			return Err(invalid());
		}
		Ok(profile)
	}
}
impl Validate<&[u8], Agent> for AgentProfile {
	type Output = GeneratedProfile<Agent>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
	) -> Result<Self::Output, Error> {
		#[cfg(test)]
		tests::observe("agent", u.get());
		#[cfg(test)]
		super::coverage::observe("agent", u.get());
		GeneratedProfile::new(&mark, utf8(u.get())?)
	}
}

pub(crate) fn frozen_profile(
	row: &Row<'_>, version: usize, raw: usize, hash: usize, source: usize,
) -> rusqlite::Result<Option<FrozenProfile>> {
	if is_null(row, raw)? && is_null(row, hash)? {
		return Ok(None);
	}
	require_agent_source(row, source)?;
	let version = std::num::NonZeroU32::new(row.get(version)?)
		.ok_or_else(|| admission_error(version, invalid()))?;
	let profile = column(row, raw)?
		.validate_carrying(StoredProfile)
		.map_err(|error| admission_error(raw, error))?;
	let digest = digest(row, hash)?;
	if row.get_ref(hash)?.as_blob()? != profile.digest() {
		return Err(admission_error(hash, invalid()));
	}
	Ok(Some(FrozenProfile { version, digest, profile }))
}

#[cfg(test)]
mod tests;
