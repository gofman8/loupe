//! Strict frozen numeric policy decoding from original SQLite TEXT.
use loupe_core::text::policy::Payload;
use loupe_core::text::{Error, JsonPolicy, Rule};
use loupe_provenance::{Db, Mark, Unvalidated, Validate};
use rusqlite::Row;

use super::{admission_error, column, invalid, utf8};
use crate::admission_policy::CampaignPolicyV2;

struct StoredV2Policy;
impl Validate<&[u8], Db> for StoredV2Policy {
	type Output = CampaignPolicyV2;
	type Error = Error;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, _: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		if input.get().len() > Payload::MAX_BYTES {
			return Err(Error::new(Payload::FIELD, Rule::Bytes));
		}
		let policy = CampaignPolicyV2::from_json(utf8(input.get())?).map_err(|_| invalid())?;
		if policy.canonical_bytes().map_err(|_| invalid())? != *input.get() {
			return Err(invalid());
		}
		Ok(policy)
	}
}

pub(crate) fn policy(
	row: &Row<'_>, raw: usize, digest: usize,
) -> rusqlite::Result<CampaignPolicyV2> {
	let policy =
		column(row, raw)?.validate(StoredV2Policy).map_err(|error| admission_error(raw, error))?;
	// Read the original BLOB in this same row; no normalization or copied SQL
	// text can erase duplicate keys before the strict validator above sees them.
	let bytes = policy.canonical_bytes().map_err(|_| admission_error(raw, invalid()))?;
	if row.get_ref(digest)?.as_blob()? != loupe_core::canonical::digest(&bytes) {
		return Err(admission_error(digest, invalid()));
	}
	Ok(policy)
}
