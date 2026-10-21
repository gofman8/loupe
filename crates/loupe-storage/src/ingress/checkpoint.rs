//! Format routing over the actual SQL column, before any historical normalization.
use loupe_core::review_payload::{LeadEvidenceV1, UnitResultPayloadV1};

use super::*;
use crate::StoredEvidence;

struct CheckpointMarker;
impl Validate<&[u8], Db> for CheckpointMarker {
	type Output = bool;
	type Error = crate::Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Db>) -> crate::Result<bool> {
		crate::review::is_checkpoint_evidence(utf8(u.get())?)
	}
}
pub(crate) fn is_modern(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
	column(row, index)?.validate(CheckpointMarker).map_err(|_| sql_error(index, ReadError::Syntax))
}
pub(crate) fn historical_payload(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<BoundedJson<policy::Payload, Agent>> {
	if is_modern(row, index)? {
		return Err(sql_error(index, ReadError::Syntax));
	}
	agent_payload(row, index)
}
fn valid_digest(row: &Row<'_>, index: usize, digest: usize) -> crate::Result<()> {
	let ValueRef::Text(raw) = row.get_ref(index)? else {
		return Err(sql_error(index, ReadError::Syntax).into());
	};
	let ValueRef::Blob(stored) = row.get_ref(digest)? else {
		return Err(sql_error(digest, ReadError::Syntax).into());
	};
	if stored != crate::canonical::digest(raw) {
		return Err(crate::Error::Conflict(crate::Conflict::CheckpointEvidence));
	}
	Ok(())
}
pub(crate) fn lead(
	row: &Row<'_>, index: usize, digest: usize,
) -> crate::Result<StoredEvidence<LeadEvidenceV1<Agent>>> {
	if !is_modern(row, index)? {
		agent_payload(row, index)?;
		return Ok(StoredEvidence::Historical);
	}
	let value = super::review_payload::lead_evidence(row, index)?;
	valid_digest(row, index, digest)?;
	Ok(StoredEvidence::Recorded(value))
}
pub(crate) fn unit_result(
	row: &Row<'_>, index: usize, digest: usize,
) -> crate::Result<StoredEvidence<UnitResultPayloadV1<Agent>>> {
	if !is_modern(row, index)? {
		agent_payload(row, index)?;
		return Ok(StoredEvidence::Historical);
	}
	let value = super::review_payload::unit_result(row, index)?;
	valid_digest(row, index, digest)?;
	Ok(StoredEvidence::Recorded(value))
}
