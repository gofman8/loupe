//! Manifest entries are assembled only from their original live SQL columns.
use loupe_core::inventory_manifest::ManifestEntry;
use loupe_core::review_metadata::ReviewCommit;
use loupe_core::text::{Error, Rule};
use loupe_provenance::{Db, Mark, Unvalidated, Validate};
use rusqlite::Row;

struct ManifestBytes<'a> {
	mode: u32,
	oid: &'a ReviewCommit<Db>,
}
impl Validate<&[u8], Db> for ManifestBytes<'_> {
	type Output = ManifestEntry<Db>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		ManifestEntry::new(&mark, u.get(), self.mode, self.oid.expose())
			.map_err(|_| Error::new("manifest_entry", Rule::Path))
	}
}
pub(crate) fn manifest_entry(
	row: &Row<'_>, raw: usize, mode: usize, oid: usize,
) -> rusqlite::Result<ManifestEntry<Db>> {
	let mode = row.get(mode)?;
	let oid = super::profile::commit(row, oid)?;
	super::blob(row, raw)?
		.validate(ManifestBytes { mode, oid: &oid })
		.map_err(|error| super::admission_error(raw, error))
}
