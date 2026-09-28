//! Phase policy inputs admitted only from their actual SQL columns.
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::{BoundedText, Error};
use loupe_provenance::{Db, Mark, Unvalidated, Validate};
use rusqlite::Row;

use crate::review_authority::RecipeText;

struct Recipe;
impl Validate<&[u8], Db> for Recipe {
	type Output = BoundedText<RecipeText, Db>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		BoundedText::new(&mark, super::utf8(u.get())?)
	}
}
pub(crate) fn optional_recipe(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<Option<BoundedText<RecipeText, Db>>> {
	if super::is_null(row, index)? {
		return Ok(None);
	}
	super::column(row, index)?
		.validate(Recipe)
		.map(Some)
		.map_err(|error| super::admission_error(index, error))
}
struct CanonicalProfile;
impl Validate<&[u8], Db> for CanonicalProfile {
	type Output = Option<[u8; 32]>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		let profile = GeneratedProfile::new(&mark, super::utf8(u.get())?)?;
		Ok((profile.canonical() == *u.get()).then_some(*profile.digest()))
	}
}
pub(crate) fn canonical_profile_matches(
	row: &Row<'_>, raw: usize, digest: usize,
) -> rusqlite::Result<bool> {
	if super::is_null(row, raw)? || super::is_null(row, digest)? {
		return Ok(false);
	}
	let digest: Vec<u8> = row.get(digest)?;
	Ok(
		matches!(super::column(row,raw)?.validate(CanonicalProfile), Ok(Some(actual)) if digest == actual),
	)
}
