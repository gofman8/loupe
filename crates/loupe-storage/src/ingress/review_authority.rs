//! Phase policy inputs admitted only from their actual SQL columns.
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
