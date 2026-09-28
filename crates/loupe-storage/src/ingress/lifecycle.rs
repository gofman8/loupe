//! Execution compatibility over original SQL columns, not Domain readiness.
//! No profile or recipe authority escapes these predicates.
use std::convert::Infallible;

use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::policy::Payload;
use loupe_core::text::{BoundedJson, JsonPolicy};
use loupe_provenance::{Db, Mark, Unvalidated, Validate};
use rusqlite::types::ValueRef;
use rusqlite::Row;

use super::{column, utf8};

// debug-ok: frozen retry limits contain only numeric execution policy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryLimits {
	pub maximum: u32,
	pub delay: i64,
}
struct RetryPolicy(u32);
impl Validate<&[u8], Db> for RetryPolicy {
	type Output = Option<RetryLimits>;
	type Error = Infallible;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, _: Mark<'v, Db>,
	) -> Result<Self::Output, Infallible> {
		let bytes = *input.get();
		if bytes.len() > Payload::MAX_BYTES {
			return Ok(None);
		}
		let Ok(raw) = utf8(bytes) else { return Ok(None) };
		if let Ok(policy) = crate::admission_policy::CampaignPolicyV2::from_json(raw) {
			return Ok(policy.canonical_bytes().ok().filter(|canonical| canonical == bytes).map(
				|_| RetryLimits { maximum: policy.max_attempts, delay: policy.retry_delay(self.0) },
			));
		}
		// Historical v1 is execution control only, never v2 admission authority.
		let Ok(policy) = serde_json::from_str::<crate::scheduler::CampaignPolicy>(raw) else {
			return Ok(None);
		};
		if policy.validate().is_err() {
			return Ok(None);
		}
		// The strict v1 schema admits omitted optional token fields. Compare
		// canonical original JSON, not a reconstruction that adds null fields.
		// Schema validation above has already rejected unknown/duplicate keys.
		let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else { return Ok(None) };
		Ok((crate::canonical::canonical_bytes(&value) == bytes).then(|| RetryLimits {
			maximum: policy.max_attempts,
			delay: policy.retry_delay(self.0),
		}))
	}
}
pub(crate) fn retry_policy(
	row: &Row<'_>, raw: usize, digest: usize, attempt: u32,
) -> rusqlite::Result<Option<RetryLimits>> {
	let (ValueRef::Text(bytes), ValueRef::Blob(stored)) = (row.get_ref(raw)?, row.get_ref(digest)?)
	else {
		return Ok(None);
	};
	if stored != crate::canonical::digest(bytes) {
		return Ok(None);
	}
	Ok(column(row, raw)?.validate(RetryPolicy(attempt)).unwrap_or_else(|never| match never {}))
}

struct RecipeCompatibility;
impl Validate<&[u8], Db> for RecipeCompatibility {
	type Output = bool;
	type Error = Infallible;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<bool, Infallible> {
		Ok(utf8(input.get()).is_ok_and(|raw| BoundedJson::<Payload, Db>::new(&mark, raw).is_ok()))
	}
}
struct ProfileCompatibility;
impl Validate<&[u8], Db> for ProfileCompatibility {
	type Output = bool;
	type Error = Infallible;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<bool, Infallible> {
		Ok(utf8(input.get()).is_ok_and(|raw| GeneratedProfile::new(&mark, raw).is_ok()))
	}
}
pub(crate) fn recipe(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
	match row.get_ref(index)? {
		ValueRef::Null => Ok(true),
		ValueRef::Text(_) => Ok(column(row, index)?
			.validate(RecipeCompatibility)
			.unwrap_or_else(|never| match never {})),
		_ => Ok(false),
	}
}
pub(crate) fn profile(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
	match row.get_ref(index)? {
		ValueRef::Null => Ok(true),
		ValueRef::Text(_) => Ok(column(row, index)?
			.validate(ProfileCompatibility)
			.unwrap_or_else(|never| match never {})),
		_ => Ok(false),
	}
}
