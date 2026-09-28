//! Decode the authenticated worker's URI without relabelling query content.
use axum::extract::Query;
use axum::http::Uri;
use loupe_core::review_candidates::{CandidateQuery, QueryText};
use loupe_provenance::{Mark, Untrusted, Unvalidated, Validate, Worker};
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::review::http::{ApiError, Result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuery {
	query: String,
	#[serde(default = "default_limit")]
	limit: u8,
}
fn default_limit() -> u8 {
	10
}

struct CandidateQueryDecoder;
impl Validate<&Uri, Worker> for CandidateQueryDecoder {
	type Output = CandidateQuery<Worker>;
	type Error = ApiError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &Uri>, mark: Mark<'view, Worker>,
	) -> Result<Self::Output> {
		if input.get().query().is_some_and(|query| query.len() > 8192) {
			return Err(ApiError::invalid("query string exceeds 8 KiB"));
		}
		let Query(raw) = Query::<RawQuery>::try_from_uri(input.get()).map_err(ApiError::invalid)?;
		let query = CandidateQuery {
			query: QueryText::new(&mark, &raw.query).map_err(ApiError::invalid)?,
			limit: raw.limit,
		};
		query.validate().map_err(ApiError::invalid)?;
		Ok(query)
	}
}

pub(crate) fn candidates(worker: &AuthedWorker, uri: &Uri) -> Result<CandidateQuery<Worker>> {
	let token = worker.worker_ingress().ok_or_else(ApiError::denied)?;
	Untrusted::new(uri, token).validate(CandidateQueryDecoder)
}
