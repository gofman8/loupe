//! Shared phase authority. Call inside the same immediate transaction as each
//! mutation or authority-issuing read, never only as an HTTP precheck.
//!
//! This module does not enable routes or runtime claims. Access purpose and
//! expected phase are selected by the server, never deserialized from requests.
use axum::http::HeaderMap;
use loupe_core::review_payload::Version1;
use loupe_storage::{jobs, review_authority as stored, Db, Error, Result};
use serde::Deserialize;
pub use stored::{Access, Phase};

use crate::auth::AuthedWorker;
use crate::job_capability;

// debug-ok: recipe variants are closed server policy choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SurveyRecipe {
	Bootstrap,
	Coverage,
	Incremental,
	Reconciliation,
	Corroboration,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssignmentKey {
	Ordinary,
}

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Recipe {
	Survey {
		#[serde(rename = "version")]
		_version: Version1,
		recipe: SurveyRecipe,
		#[serde(rename = "assignment_key")]
		_assignment_key: AssignmentKey,
	},
	Drilldown {
		#[serde(rename = "version")]
		_version: Version1,
	},
	Verify {
		#[serde(rename = "version")]
		_version: Version1,
	},
}

impl Recipe {
	fn phase(&self) -> Phase {
		match self {
			Self::Survey { .. } => Phase::Survey,
			Self::Drilldown { .. } => Phase::Drilldown,
			Self::Verify { .. } => Phase::Verify,
		}
	}
	fn bootstrap(&self) -> bool {
		matches!(self, Self::Survey { recipe: SurveyRecipe::Bootstrap, .. })
	}
	fn supported(&self, context: &stored::Context, access: Access) -> bool {
		if !matches!(context.campaign_recipe.as_str(), "bootstrap" | "incremental") {
			return false;
		}
		let Some(generation) = &context.generation else {
			return access == Access::Checkout
				&& context.head_sha.is_none()
				&& match self {
					Self::Survey { recipe: SurveyRecipe::Bootstrap, .. } => {
						context.campaign_recipe == loupe_storage::campaigns::Recipe::Bootstrap
					},
					Self::Survey { recipe: SurveyRecipe::Incremental, .. } => {
						context.campaign_recipe == loupe_storage::campaigns::Recipe::Incremental
					},
					_ => false,
				};
		};
		if generation.commit != context.target_commit {
			return false;
		}
		let active = generation.state == loupe_storage::generations::State::Active;
		let bootstrap = generation.state == loupe_storage::generations::State::Building
			&& generation.predecessor.is_none()
			&& context.campaign_recipe == loupe_storage::campaigns::Recipe::Bootstrap;
		match self {
			Self::Survey { recipe: SurveyRecipe::Bootstrap, .. } => bootstrap,
			Self::Survey { recipe: SurveyRecipe::Coverage, .. } => active,
			Self::Survey { recipe: SurveyRecipe::Incremental, .. } => {
				active && context.campaign_recipe == loupe_storage::campaigns::Recipe::Incremental
			},
			Self::Survey { .. } => false,
			Self::Drilldown { .. } | Self::Verify { .. } => active || bootstrap,
		}
	}
}

/// Bind the authenticated worker, job and header to storage's transaction owner.
/// The clock is sampled after the write lock; callback errors prevent commit.
/// A malformed header never enters the callback or returns authority.
pub fn with_transaction<T, E: From<Error>>(
	db: &Db, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64, clock: impl FnOnce() -> i64,
	body: impl for<'tx> FnOnce(&mut stored::PhaseTransaction<'tx>) -> std::result::Result<T, E>,
) -> std::result::Result<Option<T>, E> {
	let Ok(hash) = job_capability::parse_hash(headers) else { return Ok(None) };
	stored::with_phase_transaction(
		db,
		jobs::LeaseIdentity { job_id, worker_id: worker.id(), capability_hash: &hash },
		clock,
		body,
	)
	.map(Some)
}

/// Strict server recipe policy runs on the original stored text, only after
/// storage checks live identity and context. Control never decodes that context.
pub fn authorize<'scope, 'tx>(
	tx: &'scope mut stored::PhaseTransaction<'tx>, phase: Phase, access: Access,
) -> Result<Option<stored::PhaseScope<'scope, 'scope>>> {
	tx.authorize(phase, access, |context| policy(phase, access, context))
}

/// Checkout preparation re-runs this same policy after resolving its generation.
pub fn policy(
	phase: Phase, access: Access, context: &stored::Context,
) -> Result<Option<stored::PolicyDecision>> {
	let Some(recipe) =
		context.recipe.as_ref().and_then(|raw| serde_json::from_str::<Recipe>(raw.expose()).ok())
	else {
		return Ok(None);
	};
	Ok((recipe.phase() == phase && recipe.supported(context, access)).then_some(
		if recipe.bootstrap() {
			stored::PolicyDecision::Bootstrap
		} else {
			stored::PolicyDecision::Ordinary
		},
	))
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
