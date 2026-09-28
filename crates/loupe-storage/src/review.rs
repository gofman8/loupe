//! Shared DAO vocabulary and non-authorizing SQL conversion helpers.
use std::str::FromStr;

use rusqlite::types::Type;
use rusqlite::Row;

// debug-ok: entity kinds are closed schema vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
	Campaign,
	Generation,
	Inventory,
	Unit,
	UnitResult,
	Lead,
	Job,
	Finding,
	Verification,
	Artifact,
	Blob,
	Execution,
	Proof,
}
// debug-ok: closed categories and numeric identity/revision metadata only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
	ActiveCampaign,
	ActiveGeneration,
	CampaignState,
	CampaignSummary,
	CampaignPolicy,
	CompatibilityPolicy,
	Limits,
	CampaignPinned,
	CampaignBudget,
	ActiveDrilldown,
	ActiveVerify,
	JobState,
	GenerationState,
	GenerationPredecessor,
	Coverage,
	InventoryPath,
	InventoryRevision(i64),
	InventoryLimit,
	UnitKey,
	UnitState,
	Assignment,
	Corroboration,
	LeadState,
	Checkpoint,
	CheckpointEvidence,
	CheckpointLimit,
	UnitResultExists,
	IncompatibleReviewState,
	Candidate,
	TerminalReceipt,
	FindingIdentity(i64),
	CompatibilityKey(i64),
	FindingDetails,
	AttemptDetails,
	ArtifactIdentity,
}
// debug-ok: ownership relations are closed schema vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
	CampaignRoot,
	CampaignContinuation,
	CampaignGeneration,
	CampaignSummary,
	GenerationPredecessor,
	CampaignJob,
	InventoryGeneration,
	CarriedUnit,
	UnitJob,
	ResultJob,
	ResultUnit,
	CorroboratedResult,
	CorroboratedExclusion,
	LeadUnit,
	LeadJob,
	ObservationJob,
	SupersededLead,
	DuplicateLead,
	DuplicateFinding,
	PromotedFinding,
	FindingLead,
	Finding,
	Verification,
	VerificationProof,
	JobGeneration,
	JobLead,
	JobFinding,
	JobContinuation,
	Assignment,
	ArtifactBlob,
	ArtifactJob,
	ExecutionJob,
	ExecutionArtifact,
	ProofFinding,
	ProofVerification,
	ProofArtifact,
	ProofExecution,
}

// Only closed scalar vocabularies implement this trait. Text-bearing types,
// including JobKind::Unknown, go through named marked SQL validators.
pub(crate) trait ClosedSqlEnum: FromStr {}
impl ClosedSqlEnum for loupe_core::JobState {}
impl ClosedSqlEnum for loupe_core::FindingState {}
impl ClosedSqlEnum for loupe_core::Severity {}

pub(crate) fn invalid_scalar(index: usize) -> rusqlite::Error {
	rusqlite::Error::FromSqlConversionFailure(index, Type::Text, "invalid stored scalar".into())
}

pub(crate) fn parsed<T: ClosedSqlEnum>(row: &Row<'_>, index: usize) -> rusqlite::Result<T>
where
	T::Err: std::error::Error + Send + Sync + 'static,
{
	row.get_ref(index)?
		.as_str()
		.map_err(|_| invalid_scalar(index))?
		.parse()
		.map_err(|_| invalid_scalar(index))
}
pub(crate) fn optional<T: ClosedSqlEnum>(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<T>>
where
	T::Err: std::error::Error + Send + Sync + 'static,
{
	if matches!(row.get_ref(index)?, rusqlite::types::ValueRef::Null) {
		Ok(None)
	} else {
		parsed(row, index).map(Some)
	}
}

/// A duplicate on a UNIQUE index or on a rowid-alias primary key; SQLite
/// reports the latter with the same message but a different extended code.
pub(crate) fn is_unique(error: &rusqlite::Error, columns: &str) -> bool {
	matches!(error, rusqlite::Error::SqliteFailure(code, Some(message))
		if matches!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
		&& message == &format!("UNIQUE constraint failed: {columns}"))
}
pub(crate) fn classify(error: rusqlite::Error, columns: &str, conflict: Conflict) -> crate::Error {
	if is_unique(&error, columns) {
		crate::Error::Conflict(conflict)
	} else {
		error.into()
	}
}
pub(crate) fn changed(count: usize, conflict: Conflict) -> crate::Result<()> {
	if count == 1 {
		Ok(())
	} else {
		Err(crate::Error::Conflict(conflict))
	}
}

macro_rules! string_enum {
	($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
		// debug-ok: generated enums have only closed unit variants, never their input strings.
		#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum $name { $($variant),+ }
        impl crate::review::ClosedSqlEnum for $name {}
		impl $name { pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } } }
		impl std::str::FromStr for $name {
			type Err = loupe_core::text::Error;
			fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
				match raw { $($value => Ok(Self::$variant),)+ _ => Err(loupe_core::text::Error::new(stringify!($name), loupe_core::text::Rule::Identifier)) }
			}
		}
	};
}
pub(crate) use string_enum;

/// Reserve namespaced formats for strict typed checkpoint readers.
pub(crate) fn is_checkpoint_evidence(raw: &str) -> crate::Result<bool> {
	use loupe_core::text::policy::Payload;
	use loupe_core::text::{JsonPolicy, Rule};
	// Modern checkpoints and historical payloads share the same raw-byte
	// budget. Routing must enforce it before allocating either JSON view.
	if raw.len() > Payload::MAX_BYTES {
		return Err(loupe_core::text::Error::new(Payload::FIELD, Rule::Bytes).into());
	}
	#[cfg(test)]
	crate::checkpoint_evidence_tests::observe_format_parse(raw.len());
	let value: serde_json::Value =
		serde_json::from_str(raw).map_err(loupe_core::review_payload::Error::from)?;
	if !value.is_object() {
		return Ok(false);
	}
	#[derive(serde::Deserialize)]
	struct Marker {
		format: Option<serde_json::Value>,
	}
	let marker: Marker =
		serde_json::from_str(raw).map_err(loupe_core::review_payload::Error::from)?;
	Ok(marker
		.format
		.as_ref()
		.and_then(serde_json::Value::as_str)
		.is_some_and(|format| format.starts_with("loupe.")))
}
pub(crate) fn require_historical_payload(raw: &str) -> crate::Result<()> {
	if is_checkpoint_evidence(raw)? {
		return Err(crate::Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(())
}
/// Projection of already labelled references; this creates no new source owner.
pub(crate) fn checkpoint_refs<S: loupe_provenance::Source>(
	refs: &[loupe_core::text::SourceRef<S>],
) -> crate::Result<String> {
	let value = serde_json::to_value(refs).map_err(loupe_core::review_payload::Error::from)?;
	String::from_utf8(crate::canonical::canonical_bytes(&value))
		.map_err(|_| crate::Error::Conflict(Conflict::CheckpointEvidence))
}
