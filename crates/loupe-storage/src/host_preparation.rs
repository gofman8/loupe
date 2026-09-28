//! Attempt-bound host preparation results. Mutations are available only through
//! the identity-bound phase transaction and its purpose-bound scopes.

pub use loupe_core::inventory_manifest::ManifestEntry;
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_provenance::Db;

use crate::review_authority::PhaseScope;
use crate::terminal_receipt::Receipt;

// debug-ok: row identifiers, counters, a content digest and timestamps only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
	pub generation_id: i64,
	pub owner_job_id: Option<i64>,
	pub expected_count: u64,
	pub digest: [u8; 32],
	pub digest_hex: ReviewDigest<Db>,
	pub received_count: u64,
	pub received_bytes: u64,
	pub sealed_at: Option<i64>,
}

// debug-ok: frozen profile version and content digest only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedProfile {
	pub version: i64,
	pub digest: [u8; 32],
	pub digest_hex: ReviewDigest<Db>,
}

/// Prepared authority is issued only after pinning, exact-attempt confirmation
/// and a second server policy decision over the now-pinned generation.
pub enum PinOutcome<'scope, 'tx> {
	Prepared(PhaseScope<'scope, 'tx>),
	Deferred { receipt: Box<Receipt>, commit: ReviewCommit<Db> },
}

// debug-ok: retained receipt and commit use redacted owners; reject is closed.
#[derive(Debug)]
pub enum PinReplay {
	Receipt { receipt: Box<Receipt>, commit: ReviewCommit<Db> },
	Reject(crate::terminal_receipt::Reject),
}

#[cfg(test)]
mod tests;
