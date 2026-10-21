//! Byte-exact inventory references, including visibly unrepresentable entries.
use loupe_core::text::policy::{Reason, RevisionText};
use loupe_core::text::{BoundedText, RepoPath, SourceRef};
use loupe_provenance::{Agent, Db, Mark, Repo, Source};
use rusqlite::{params, Connection, OptionalExtension};

pub use crate::ingress::InventoryRendering;
use crate::review::{is_unique, parsed, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(EntryKind { Tracked => "tracked", Submodule => "submodule" });
string_enum!(Disposition { Mapped => "mapped", Context => "context", Excluded => "excluded", Unresolved => "unresolved" });
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_RAW_PATH_BYTES: usize = loupe_core::inventory_manifest::MAX_PATH_BYTES;

pub(crate) struct RawPath<S: Source>(Vec<u8>, std::marker::PhantomData<S>);
impl<S: Source> RawPath<S> {
	pub(crate) fn new(
		_: &Mark<'_, S>, raw: &[u8],
	) -> std::result::Result<Self, loupe_core::text::Error> {
		if raw.is_empty() || raw.len() > MAX_RAW_PATH_BYTES {
			return Err(loupe_core::text::Error::new("raw_path", loupe_core::text::Rule::Bytes));
		}
		Ok(Self(raw.to_vec(), std::marker::PhantomData))
	}
}
impl<S: Source> Clone for RawPath<S> {
	fn clone(&self) -> Self {
		Self(self.0.clone(), std::marker::PhantomData)
	}
}

pub struct InventoryPath<S: Source> {
	rendering: BoundedText<InventoryRendering, S>,
	raw: Option<RawPath<S>>,
	source: Option<RepoPath<S>>,
}
impl InventoryPath<Repo> {
	pub fn from_git_bytes(mark: &Mark<'_, Repo>, raw: &[u8]) -> Result<Self> {
		let raw_path = RawPath::new(mark, raw)?;
		if let Ok(text) = std::str::from_utf8(raw)
			&& let Ok(path) = RepoPath::new(mark, text)
		{
			return Ok(Self {
				rendering: BoundedText::new(mark, text)?,
				raw: Some(raw_path),
				source: Some(path),
			});
		}
		let mut rendering = String::new();
		for &byte in raw {
			if (0x20..=0x7e).contains(&byte) {
				rendering.push(byte as char);
			} else {
				use std::fmt::Write;
				#[expect(
					clippy::expect_used,
					reason = "formatting one u8 into an owned String has no fallible writer or custom formatter"
				)]
				write!(&mut rendering, "%{byte:02X}").expect("writing a String");
			}
		}
		Ok(Self {
			rendering: BoundedText::new(mark, &rendering)?,
			raw: Some(raw_path),
			source: None,
		})
	}
}
impl<S: Source> Clone for InventoryPath<S> {
	fn clone(&self) -> Self {
		Self {
			rendering: self.rendering.clone(),
			raw: self.raw.clone(),
			source: self.source.clone(),
		}
	}
}
impl<S: Source> InventoryPath<S> {
	pub fn expose(&self) -> &str {
		self.rendering.expose()
	}
	pub fn representable(&self) -> bool {
		self.source.is_some()
	}
	/// Historical display strings never supply guessed raw bytes.
	pub fn raw_bytes(&self) -> Option<&[u8]> {
		self.raw.as_ref().map(|raw| raw.0.as_slice())
	}
	pub fn source_path(&self) -> Option<&RepoPath<S>> {
		self.source.as_ref()
	}
	pub(crate) fn stored(
		rendering: BoundedText<InventoryRendering, S>, raw: Option<RawPath<S>>,
		source: Option<RepoPath<S>>,
	) -> Self {
		Self { rendering, raw, source }
	}
}
impl<S: Source> std::fmt::Debug for InventoryPath<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"InventoryPath(len={}, representable={})",
			self.expose().len(),
			self.representable()
		)
	}
}
pub struct NewEntry<'a, PathS: Source, RevisionS: Source, ReasonS: Source> {
	pub path: &'a InventoryPath<PathS>,
	pub blob_sha: Option<&'a BoundedText<RevisionText, RevisionS>>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<Reason, ReasonS>>,
	pub highlighted: bool,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Entry {
	pub inventory_entry_id: i64,
	pub generation_id: i64,
	pub path: InventoryPath<Db>,
	pub blob_sha: Option<BoundedText<RevisionText, Db>>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<Reason, Db>>,
	pub highlighted: bool,
}
// debug-ok: insertion outcomes contain only row counters, never inventory paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
	/// Newly inserted raw identities, including distinct display aliases.
	pub inserted: usize,
	pub excluded: usize,
	/// Identical retries only. Distinct raw paths are never skipped.
	pub skipped: usize,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPaths(pub Vec<RepoPath<Agent>>);
impl std::fmt::Display for UnknownPaths {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} references are outside the pinned inventory", self.0.len())
	}
}
impl std::error::Error for UnknownPaths {}

/// None preserves legacy setup behavior; it never certifies preparation.
pub(crate) fn manifest_sealed(
	scope: &crate::scope::RepoScope<'_>, generation: i64,
) -> Result<Option<bool>> {
	manifest_sealed_raw(scope.conn, scope.repo_id, generation)
}
pub(crate) fn manifest_sealed_raw(
	conn: &Connection, repo: i64, generation: i64,
) -> Result<Option<bool>> {
	ownership::generation(conn, repo, generation, Ownership::InventoryGeneration)?;
	Ok(conn
		.query_row(
			"SELECT sealed_at IS NOT NULL FROM generation_manifests m
		 JOIN review_generations g ON g.generation_id=m.generation_id
		 WHERE m.generation_id=?1 AND g.repo_id=?2",
			params![generation, repo],
			|row| row.get(0),
		)
		.optional()?)
}

/// Legacy setup only. Managed generations require the host-owned upload path.
pub fn insert<PathS: Source, RevisionS: Source, ReasonS: Source>(
	scope: &crate::scope::RepoScope<'_>, generation: i64,
	entries: &[NewEntry<'_, PathS, RevisionS, ReasonS>], now: i64,
) -> Result<Inserted> {
	scope.require_operator()?;
	let tx = scope.conn;
	if manifest_sealed(scope, generation)?.is_some() {
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	if entries.len() > MAX_ENTRIES {
		return Err(Error::Conflict(Conflict::InventoryLimit));
	}
	let mut outcome = Inserted { inserted: 0, excluded: 0, skipped: 0 };
	let mut insert = tx.prepare("INSERT INTO generation_inventory
		(generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,created_at,raw_path,source_path)
		SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10
		WHERE EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?11)")?;
	// The complete accepted entry must agree; another display alias never
	// makes an upload a retry or changes the target of historical evidence.
	let mut identical = tx.prepare(
		"SELECT EXISTS(SELECT 1 FROM generation_inventory
		 WHERE generation_id=?1 AND raw_path=?2 AND blob_sha IS ?3 AND entry_kind=?4
		 AND disposition=?5 AND disposition_reason IS ?6 AND highlighted=?7
		 AND EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?8))",
	)?;
	for entry in entries {
		let raw = entry.path.raw_bytes().ok_or_else(|| {
			loupe_core::text::Error::new("raw_path", loupe_core::text::Rule::Path)
		})?;
		let excluded = !entry.path.representable();
		if !excluded && entry.reason.is_some_and(|r| r.expose() == "unrepresentable-path") {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Identifier,
			)
			.into());
		}
		let disposition = if excluded { Disposition::Excluded } else { entry.disposition };
		let reason = if excluded {
			Some("unrepresentable-path")
		} else {
			entry.reason.map(BoundedText::expose)
		};
		if disposition == Disposition::Excluded && reason.is_none() {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Empty,
			)
			.into());
		}
		let row = params![
			generation,
			entry.path.expose(),
			entry.blob_sha.map(BoundedText::expose),
			entry.kind.as_str(),
			disposition.as_str(),
			reason,
			entry.highlighted,
			now,
			raw,
			entry.path.source_path().map(RepoPath::expose),
			scope.repo_id
		];
		match insert.execute(row) {
			Ok(_) => {
				outcome.inserted += 1;
				outcome.excluded += usize::from(excluded);
			},
			Err(e)
				if is_unique(
					&e,
					"generation_inventory.generation_id, generation_inventory.raw_path",
				) || is_unique(
					&e,
					"generation_inventory.generation_id, generation_inventory.source_path",
				) =>
			{
				if identical.query_row(
					params![
						generation,
						raw,
						entry.blob_sha.map(BoundedText::expose),
						entry.kind.as_str(),
						disposition.as_str(),
						reason,
						entry.highlighted,
						scope.repo_id
					],
					|row| row.get::<_, bool>(0),
				)? {
					outcome.skipped += 1;
				} else {
					return Err(Error::Conflict(Conflict::InventoryPath));
				}
			},
			Err(e) => return Err(e.into()),
		}
	}
	Ok(outcome)
}
pub fn list(scope: &crate::scope::RepoScope<'_>, generation: i64) -> Result<Vec<Entry>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!(
			"SELECT {COLUMNS} FROM generation_inventory WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=generation_inventory.generation_id AND g.repo_id=?2) ORDER BY path,inventory_entry_id"
		))?
		.query_map(params![generation,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "inventory_entry_id,generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,raw_path,source_path";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
	let reason: Option<BoundedText<Reason, Db>> = crate::ingress::optional_reason(r, 6)?;
	let representable =
		reason.as_ref().is_none_or(|reason| reason.expose() != "unrepresentable-path");
	let path = crate::ingress::stored_inventory_path(r, 2, 8, 9, representable)?;
	Ok(Entry {
		inventory_entry_id: r.get(0)?,
		generation_id: r.get(1)?,
		path,
		blob_sha: crate::ingress::optional_revision(r, 3)?,
		kind: parsed(r, 4)?,
		disposition: parsed(r, 5)?,
		reason,
		highlighted: r.get(7)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "generation_inventory", COLUMNS, row)?;
	crate::migrations::admission::scan(
		conn,
		"generation_inventory",
		"created_at,manifest_position,git_mode,disposition_revision",
		|_| Ok::<_, rusqlite::Error>(()),
	)
}
pub fn verify_refs(
	scope: &crate::scope::RepoScope<'_>, generation: i64, refs: &[SourceRef<Agent>],
) -> Result<()> {
	verify_refs_raw(scope.conn, scope.repo_id, generation, refs)
}
pub(crate) fn verify_refs_raw(
	tx: &Connection, repo: i64, generation: i64, refs: &[SourceRef<Agent>],
) -> Result<()> {
	let managed = match manifest_sealed_raw(tx, repo, generation)? {
		Some(false) => return Err(Error::Conflict(Conflict::GenerationState)),
		Some(true) => true,
		None => false,
	};
	if !managed {
		let exists: bool = tx.query_row("SELECT inventory_digest IS NOT NULL OR EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1) FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![generation,repo],|r|r.get(0))?;
		if !exists {
			return Ok(());
		}
	}
	let mut unknown = Vec::new();
	let mut statement = tx.prepare("SELECT EXISTS(SELECT 1 FROM generation_inventory
		WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g
		 WHERE g.generation_id=generation_inventory.generation_id AND g.repo_id=?3)
		AND ((?4 AND source_path=?2 AND manifest_position IS NOT NULL)
		 OR (NOT ?4 AND path=?2 AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))))")?;
	for source in refs {
		if !statement.query_row(params![generation, source.path.expose(), repo, managed], |r| {
			r.get::<_, bool>(0)
		})? {
			unknown.push(source.path.clone());
		}
	}
	if unknown.is_empty() {
		Ok(())
	} else {
		Err(Error::UnknownPaths(UnknownPaths(unknown)))
	}
}
