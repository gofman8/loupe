//! Entry-local CAS and numeric receipts, called by the purpose-bound phase
//! facade inside its storage-owned IMMEDIATE transaction.
use loupe_core::text::policy::{ClientKey, InventoryReason};
use loupe_core::text::{BoundedText, Identifier, RepoPath};
use loupe_provenance::Worker;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::inventory::Disposition;
use crate::review::changed;
use crate::{Conflict, Error, Result};

pub const MAX_OPERATIONS: i64 = 4096;
pub const MAX_MAPPINGS: usize = 8;

pub(crate) struct Entry {
	id: i64,
	generation: i64,
	path: RepoPath<Worker>,
	revision: i64,
}
impl Entry {
	pub(crate) fn id(&self) -> i64 {
		self.id
	}
	pub(crate) fn revision(&self) -> i64 {
		self.revision
	}
}
// debug-ok: numeric unit identifiers and epochs only.
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
	pub unit_id: i64,
	pub assignment_epoch: i64,
}
pub(crate) struct Update<'a> {
	pub expected_revision: i64,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<InventoryReason, Worker>>,
	pub mappings: &'a [Mapping],
}

/// Resolve source identity and job scope together, before returning revision.
/// Bootstrap/ordinary classification is derived by the server's authority.
/// Completed assignments still describe source scope; fresh mapped-unit write
/// authority is checked separately by the caller after replay and CAS lookup.
pub(crate) fn resolve(
	tx: &Connection, repo: i64, job: i64, generation: i64, bootstrap: bool, path: &RepoPath<Worker>,
) -> Result<Option<Entry>> {
	Ok(tx.query_row("SELECT i.inventory_entry_id,i.disposition_revision FROM generation_inventory i JOIN generation_manifests m ON m.generation_id=i.generation_id JOIN jobs j ON j.id=?1 AND j.generation_id=i.generation_id WHERE j.repo_id=?5 AND i.generation_id=?2 AND i.source_path=?3 AND i.raw_path=CAST(?3 AS BLOB) AND i.manifest_position IS NOT NULL AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count AND (?4 OR EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN review_units u ON u.review_unit_id=a.review_unit_id WHERE a.job_id=j.id AND u.generation_id=i.generation_id AND a.assignment_epoch=u.assignment_epoch AND EXISTS(SELECT 1 FROM json_each(u.source_refs) r WHERE json_extract(r.value,'$.path')=?3)))",params![job,generation,path.expose(),bootstrap,repo],|r|Ok(Entry{id:r.get(0)?,generation,path:path.clone(),revision:r.get(1)?})).optional()?)
}

/// Replace all mappings and advance exactly this entry's revision. Input unit
/// ownership must already pass the transaction-bound survey authority check;
/// these relational checks additionally bind every unit to this exact path.
pub(crate) fn replace(tx: &Connection, entry: &Entry, update: &Update<'_>) -> Result<i64> {
	if update.expected_revision < 0 || update.expected_revision != entry.revision {
		return Err(Error::Conflict(Conflict::InventoryPath));
	}
	let revision =
		entry.revision.checked_add(1).ok_or(Error::Conflict(Conflict::InventoryLimit))?;
	if update.mappings.len() > MAX_MAPPINGS
		|| (update.disposition == Disposition::Mapped) == update.mappings.is_empty()
		|| (matches!(update.disposition, Disposition::Context | Disposition::Excluded)
			&& update.reason.is_none())
		|| update
			.reason
			.is_some_and(|r| r.expose().chars().count() > 500 || r.expose().len() > 1000)
	{
		return Err(Error::Conflict(Conflict::InventoryPath));
	}
	let mut seen = std::collections::HashSet::new();
	for mapping in update.mappings {
		if mapping.unit_id <= 0 || mapping.assignment_epoch < 0 || !seen.insert(mapping.unit_id) {
			return Err(Error::Conflict(Conflict::Assignment));
		}
		let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND u.assignment_epoch=?3 AND EXISTS(SELECT 1 FROM json_each(u.source_refs) r WHERE json_extract(r.value,'$.path')=?4))",params![mapping.unit_id,entry.generation,mapping.assignment_epoch,entry.path.expose()],|r|r.get(0))?;
		if !valid {
			return Err(Error::Conflict(Conflict::Assignment));
		}
	}
	changed(tx.execute("UPDATE generation_inventory SET disposition=?3,disposition_reason=?4,disposition_revision=?5 WHERE inventory_entry_id=?1 AND generation_id=?2 AND disposition_revision=?6",params![entry.id,entry.generation,update.disposition.as_str(),update.reason.map(BoundedText::expose),revision,update.expected_revision])?,Conflict::InventoryPath)?;
	tx.execute("DELETE FROM generation_inventory_units WHERE inventory_entry_id=?1", [entry.id])?;
	for mapping in update.mappings {
		tx.execute("INSERT INTO generation_inventory_units(generation_id,inventory_entry_id,review_unit_id) VALUES(?1,?2,?3)",params![entry.generation,entry.id,mapping.unit_id])?;
	}
	Ok(revision)
}

/// Borrowed Worker fields retain their original owners. The issuing phase
/// supplies repository/job/generation authority, never this request.
pub struct Submission<'a> {
	pub key: &'a Identifier<ClientKey, Worker>,
	pub path: &'a RepoPath<Worker>,
	pub digest: &'a [u8; 32],
	pub expected_revision: i64,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<InventoryReason, Worker>>,
	pub mappings: &'a [Mapping],
}
// debug-ok: receipt fields are positive numeric identities/revisions only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
	pub inventory_entry_id: i64,
	pub revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
	protocol_version: u16,
	inventory_entry_id: i64,
	revision: u64,
}
impl StoredReceipt {
	fn from_receipt(receipt: Receipt) -> Self {
		Self {
			protocol_version: 3,
			inventory_entry_id: receipt.inventory_entry_id,
			revision: receipt.revision,
		}
	}
	fn receipt(self) -> Result<Receipt> {
		if self.protocol_version != 3
			|| self.inventory_entry_id <= 0
			|| self.revision == 0
			|| self.revision > i64::MAX as u64
		{
			return Err(Error::Conflict(Conflict::Checkpoint));
		}
		Ok(Receipt { inventory_entry_id: self.inventory_entry_id, revision: self.revision })
	}
}
pub(crate) fn replay(
	conn: &Connection, repo: i64, job: i64, request: &Submission<'_>,
) -> Result<Option<Receipt>> {
	use crate::checkpoints::{self, Operation, Replay, Stored};
	let qualified =
		format!("{}:{}", Operation::SubmitInventoryDisposition.as_str(), request.key.expose());
	conn.query_row(
  "SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key=?2 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3)",
  params![job,qualified,repo], |row| {
   let stored=Stored { operation:row.get_ref(0)?.as_str()?,digest:row.get_ref(1)?.as_blob()? };
   if checkpoints::replay_decision(Some(&stored),Operation::SubmitInventoryDisposition,request.digest) != Replay::Hit {
    return Ok(Err(Error::Conflict(Conflict::Checkpoint)));
   }
   // This fixed response contains closed scalars only, no content-source carry.
   let raw=row.get_ref(2)?.as_str()?;
   if raw.len()>1024 { return Ok(Err(Error::Conflict(Conflict::Checkpoint))); }
   Ok(serde_json::from_str::<StoredReceipt>(raw)
    .map_err(|_| Error::Conflict(Conflict::Checkpoint)).and_then(StoredReceipt::receipt))
  }).optional()?.transpose()
}
pub(crate) fn record(
	conn: &Connection, repo: i64, job: i64, request: &Submission<'_>, receipt: Receipt, now: i64,
) -> Result<()> {
	let op = crate::checkpoints::Operation::SubmitInventoryDisposition;
	let qualified = format!("{}:{}", op.as_str(), request.key.expose());
	let response = serde_json::to_string(&StoredReceipt::from_receipt(receipt))
		.map_err(|_| Error::Conflict(Conflict::Checkpoint))?;
	changed(conn.execute("INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?7)",
  params![job,qualified,op.as_str(),request.digest.as_slice(),response,now,repo])?,Conflict::Checkpoint)
}

#[cfg(test)]
mod tests;
