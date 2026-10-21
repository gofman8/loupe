use loupe_core::inventory_manifest::{self, ManifestEntry, ManifestHasher};
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::policy::RevisionText;
use loupe_core::text::BoundedText;
use loupe_provenance::{Agent, Db, Worker};
use rusqlite::{params, Connection, OptionalExtension};

use super::{generation_state, PhaseScope};
use crate::host_preparation::{Manifest, PublishedProfile};
use crate::{inventory, Conflict, Error, Result};

fn invalid() -> Error {
	Error::Conflict(Conflict::InventoryPath)
}
fn limit() -> Error {
	Error::Conflict(Conflict::InventoryLimit)
}

fn get(conn: &Connection, generation: i64) -> Result<Option<Manifest>> {
	Ok(conn.query_row("SELECT owner_job_id,expected_entry_count,expected_digest,received_entry_count,received_canonical_bytes,sealed_at FROM generation_manifests WHERE generation_id=?1",[generation],|row| {
		let digest:Vec<u8>=row.get(2)?;
		Ok(Manifest {generation_id:generation,owner_job_id:row.get(0)?,expected_count:row.get(1)?,digest:digest.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?,digest_hex:crate::ingress::profile::digest(row,2)?,received_count:row.get(3)?,received_bytes:row.get(4)?,sealed_at:row.get(5)?})
	}).optional()?)
}

impl PhaseScope<'_, '_> {
	fn owned_manifest(&self) -> Result<Manifest> {
		let generation = self.bootstrap_generation()?;
		let manifest = get(self.transaction.conn, generation)?.ok_or_else(generation_state)?;
		if manifest.owner_job_id != Some(self.job.id) {
			return Err(generation_state());
		}
		Ok(manifest)
	}

	/// The immutable descriptor may change logical owner only after that owner
	/// is absent or terminal. Accepted membership and counters never reset.
	pub fn declare_manifest(&self, expected_count: u64, digest: &[u8; 32]) -> Result<Manifest> {
		let generation = self.bootstrap_generation()?;
		let conn = self.transaction.conn;
		if expected_count > inventory_manifest::MAX_ENTRIES {
			return Err(limit());
		}
		if let Some(existing) = get(conn, generation)? {
			if existing.expected_count != expected_count || existing.digest != *digest {
				return Err(invalid());
			}
			if existing.owner_job_id != Some(self.job.id) {
				let live:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND state IN ('queued','leased'))",[existing.owner_job_id],|row|row.get(0))?;
				if live {
					return Err(generation_state());
				}
				conn.execute(
					"UPDATE generation_manifests SET owner_job_id=?2 WHERE generation_id=?1",
					params![generation, self.job.id],
				)?;
			}
		} else {
			conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,expected_digest,created_at) VALUES(?1,1,?2,?3,?4,?5)",params![generation,self.job.id,expected_count,digest.as_slice(),self.transaction.now])?;
		}
		get(conn, generation)?.ok_or_else(generation_state)
	}

	/// Accept only a prefix extension or a wholly accepted, byte-identical retry.
	pub fn upload_manifest(
		&self, start: u64, entries: &[ManifestEntry<Worker>],
	) -> Result<Manifest> {
		let manifest = self.owned_manifest()?;
		let generation = manifest.generation_id;
		let conn = self.transaction.conn;
		let bytes = chunk_bytes(entries)?;
		let end = start.checked_add(entries.len() as u64).ok_or_else(limit)?;
		if end > manifest.expected_count {
			return Err(limit());
		}
		if start < manifest.received_count || manifest.sealed_at.is_some() {
			if end > manifest.received_count {
				return Err(invalid());
			}
			for (offset, entry) in entries.iter().enumerate() {
				let identical:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1 AND manifest_position=?2 AND raw_path=?3 AND git_mode=?4 AND blob_sha=?5)",params![generation,start+offset as u64,entry.raw_path(),entry.git_mode(),entry.object_id()],|row|row.get(0))?;
				if !identical {
					return Err(invalid());
				}
			}
			return Ok(manifest);
		}
		if start != manifest.received_count {
			return Err(invalid());
		}
		let total_bytes = manifest
			.received_bytes
			.checked_add(bytes)
			.filter(|bytes| *bytes <= inventory_manifest::MAX_BYTES)
			.ok_or_else(limit)?;
		if let Some(first) = entries.first() {
			let previous=conn.query_row("SELECT raw_path,git_mode,blob_sha FROM generation_inventory WHERE generation_id=?1 AND manifest_position IS NOT NULL ORDER BY manifest_position DESC LIMIT 1",[generation],|row|crate::ingress::host_preparation::manifest_entry(row,0,1,2)).optional()?;
			if previous.is_some_and(|previous| previous.raw_path() >= first.raw_path()) {
				return Err(invalid());
			}
		}
		for (offset, entry) in entries.iter().enumerate() {
			insert_entry(conn, generation, start + offset as u64, entry, self.transaction.now)?;
		}
		conn.execute("UPDATE generation_manifests SET received_entry_count=?2,received_canonical_bytes=?3 WHERE generation_id=?1",params![generation,end,total_bytes])?;
		get(conn, generation)?.ok_or_else(generation_state)
	}

	/// Stream all original stored members before certifying completeness.
	pub fn seal_manifest(&self) -> Result<Manifest> {
		let manifest = self.owned_manifest()?;
		let generation = manifest.generation_id;
		let conn = self.transaction.conn;
		if manifest.sealed_at.is_some() {
			return Ok(manifest);
		}
		if manifest.received_count != manifest.expected_count {
			return Err(invalid());
		}
		let orphaned:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1 AND source_path IS NOT NULL AND manifest_position IS NULL)",[generation],|row|row.get(0))?;
		if orphaned {
			return Err(invalid());
		}
		let commit=conn.query_row("SELECT generation_commit_sha FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![generation,self.job.repo_id],|row|crate::ingress::profile::commit(row,0))?;
		let mut hasher =
			ManifestHasher::new(commit.expose(), manifest.expected_count).map_err(|_| invalid())?;
		let mut statement=conn.prepare("SELECT manifest_position,raw_path,git_mode,blob_sha FROM generation_inventory WHERE generation_id=?1 AND manifest_position IS NOT NULL ORDER BY manifest_position")?;
		let mut rows = statement.query([generation])?;
		let mut position = 0u64;
		while let Some(row) = rows.next()? {
			if row.get::<_, u64>(0)? != position {
				return Err(invalid());
			}
			hasher
				.push(&crate::ingress::host_preparation::manifest_entry(row, 1, 2, 3)?)
				.map_err(|_| invalid())?;
			position += 1;
		}
		if hasher.bytes() != manifest.received_bytes
			|| hasher.finish().map_err(|_| invalid())? != manifest.digest
		{
			return Err(invalid());
		}
		conn.execute("UPDATE generation_manifests SET sealed_at=?2 WHERE generation_id=?1 AND sealed_at IS NULL",params![generation,self.transaction.now])?;
		conn.execute("UPDATE review_generations SET inventory_digest=?2 WHERE generation_id=?1 AND repo_id=?3",params![generation,manifest.digest.as_slice(),self.job.repo_id])?;
		get(conn, generation)?.ok_or_else(generation_state)
	}

	/// Fixed logical-job checkpoint. Retries may replay, never rewrite or bump
	/// a frozen profile. Agent designation is explicit at the durable write.
	pub fn publish_profile(&self, profile: &GeneratedProfile<Agent>) -> Result<PublishedProfile> {
		let manifest = self.owned_manifest()?;
		if manifest.sealed_at.is_none() {
			return Err(generation_state());
		}
		let conn = self.transaction.conn;
		let digest = *profile.digest();
		let prior=conn.query_row("SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key='publish_profile:bootstrap'",[self.job.id],|row|Ok((crate::ingress::operation(row,0)?,row.get::<_,Vec<u8>>(1)?,crate::ingress::db_payload(row,2)?))).optional()?;
		if let Some((operation, prior_digest, _)) = prior {
			if operation.expose() != "publish_profile" || prior_digest != digest {
				return Err(Error::Conflict(Conflict::Checkpoint));
			}
		} else {
			let changed=conn.execute("UPDATE review_generations SET profile_version=1,generated_profile=?2,generated_profile_digest=?3,generated_profile_source='agent' WHERE generation_id=?1 AND repo_id=?4 AND state='building' AND generated_profile IS NULL AND profile_version=1",params![manifest.generation_id,profile.expose(),digest.as_slice(),self.job.repo_id])?;
			if changed != 1 {
				return Err(generation_state());
			}
			conn.execute("INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(?1,'publish_profile:bootstrap','publish_profile',?2,'{\"profile_version\":1}',?3)",params![self.job.id,digest.as_slice(),self.transaction.now])?;
		}
		let published=conn.query_row("SELECT profile_version,generated_profile,generated_profile_digest,generated_profile_source FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![manifest.generation_id,self.job.repo_id],|row| {
			let profile=crate::ingress::profile::frozen_profile(row,0,1,2,3)?.ok_or(rusqlite::Error::InvalidQuery)?;
			let digest:Vec<u8>=row.get(2)?;
			Ok(PublishedProfile { version:i64::from(profile.version.get()),digest:digest.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?,digest_hex:profile.digest })
		})?;
		if published.version != 1 || published.digest != digest {
			return Err(Error::Conflict(Conflict::Checkpoint));
		}
		Ok(published)
	}
}

fn chunk_bytes(entries: &[ManifestEntry<Worker>]) -> Result<u64> {
	if entries.len() > inventory_manifest::MAX_CHUNK_ENTRIES {
		return Err(limit());
	}
	let mut bytes = 0u64;
	for (index, entry) in entries.iter().enumerate() {
		bytes =
			bytes.checked_add(entry.canonical_len().map_err(|_| invalid())?).ok_or_else(limit)?;
		if index > 0 && entries[index - 1].raw_path() >= entry.raw_path() {
			return Err(invalid());
		}
	}
	if bytes > inventory_manifest::MAX_CHUNK_BYTES {
		return Err(limit());
	}
	Ok(bytes)
}

struct ExistingEntry {
	id: i64,
	path: inventory::InventoryPath<Db>,
	oid: Option<BoundedText<RevisionText, Db>>,
	kind: inventory::EntryKind,
	position: Option<u64>,
}
fn insert_entry(
	conn: &Connection, generation: i64, position: u64, entry: &ManifestEntry<Worker>, now: i64,
) -> Result<()> {
	let source = entry.source_path();
	let kind = if inventory_manifest::is_submodule_mode(entry.git_mode()).map_err(|_| invalid())? {
		inventory::EntryKind::Submodule
	} else {
		inventory::EntryKind::Tracked
	};
	let existing=conn.query_row("SELECT inventory_entry_id,path,raw_path,source_path,blob_sha,entry_kind,manifest_position,disposition_reason IS NOT 'unrepresentable-path' FROM generation_inventory WHERE generation_id=?1 AND (raw_path=?2 OR (?3 IS NOT NULL AND source_path=?3))",params![generation,entry.raw_path(),source],|row|Ok(ExistingEntry {
		id:row.get(0)?,path:crate::ingress::stored_inventory_path(row,1,2,3,row.get(7)?)?,oid:crate::ingress::optional_revision(row,4)?,kind:crate::review::parsed(row,5)?,position:row.get(6)?
	})).optional()?;
	if let Some(existing) = existing {
		if existing.path.raw_bytes().is_some_and(|raw| raw != entry.raw_path())
			|| existing.oid.as_ref().is_some_and(|oid| oid.expose() != entry.object_id())
			|| existing.kind != kind
			|| existing.position.is_some()
		{
			return Err(invalid());
		}
		conn.execute("UPDATE generation_inventory SET raw_path=?2,blob_sha=?3,git_mode=?4,manifest_position=?5 WHERE inventory_entry_id=?1 AND generation_id=?6",params![existing.id,entry.raw_path(),entry.object_id(),entry.git_mode(),position,generation])?;
	} else {
		let excluded = source.is_none();
		conn.execute("INSERT INTO generation_inventory(generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,created_at,raw_path,source_path,manifest_position,git_mode) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![generation,entry.display_path().as_ref(),entry.object_id(),kind.as_str(),if excluded {"excluded"}else{"unresolved"},if excluded {Some("unrepresentable-path")}else{None},now,entry.raw_path(),source,position,entry.git_mode()])?;
	}
	Ok(())
}
