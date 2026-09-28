//! Append-only unit evidence and explicit invalidation.
pub use loupe_core::review_payload::UnitResultDisposition as Disposition;
use loupe_core::review_payload::UnitResultPayloadV1;
use loupe_core::text::policy::{Argument, Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection};

use crate::review::{changed, parsed};
use crate::source_refs::InspectedRefs;
use crate::{inventory, ownership, Conflict, Error, Ownership, Result, StoredEvidence};
impl crate::review::ClosedSqlEnum for Disposition {}
pub struct NewResult<'a, RevisionS: Source> {
	pub generation_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: &'a InspectedRefs<Agent>,
	pub counterevidence: Option<&'a BoundedText<Argument, Agent>>,
	pub proof_gaps: Option<&'a BoundedText<Argument, Agent>>,
	pub payload: &'a BoundedJson<Payload, Agent>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct UnitResult {
	pub result_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: InspectedRefs<Agent>,
	pub counterevidence: Option<BoundedText<Argument, Agent>>,
	pub proof_gaps: Option<BoundedText<Argument, Agent>>,
	pub payload: BoundedJson<Payload, Agent>,
	pub invalidated: bool,
	pub invalidated_reason: Option<BoundedText<Reason, Db>>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
	pub created_at: i64,
}
pub fn insert<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewResult<'_, RevisionS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	crate::review::require_historical_payload(new.payload.expose())?;
	let tx = scope.conn;
	ownership::generation(tx, scope.repo_id, new.generation_id, Ownership::ResultUnit)?;
	ownership::unit_in_generation(tx, new.unit_id, new.generation_id, Ownership::ResultUnit)?;
	if let Some(job) = new.produced_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::ResultJob)?;
	}
	if new.corroborates_result.is_some() && new.corroborates_exclusion.is_some() {
		return Err(Error::Conflict(Conflict::Corroboration));
	}
	if let Some(id) = new.corroborates_result {
		let scope =
			ownership::generation_scope(tx, new.generation_id, Ownership::CorroboratedResult)?;
		ownership::require(tx,"SELECT g.repo_id,u.generation_id FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id JOIN review_generations g ON g.generation_id=u.generation_id WHERE r.review_unit_result_id=?1 AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL",[id],scope,Ownership::CorroboratedResult,ownership::generation_row)?;
	}
	if let Some(id) = new.corroborates_exclusion {
		let scope =
			ownership::generation_scope(tx, new.generation_id, Ownership::CorroboratedExclusion)?;
		ownership::require(tx,"SELECT g.repo_id,i.generation_id FROM generation_inventory i JOIN review_generations g ON g.generation_id=i.generation_id WHERE i.inventory_entry_id=?1 AND i.disposition='excluded'",[id],scope,Ownership::CorroboratedExclusion,ownership::generation_row)?;
	}
	inventory::verify_refs(scope, new.generation_id, new.inspected_refs.as_slice())?;
	tx.execute("INSERT INTO review_unit_results (review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,result_digest,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'agent' WHERE EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND g.repo_id=?14)",params![new.unit_id,new.produced_by_job,new.commit_sha.expose(),new.profile_version,new.disposition.as_str(),new.inspected_refs.expose(),new.counterevidence.map(BoundedText::expose),new.proof_gaps.map(BoundedText::expose),new.payload.expose(),new.payload.digest().as_slice(),new.corroborates_result,new.corroborates_exclusion,now,scope.repo_id])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(scope: &crate::scope::RepoScope<'_>, unit: i64) -> Result<Vec<UnitResult>> {
	let tx = scope.conn;
	Ok(tx.prepare(&format!("SELECT {COLUMNS} FROM review_unit_results WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=review_unit_results.review_unit_id AND g.repo_id=?2) ORDER BY review_unit_result_id"))?.query_map(params![unit,scope.repo_id],row)?.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,invalidated,invalidated_reason,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at,source,result_digest";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UnitResult> {
	crate::ingress::require_agent_source(r, 15)?;
	Ok(UnitResult {
		result_id: r.get(0)?,
		unit_id: r.get(1)?,
		produced_by_job: r.get(2)?,
		commit_sha: crate::ingress::revision(r, 3)?,
		profile_version: r.get(4)?,
		disposition: parsed(r, 5)?,
		inspected_refs: crate::ingress::inspected_refs(r, 6)?,
		counterevidence: crate::ingress::optional_argument(r, 7)?,
		proof_gaps: crate::ingress::optional_argument(r, 8)?,
		payload: crate::ingress::checkpoint::historical_payload(r, 9)?,
		invalidated: r.get(10)?,
		invalidated_reason: crate::ingress::optional_reason(r, 11)?,
		corroborates_result: r.get(12)?,
		corroborates_exclusion: r.get(13)?,
		created_at: r.get(14)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "review_unit_results", COLUMNS, |r| {
		crate::ingress::require_agent_source(r, 15)?;
		if crate::ingress::checkpoint::is_modern(r, 9)? {
			evidence_row(r).map_err(|_| crate::review::invalid_scalar(9))?;
		} else {
			row(r)?;
		}
		Ok::<_, rusqlite::Error>(())
	})
}
pub fn invalidate<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_unit_results SET invalidated=1,invalidated_reason=?2 WHERE review_unit_result_id=?1 AND EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=review_unit_results.review_unit_id AND g.repo_id=?3) AND invalidated=0",params![id,reason.expose(),scope.repo_id])?,Conflict::Corroboration)
}

pub struct NewResultEvidence<'a, RevisionS: Source> {
	pub generation_id: i64,
	pub produced_by_job: i64,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub profile_version: i64,
	pub payload: &'a UnitResultPayloadV1<Agent>,
}
// debug-ok: typed evidence and text redact content; other fields are scalar metadata.
#[derive(Debug, Clone)]
pub struct EvidenceResult {
	pub result_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub profile_version: i64,
	pub payload: StoredEvidence<UnitResultPayloadV1<Agent>>,
	pub invalidated: bool,
	pub invalidated_reason: Option<BoundedText<Reason, Db>>,
	pub created_at: i64,
}
pub fn insert_evidence<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewResultEvidence<'_, RevisionS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	insert_evidence_raw(scope.conn, scope.repo_id, new, now)
}
pub(crate) fn insert_evidence_raw<RevisionS: Source>(
	tx: &Connection, repo: i64, new: &NewResultEvidence<'_, RevisionS>, now: i64,
) -> Result<i64> {
	let bytes = new.payload.canonical_bytes()?;
	let payload = new.payload;
	ownership::generation(tx, repo, new.generation_id, Ownership::ResultUnit)?;
	ownership::unit_in_generation(
		tx,
		payload.review_unit_id,
		new.generation_id,
		Ownership::ResultUnit,
	)?;
	ownership::job_for_generation(
		tx,
		new.produced_by_job,
		new.generation_id,
		Ownership::ResultJob,
	)?;
	for lead in &payload.created_lead_ids {
		ownership::lead_in_generation(tx, *lead, new.generation_id, Ownership::LeadUnit)?;
	}
	inventory::verify_refs_raw(tx, repo, new.generation_id, &payload.inspected_refs)?;
	let refs = crate::review::checkpoint_refs(&payload.inspected_refs)?;
	let raw =
		std::str::from_utf8(&bytes).map_err(|_| Error::Conflict(Conflict::CheckpointEvidence))?;
	tx.execute("INSERT INTO review_unit_results(review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at,source) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,'agent' WHERE EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND g.repo_id=?10)",params![payload.review_unit_id,new.produced_by_job,new.commit_sha.expose(),new.profile_version,payload.disposition.as_str(),refs,raw,crate::canonical::digest(&bytes).as_slice(),now,repo])?;
	Ok(tx.last_insert_rowid())
}
fn evidence_row(r: &rusqlite::Row<'_>) -> Result<EvidenceResult> {
	crate::ingress::require_agent_source(r, 15)?;
	let payload = crate::ingress::checkpoint::unit_result(r, 9, 16)?;
	let unit_id = r.get(1)?;
	if let StoredEvidence::Recorded(value) = &payload
		&& (value.review_unit_id != unit_id
			|| r.get::<_, String>(5)? != value.disposition.as_str()
			|| r.get::<_, String>(6)? != crate::review::checkpoint_refs(&value.inspected_refs)?
			|| [7, 8, 12, 13]
				.into_iter()
				.any(|i| !matches!(r.get_ref(i), Ok(rusqlite::types::ValueRef::Null))))
	{
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(EvidenceResult {
		result_id: r.get(0)?,
		unit_id,
		produced_by_job: r.get(2)?,
		commit_sha: crate::ingress::revision(r, 3)?,
		profile_version: r.get(4)?,
		payload,
		invalidated: r.get(10)?,
		invalidated_reason: crate::ingress::optional_reason(r, 11)?,
		created_at: r.get(14)?,
	})
}
pub fn get_evidence(
	scope: &crate::scope::RepoScope<'_>, id: i64,
) -> Result<StoredEvidence<UnitResultPayloadV1<Agent>>> {
	get_evidence_raw(scope.conn, scope.repo_id, id)
}
pub(crate) fn get_evidence_raw(
	conn: &Connection, repo: i64, id: i64,
) -> Result<StoredEvidence<UnitResultPayloadV1<Agent>>> {
	let mut statement=conn.prepare(&format!("SELECT {COLUMNS} FROM review_unit_results WHERE review_unit_result_id=?1 AND EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=review_unit_results.review_unit_id AND g.repo_id=?2)"))?;
	let mut rows = statement.query(params![id, repo])?;
	match rows.next()? {
		Some(row) => Ok(evidence_row(row)?.payload),
		None => Ok(StoredEvidence::Missing),
	}
}
pub fn list_evidence(
	scope: &crate::scope::RepoScope<'_>, unit: i64,
) -> Result<Vec<EvidenceResult>> {
	let mut statement=scope.conn.prepare(&format!("SELECT {COLUMNS} FROM review_unit_results WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=review_unit_results.review_unit_id AND g.repo_id=?2) ORDER BY review_unit_result_id"))?;
	let mut rows = statement.query(params![unit, scope.repo_id])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(evidence_row(row)?);
	}
	Ok(result)
}
