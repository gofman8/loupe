//! Immutable observations attached to a lead's stable identity.
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::policy::{Payload, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection};

use crate::{leads, ownership, Conflict, Entity, Error, Ownership, Result, StoredEvidence};
pub struct NewObservation<'a, RevisionS: Source> {
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: &'a BoundedJson<Payload, Agent>,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Observation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: BoundedJson<Payload, Agent>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub created_at: i64,
}

pub struct NewObservationEvidence<'a, RevisionS: Source> {
	pub lead_id: i64,
	pub submitted_by_job: i64,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub payload: &'a LeadEvidenceV1<Agent>,
}
// debug-ok: evidence and revision owners redact content; other fields are numeric.
#[derive(Debug, Clone)]
pub struct EvidenceObservation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: StoredEvidence<LeadEvidenceV1<Agent>>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub created_at: i64,
}
pub fn insert<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewObservation<'_, RevisionS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	crate::review::require_historical_payload(new.payload.expose())?;
	insert_raw(
		scope.conn,
		scope.repo_id,
		&ObservationInput {
			lead_id: new.lead_id,
			submitted_by_job: new.submitted_by_job,
			payload: new.payload.expose(),
			digest: new.payload.digest(),
			commit_sha: new.commit_sha.expose(),
		},
		now,
	)
}
pub fn insert_evidence<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewObservationEvidence<'_, RevisionS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let bytes = new.payload.canonical_bytes()?;
	let lead = leads::get_metadata(scope, new.lead_id)?
		.ok_or(Error::NotFound(Entity::Lead, new.lead_id))?;
	if lead.identity != leads::evidence_identity(new.payload) {
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	leads::validate_evidence_scope(scope, lead.generation_id, new.payload)?;
	insert_raw(
		scope.conn,
		scope.repo_id,
		&ObservationInput {
			lead_id: new.lead_id,
			submitted_by_job: Some(new.submitted_by_job),
			payload: std::str::from_utf8(&bytes)
				.map_err(|_| Error::Conflict(Conflict::CheckpointEvidence))?,
			digest: &crate::canonical::digest(&bytes),
			commit_sha: new.commit_sha.expose(),
		},
		now,
	)
}
pub(crate) struct ObservationInput<'a> {
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: &'a str,
	pub digest: &'a [u8; 32],
	pub commit_sha: &'a str,
}
pub(crate) fn insert_raw(
	tx: &Connection, repo: i64, new: &ObservationInput<'_>, now: i64,
) -> Result<i64> {
	let ObservationInput { lead_id, submitted_by_job, payload, digest, commit_sha } = *new;
	let lead = leads::get_metadata_raw(tx, repo, lead_id)?
		.ok_or(Error::NotFound(Entity::Lead, lead_id))?;
	if let Some(job) = submitted_by_job {
		ownership::job_for_generation(tx, job, lead.generation_id, Ownership::ObservationJob)?;
	}
	tx.execute("INSERT INTO lead_observations (lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at,source) SELECT ?1,?2,?3,?4,?5,?6,'agent' WHERE EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1 AND g.repo_id=?7)",params![lead_id,submitted_by_job,payload,digest.as_slice(),commit_sha,now,repo])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(scope: &crate::scope::RepoScope<'_>, lead: i64) -> Result<Vec<Observation>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!(
			"SELECT {COLUMNS} FROM lead_observations WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=lead_observations.lead_id AND g.repo_id=?2) ORDER BY lead_observation_id"
		))?
		.query_map(params![lead,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "lead_observation_id,lead_id,submitted_by_job_id,observation_payload,commit_sha,created_at,source,observation_digest,(SELECT identity_family FROM leads l WHERE l.lead_id=lead_observations.lead_id),(SELECT identity_anchor FROM leads l WHERE l.lead_id=lead_observations.lead_id),(SELECT identity_instance_key FROM leads l WHERE l.lead_id=lead_observations.lead_id),(SELECT source FROM leads l WHERE l.lead_id=lead_observations.lead_id)";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Observation> {
	crate::ingress::require_agent_source(r, 6)?;
	Ok(Observation {
		observation_id: r.get(0)?,
		lead_id: r.get(1)?,
		submitted_by_job: r.get(2)?,
		payload: crate::ingress::checkpoint::historical_payload(r, 3)?,
		commit_sha: crate::ingress::revision(r, 4)?,
		created_at: r.get(5)?,
	})
}

fn evidence_row(r: &rusqlite::Row<'_>) -> Result<EvidenceObservation> {
	crate::ingress::require_agent_source(r, 6)?;
	let payload = crate::ingress::checkpoint::lead(r, 3, 7)?;
	if let StoredEvidence::Recorded(value) = &payload {
		crate::ingress::require_agent_source(r, 11)?;
		let identity = crate::identity::Identity {
			family: crate::ingress::family(r, 8)?,
			anchor: crate::ingress::anchor(r, 9)?,
			instance: crate::ingress::optional_instance(r, 10)?,
		};
		if identity != leads::evidence_identity(value) {
			return Err(Error::Conflict(Conflict::CheckpointEvidence));
		}
	}
	Ok(EvidenceObservation {
		observation_id: r.get(0)?,
		lead_id: r.get(1)?,
		submitted_by_job: r.get(2)?,
		payload,
		commit_sha: crate::ingress::revision(r, 4)?,
		created_at: r.get(5)?,
	})
}
pub fn list_evidence(
	scope: &crate::scope::RepoScope<'_>, lead: i64,
) -> Result<Vec<EvidenceObservation>> {
	let mut statement=scope.conn.prepare(&format!("SELECT {COLUMNS} FROM lead_observations WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=lead_observations.lead_id AND g.repo_id=?2) ORDER BY lead_observation_id"))?;
	let mut rows = statement.query(params![lead, scope.repo_id])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(evidence_row(row)?);
	}
	Ok(result)
}
/// Fresh attachment lookup is bounded to the exact repository and producer.
pub(crate) fn latest_evidence_for_job(
	conn: &Connection, repo: i64, lead: i64, job: i64,
) -> Result<Option<EvidenceObservation>> {
	let mut statement = conn.prepare(&format!(
		"SELECT {COLUMNS} FROM lead_observations
 WHERE lead_id=?1 AND submitted_by_job_id=?2 AND EXISTS(SELECT 1 FROM leads l
 JOIN review_generations g ON g.generation_id=l.generation_id
 WHERE l.lead_id=lead_observations.lead_id AND g.repo_id=?3)
 ORDER BY lead_observation_id DESC LIMIT 1"
	))?;
	let mut rows = statement.query(params![lead, job, repo])?;
	rows.next()?.map(evidence_row).transpose()
}

/// An accepted receipt precedes even JSON association inspection. Corrupt
/// accepted evidence remains an integrity error, never an apparently missing row.
pub(crate) fn accepted_evidence_for_unit(
	conn: &Connection, repo: i64, lead: i64, job: i64, generation: i64, unit: i64, epoch: i64,
) -> Result<Option<EvidenceObservation>> {
	let mut statement=conn.prepare(&format!("SELECT {COLUMNS} FROM lead_observations
 WHERE lead_id=?1 AND submitted_by_job_id=?2
 AND EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id
 WHERE l.lead_id=lead_observations.lead_id AND l.generation_id=?3 AND g.repo_id=?6)
 AND CASE WHEN EXISTS(SELECT 1 FROM job_checkpoints c JOIN jobs j ON j.id=c.job_id
 WHERE c.job_id=?2 AND j.repo_id=?6 AND c.operation='submit_lead'
 AND json_extract(c.response,'$.lead_id')=?1
 AND json_extract(c.response,'$.observation_id')=lead_observations.lead_observation_id)
 THEN CASE WHEN json_valid(observation_payload) THEN
 json_extract(observation_payload,'$.review_unit_id')=?4 AND json_extract(observation_payload,'$.assignment_epoch')=?5
 ELSE 1 END ELSE 0 END
 ORDER BY lead_observation_id DESC LIMIT 1"))?;
	let mut rows = statement.query(params![lead, job, generation, unit, epoch, repo])?;
	rows.next()?.map(evidence_row).transpose()
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "lead_observations", COLUMNS, |r| {
		crate::ingress::require_agent_source(r, 6)?;
		if crate::ingress::checkpoint::is_modern(r, 3)? {
			evidence_row(r).map_err(|_| crate::review::invalid_scalar(3))?;
		} else {
			row(r)?;
		}
		Ok::<_, rusqlite::Error>(())
	})
}
