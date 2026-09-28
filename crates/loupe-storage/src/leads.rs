//! Semantic identity attachment never discards a submitted observation.
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::policy::{Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::identity::Identity;
use crate::review::{changed, is_unique, optional, parsed, string_enum};
use crate::review_units::Priority;
use crate::{
	inventory, lead_observations, ownership, Conflict, Entity, Error, Ownership, Result,
	StoredEvidence,
};
string_enum!(Status { Open=>"open", Deferred=>"deferred", Closed=>"closed" });
string_enum!(Disposition { Promoted=>"promoted", Rejected=>"rejected", Duplicate=>"duplicate", Hardening=>"hardening", Stale=>"stale" });
pub struct NewLead<'a, RevisionS: Source> {
	pub generation_id: i64,
	pub unit_id: Option<i64>,
	pub identity: &'a Identity<Agent>,
	pub payload: &'a BoundedJson<Payload, Agent>,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub priority: Priority,
	pub priority_proposal: Option<&'a BoundedJson<Payload, Agent>>,
	pub supersedes: Option<i64>,
	pub created_by_job: Option<i64>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Lead {
	pub lead_id: i64,
	pub generation_id: i64,
	pub unit_id: Option<i64>,
	pub status: Status,
	pub disposition: Option<Disposition>,
	pub defer_reason: Option<BoundedText<Reason, Db>>,
	pub retry_condition: Option<BoundedText<Reason, Db>>,
	pub priority: Priority,
	pub priority_proposal: Option<BoundedJson<Payload, Agent>>,
	pub identity: Identity<Agent>,
	pub payload: BoundedJson<Payload, Agent>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub needs_revalidation: bool,
	pub carry_depth: i64,
	pub supersedes: Option<i64>,
	pub duplicate_lead: Option<i64>,
	pub duplicate_finding: Option<i64>,
	pub promoted_finding: Option<i64>,
	pub created_by_job: Option<i64>,
	pub created_at: i64,
	pub closed_at: Option<i64>,
}
// debug-ok: submission outcomes contain integer IDs and closed lead states/dispositions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
	Created(i64),
	Attached { lead_id: i64, status: Status },
	ClosedExists { lead_id: i64, disposition: Disposition, finding_id: Option<i64> },
}
pub enum Closure {
	Promoted { finding: i64 },
	Rejected,
	Duplicate { lead: Option<i64>, finding: Option<i64> },
	Hardening,
	Stale,
}

pub struct NewLeadEvidence<'a, RevisionS: Source> {
	pub generation_id: i64,
	pub created_by_job: i64,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub priority: Priority,
	pub payload: &'a LeadEvidenceV1<Agent>,
}
// debug-ok: content owners redact text; remaining fields are numeric or closed states.
#[derive(Debug, Clone)]
pub struct Metadata {
	pub lead_id: i64,
	pub generation_id: i64,
	pub unit_id: Option<i64>,
	pub identity: Identity<Agent>,
	pub status: Status,
	pub disposition: Option<Disposition>,
	pub priority: Priority,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub needs_revalidation: bool,
	pub promoted_finding: Option<i64>,
	pub created_by_job: Option<i64>,
	pub created_at: i64,
}
pub fn submit<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewLead<'_, RevisionS>, now: i64,
) -> Result<Submitted> {
	scope.require_operator()?;
	crate::review::require_historical_payload(new.payload.expose())?;
	submit_inner(
		scope.conn,
		scope.repo_id,
		&LeadInput {
			generation_id: new.generation_id,
			unit_id: new.unit_id,
			identity: new.identity,
			payload: new.payload.expose(),
			digest: *new.payload.digest(),
			commit_sha: new.commit_sha.expose(),
			priority: new.priority,
			priority_proposal: new.priority_proposal.map(BoundedJson::expose),
			supersedes: new.supersedes,
			created_by_job: new.created_by_job,
		},
		now,
	)
}
pub fn submit_evidence<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewLeadEvidence<'_, RevisionS>, now: i64,
) -> Result<Submitted> {
	scope.require_operator()?;
	submit_evidence_raw(scope.conn, scope.repo_id, new, now)
}
pub(crate) fn submit_evidence_raw<RevisionS: Source>(
	conn: &Connection, repo: i64, new: &NewLeadEvidence<'_, RevisionS>, now: i64,
) -> Result<Submitted> {
	let bytes = new.payload.canonical_bytes()?;
	validate_evidence_scope_raw(conn, repo, new.generation_id, new.payload)?;
	let identity = evidence_identity(new.payload);
	submit_inner(
		conn,
		repo,
		&LeadInput {
			generation_id: new.generation_id,
			unit_id: new.payload.review_unit_id,
			identity: &identity,
			payload: std::str::from_utf8(&bytes)
				.map_err(|_| Error::Conflict(Conflict::CheckpointEvidence))?,
			digest: crate::canonical::digest(&bytes),
			commit_sha: new.commit_sha.expose(),
			priority: new.priority,
			priority_proposal: None,
			supersedes: None,
			created_by_job: Some(new.created_by_job),
		},
		now,
	)
}
pub(crate) fn evidence_identity(payload: &LeadEvidenceV1<Agent>) -> Identity<Agent> {
	Identity {
		family: payload.identity_family.clone(),
		anchor: payload.identity_anchor.clone(),
		instance: payload.identity_instance_key.clone(),
	}
}
pub(crate) fn validate_evidence_scope(
	scope: &crate::scope::RepoScope<'_>, generation: i64, payload: &LeadEvidenceV1<Agent>,
) -> Result<()> {
	validate_evidence_scope_raw(scope.conn, scope.repo_id, generation, payload)
}
pub(crate) fn validate_evidence_scope_raw(
	conn: &Connection, repo: i64, generation: i64, payload: &LeadEvidenceV1<Agent>,
) -> Result<()> {
	ownership::generation(conn, repo, generation, Ownership::LeadUnit)?;
	if let Some(unit) = payload.review_unit_id {
		ownership::unit_in_generation(conn, unit, generation, Ownership::LeadUnit)?;
	}
	inventory::verify_refs_raw(conn, repo, generation, &payload.source_refs)?;
	if let Some(proposal) = &payload.priority_proposal {
		inventory::verify_refs_raw(conn, repo, generation, &proposal.boundary_refs)?;
	}
	if let Some(hint) = &payload.duplicate_hint {
		ownership::lead_in_repo(conn, hint.lead_id, repo, Ownership::DuplicateLead)?;
	}
	Ok(())
}
struct LeadInput<'a> {
	generation_id: i64,
	unit_id: Option<i64>,
	identity: &'a Identity<Agent>,
	payload: &'a str,
	digest: [u8; 32],
	commit_sha: &'a str,
	priority: Priority,
	priority_proposal: Option<&'a str>,
	supersedes: Option<i64>,
	created_by_job: Option<i64>,
}
fn submit_inner(tx: &Connection, repo: i64, new: &LeadInput<'_>, now: i64) -> Result<Submitted> {
	ownership::generation(tx, repo, new.generation_id, Ownership::LeadUnit)?;
	if let Some(unit) = new.unit_id {
		ownership::unit_in_generation(tx, unit, new.generation_id, Ownership::LeadUnit)?;
	}
	if let Some(job) = new.created_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::LeadJob)?;
	}
	if let Some(parent) = new.supersedes {
		ownership::lead_in_generation(tx, parent, new.generation_id, Ownership::SupersededLead)?;
		// Superseding records a stale-closed identity being resubmitted; any
		// other lead state would fabricate that history.
		let stale: bool = tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2) AND status='closed' AND disposition='stale')",
			params![parent,repo],
			|r| r.get(0),
		)?;
		if !stale {
			return Err(Error::Conflict(Conflict::LeadState));
		}
	}
	let fingerprint = new.identity.fingerprint();
	let supersedes=match new.supersedes{
  Some(id)=>Some(id),
  None=>tx.query_row("SELECT lead_id FROM leads WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?3) AND identity_fingerprint=?2 AND status='closed' AND disposition='stale' ORDER BY lead_id DESC LIMIT 1",params![new.generation_id,fingerprint.as_slice(),repo],|r|r.get(0)).optional()?
 };
	let result=tx.execute("INSERT INTO leads (generation_id,review_unit_id,priority_band,priority_proposal,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,supersedes_lead_id,created_by_job_id,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'agent' WHERE EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?15)",params![new.generation_id,new.unit_id,new.priority.as_str(),new.priority_proposal,new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.payload,new.digest.as_slice(),new.commit_sha,supersedes,new.created_by_job,now,repo]);
	match result {
		Ok(_) => Ok(Submitted::Created(tx.last_insert_rowid())),
		Err(error) if is_unique(&error, "leads.generation_id, leads.identity_fingerprint") => {
			let existing=tx.query_row(&format!("SELECT {COLUMNS} FROM leads WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?3) AND identity_fingerprint=?2 AND (status<>'closed' OR disposition<>'stale')"),params![new.generation_id,fingerprint.as_slice(),repo],metadata_row)?;
			lead_observations::insert_raw(
				tx,
				repo,
				&lead_observations::ObservationInput {
					lead_id: existing.lead_id,
					submitted_by_job: new.created_by_job,
					payload: new.payload,
					digest: &new.digest,
					commit_sha: new.commit_sha,
				},
				now,
			)?;
			match existing.status {
				Status::Open | Status::Deferred => {
					Ok(Submitted::Attached { lead_id: existing.lead_id, status: existing.status })
				},
				Status::Closed => {
					let disposition =
						existing.disposition.ok_or(Error::Conflict(Conflict::LeadState))?;
					Ok(Submitted::ClosedExists {
						lead_id: existing.lead_id,
						disposition,
						finding_id: if disposition == Disposition::Promoted {
							existing.promoted_finding
						} else {
							None
						},
					})
				},
			}
		},
		Err(error) => Err(error.into()),
	}
}
const COLUMNS:&str="lead_id,generation_id,review_unit_id,status,disposition,defer_reason,retry_condition,priority_band,priority_proposal,identity_family,identity_anchor,identity_instance_key,anchored_payload,commit_sha,needs_revalidation,carry_depth,supersedes_lead_id,duplicate_of_lead_id,duplicate_of_finding_id,promoted_finding_id,created_by_job_id,created_at,closed_at,source,anchored_digest,identity_fingerprint";
fn row(r: &Row<'_>) -> rusqlite::Result<Lead> {
	crate::ingress::require_agent_source(r, 23)?;
	Ok(Lead {
		lead_id: r.get(0)?,
		generation_id: r.get(1)?,
		unit_id: r.get(2)?,
		status: parsed(r, 3)?,
		disposition: optional(r, 4)?,
		defer_reason: crate::ingress::optional_reason(r, 5)?,
		retry_condition: crate::ingress::optional_reason(r, 6)?,
		priority: parsed(r, 7)?,
		priority_proposal: crate::ingress::optional_agent_payload(r, 8)?,
		identity: Identity {
			family: crate::ingress::family(r, 9)?,
			anchor: crate::ingress::anchor(r, 10)?,
			instance: crate::ingress::optional_instance(r, 11)?,
		},
		payload: crate::ingress::checkpoint::historical_payload(r, 12)?,
		commit_sha: crate::ingress::revision(r, 13)?,
		needs_revalidation: r.get(14)?,
		carry_depth: r.get(15)?,
		supersedes: r.get(16)?,
		duplicate_lead: r.get(17)?,
		duplicate_finding: r.get(18)?,
		promoted_finding: r.get(19)?,
		created_by_job: r.get(20)?,
		created_at: r.get(21)?,
		closed_at: r.get(22)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "leads", COLUMNS, |r| {
		crate::ingress::require_agent_source(r, 23)?;
		if crate::ingress::checkpoint::is_modern(r, 12)? {
			metadata_row(r)?;
			crate::ingress::optional_reason(r, 5)?;
			crate::ingress::optional_reason(r, 6)?;
			let _: i64 = r.get(15)?;
			for index in [16, 17, 18, 22] {
				let _: Option<i64> = r.get(index)?;
			}
			evidence_row(r).map_err(|_| crate::review::invalid_scalar(12))?;
		} else {
			row(r)?;
		}
		Ok::<_, rusqlite::Error>(())
	})
}
pub fn get(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<Option<Lead>> {
	let tx = scope.conn;
	Ok(tx
		.query_row(&format!("SELECT {COLUMNS} FROM leads WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2)"), params![id,scope.repo_id], row)
		.optional()?)
}
pub fn list(scope: &crate::scope::RepoScope<'_>, generation: i64) -> Result<Vec<Lead>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!("SELECT {COLUMNS} FROM leads WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2) ORDER BY lead_id"))?
		.query_map(params![generation,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
pub fn close(
	scope: &crate::scope::RepoScope<'_>, id: i64, closure: &Closure, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	close_raw(scope.conn, scope.repo_id, id, closure, now)
}
pub(crate) fn close_raw(
	tx: &Connection, repo: i64, id: i64, closure: &Closure, now: i64,
) -> Result<()> {
	get_metadata_raw(tx, repo, id)?.ok_or(Error::NotFound(Entity::Lead, id))?;
	let (disposition, duplicate_lead, duplicate_finding, promoted_finding) = match closure {
		Closure::Promoted { finding } => {
			ownership::finding(tx, *finding, repo, Ownership::PromotedFinding)?;
			(Disposition::Promoted, None, None, Some(*finding))
		},
		Closure::Duplicate { lead, finding } => {
			if lead.is_none() && finding.is_none() || *lead == Some(id) {
				return Err(Error::Conflict(Conflict::LeadState));
			}
			if let Some(other) = lead {
				ownership::lead_in_repo(tx, *other, repo, Ownership::DuplicateLead)?;
			}
			if let Some(other) = finding {
				ownership::finding(tx, *other, repo, Ownership::DuplicateFinding)?;
			}
			(Disposition::Duplicate, *lead, *finding, None)
		},
		Closure::Rejected => (Disposition::Rejected, None, None, None),
		Closure::Hardening => (Disposition::Hardening, None, None, None),
		Closure::Stale => (Disposition::Stale, None, None, None),
	};
	changed(tx.execute("UPDATE leads SET status='closed',disposition=?2,duplicate_of_lead_id=?3,duplicate_of_finding_id=?4,promoted_finding_id=?5,closed_at=?6 WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?7) AND status IN ('open','deferred') AND (?2<>'stale' OR NOT EXISTS(SELECT 1 FROM jobs WHERE assigned_lead_id=?1 AND state IN ('queued','leased')))",params![id,disposition.as_str(),duplicate_lead,duplicate_finding,promoted_finding,now,repo])?,Conflict::LeadState)
}
pub fn defer<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>,
	retry: Option<&BoundedText<Reason, S>>,
) -> Result<()> {
	scope.require_operator()?;
	defer_raw(scope.conn, scope.repo_id, id, reason.expose(), retry.map(BoundedText::expose))
}
pub(crate) fn defer_for_continuation_raw(
	tx: &Connection, repo: i64, id: i64, class: loupe_core::review_payload::ContinuationClass,
) -> Result<()> {
	defer_raw(tx, repo, id, crate::review_intents::class_str(class), None)
}
fn defer_raw(tx: &Connection, repo: i64, id: i64, reason: &str, retry: Option<&str>) -> Result<()> {
	changed(tx.execute("UPDATE leads SET status='deferred',defer_reason=?2,retry_condition=?3 WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?4) AND status='open'",params![id,reason,retry,repo])?,Conflict::LeadState)
}
pub fn reopen(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE leads SET status='open',defer_reason=NULL,retry_condition=NULL WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2) AND status='deferred'",params![id,scope.repo_id])?,Conflict::LeadState)
}
pub fn mark_needs_revalidation(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE leads SET needs_revalidation=1 WHERE lead_id=?1 AND status IN ('open','deferred') AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2)",params![id,scope.repo_id])?,Conflict::LeadState)
}

fn metadata_row(r: &Row<'_>) -> rusqlite::Result<Metadata> {
	crate::ingress::require_agent_source(r, 23)?;
	Ok(Metadata {
		lead_id: r.get(0)?,
		generation_id: r.get(1)?,
		unit_id: r.get(2)?,
		identity: Identity {
			family: crate::ingress::family(r, 9)?,
			anchor: crate::ingress::anchor(r, 10)?,
			instance: crate::ingress::optional_instance(r, 11)?,
		},
		status: parsed(r, 3)?,
		disposition: optional(r, 4)?,
		priority: parsed(r, 7)?,
		commit_sha: crate::ingress::revision(r, 13)?,
		needs_revalidation: r.get(14)?,
		promoted_finding: r.get(19)?,
		created_by_job: r.get(20)?,
		created_at: r.get(21)?,
	})
}
pub fn get_metadata(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<Option<Metadata>> {
	get_metadata_raw(scope.conn, scope.repo_id, id)
}
pub(crate) fn get_metadata_raw(conn: &Connection, repo: i64, id: i64) -> Result<Option<Metadata>> {
	Ok(conn.query_row(&format!("SELECT {COLUMNS} FROM leads WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2)"),params![id,repo],metadata_row).optional()?)
}
fn evidence_row(r: &Row<'_>) -> Result<StoredEvidence<LeadEvidenceV1<Agent>>> {
	crate::ingress::require_agent_source(r, 23)?;
	let evidence = crate::ingress::checkpoint::lead(r, 12, 24)?;
	if let StoredEvidence::Recorded(value) = &evidence
		&& (r.get::<_, Option<i64>>(2)? != value.review_unit_id
			|| r.get::<_, String>(9)? != value.identity_family.expose()
			|| r.get::<_, String>(10)? != value.identity_anchor.expose()
			|| r.get::<_, Option<String>>(11)?.as_deref()
				!= value.identity_instance_key.as_ref().map(|v| v.expose())
			|| r.get::<_, Vec<u8>>(25)? != evidence_identity(value).fingerprint()
			|| !matches!(r.get_ref(8)?, rusqlite::types::ValueRef::Null))
	{
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(evidence)
}
pub fn get_evidence(
	scope: &crate::scope::RepoScope<'_>, id: i64,
) -> Result<StoredEvidence<LeadEvidenceV1<Agent>>> {
	get_evidence_raw(scope.conn, scope.repo_id, id)
}
pub(crate) fn get_evidence_raw(
	conn: &Connection, repo: i64, id: i64,
) -> Result<StoredEvidence<LeadEvidenceV1<Agent>>> {
	let mut statement=conn.prepare(&format!("SELECT {COLUMNS} FROM leads WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2)"))?;
	let mut rows = statement.query(params![id, repo])?;
	match rows.next()? {
		Some(row) => evidence_row(row),
		None => Ok(StoredEvidence::Missing),
	}
}
