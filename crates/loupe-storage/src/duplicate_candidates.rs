//! Job-issued duplicate context. Only the purpose-bound phase facade can
//! issue or revalidate these minimal immutable snapshots.
use loupe_core::review_candidates::{Candidate, CandidateKind, CandidateQuery};
use loupe_provenance::{Agent, Db, Worker};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::checkpoints::{self, Operation, Replay, Stored};
use crate::identity::Identity;
use crate::{Conflict, Error, Result};

pub const QUERY_LIMIT: i64 = 32;

fn invalid() -> Error {
	Error::Conflict(Conflict::Candidate)
}

fn row(row: &Row<'_>) -> rusqlite::Result<(Candidate<Agent, Db>, Vec<u8>)> {
	crate::ingress::require_agent_source(row, 9)?;
	Ok((
		Candidate {
			kind: match row.get_ref(0)?.as_str()? {
				"lead" => CandidateKind::Lead,
				"finding" => CandidateKind::Finding,
				_ => return Err(crate::review::invalid_scalar(0)),
			},
			id: row.get(1)?,
			producer_job_id: row.get(2)?,
			commit_sha: crate::ingress::profile::commit(row, 3)?,
			created_at: row.get(4)?,
			identity_family: crate::ingress::family(row, 5)?,
			identity_anchor: crate::ingress::anchor(row, 6)?,
			identity_instance_key: crate::ingress::optional_instance(row, 7)?,
		},
		row.get(8)?,
	))
}

const CANDIDATES: &str = "
SELECT 'lead' AS kind,l.lead_id AS id,l.created_by_job_id AS producer_job_id,
 l.commit_sha,l.created_at,l.identity_family,l.identity_anchor,l.identity_instance_key,l.identity_fingerprint,l.source
 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id
 WHERE g.repo_id=?1 AND l.created_by_job_id IS NOT NULL
UNION ALL
SELECT 'finding',f.id,f.job_id,d.reviewed_commit_sha,f.created_at,
 d.identity_family,d.identity_anchor,d.identity_instance_key,d.identity_fingerprint,d.source
 FROM findings f JOIN finding_review_details d ON d.finding_id=f.id AND d.repo_id=f.repo_id
 WHERE f.repo_id=?1";

fn checked(
	(candidate, fingerprint): (Candidate<Agent, Db>, Vec<u8>),
) -> Result<Candidate<Agent, Db>> {
	let identity = Identity {
		family: candidate.identity_family.clone(),
		anchor: candidate.identity_anchor.clone(),
		instance: candidate.identity_instance_key.clone(),
	};
	if candidate.validate().is_err() || fingerprint != identity.fingerprint() {
		return Err(invalid());
	}
	Ok(candidate)
}

pub(crate) fn issue(
	conn: &Connection, job: i64, repo: i64, query: &CandidateQuery<Worker>, now: i64,
) -> Result<Vec<Candidate<Agent, Db>>> {
	query.validate().map_err(|_| invalid())?;
	let owned: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND campaign_id IS NOT NULL AND kind IN ('survey','drilldown'))", params![job,repo], |row| row.get(0))?;
	if !owned {
		return Err(Error::ScopeDenied);
	}
	let bytes =
		crate::canonical::canonical_bytes(&serde_json::to_value(query).map_err(|_| invalid())?);
	let digest = crate::canonical::digest(&bytes);
	// This host-generated key is not labelled as content from the peer.
	let key: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
	let qualified = format!("{}:{key}", Operation::IssueDuplicateCandidates.as_str());
	let replay = conn.query_row(
		"SELECT operation,payload_digest,response FROM job_checkpoints
		 WHERE job_id=?1 AND client_key=?2 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3)",
		params![job,qualified,repo],
		|row| {
			// Check the fixed producer and exact query binding before decoding any
			// response tokens or carrying their stored identity as Agent.
			let stored = Stored { operation: row.get_ref(0)?.as_str()?, digest: row.get_ref(1)?.as_blob()? };
			if checkpoints::replay_decision(Some(&stored), Operation::IssueDuplicateCandidates, &digest) != Replay::Hit {
				return Ok(Err(Error::Conflict(Conflict::Checkpoint)));
			}
			Ok(crate::ingress::candidates::snapshot(row, 2).map_err(Error::from))
		},
	).optional()?;
	if let Some(replay) = replay {
		return replay;
	}
	if checkpoints::accepted_count_raw(conn, repo, job, Operation::IssueDuplicateCandidates)?
		>= QUERY_LIMIT
	{
		return Err(Error::Conflict(Conflict::CheckpointLimit));
	}
	let sql = format!("SELECT * FROM ({CANDIDATES}) WHERE instr(lower(identity_family),lower(?2))>0 OR instr(lower(identity_anchor),lower(?2))>0 ORDER BY kind,id LIMIT ?3");
	let mut statement = conn.prepare(&sql)?;
	let candidates = statement
		.query_map(params![repo, query.query.expose(), query.limit], row)?
		.map(|value| checked(value?))
		.collect::<Result<Vec<_>>>()?;
	let response = serde_json::to_string(&candidates).map_err(|_| invalid())?;
	if response.len() > crate::ingress::candidates::MAX_BYTES {
		return Err(invalid());
	}
	let inserted = conn.execute(
		"INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at)
		 SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?7)",
		params![job,qualified,Operation::IssueDuplicateCandidates.as_str(),digest.as_slice(),response,now,repo],
	)?;
	if inserted != 1 {
		return Err(invalid());
	}
	Ok(candidates)
}

/// Issuance precedes current target reads, including reads that could fail on
/// malformed content. Mutable lifecycle/body fields are deliberately absent.
pub(crate) fn issued_target(
	conn: &Connection, job: i64, repo: i64, kind: CandidateKind, id: i64,
) -> Result<bool> {
	let mut statement = conn.prepare(
		"SELECT response FROM job_checkpoints WHERE job_id=?1 AND operation=?2
		 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3) ORDER BY client_key LIMIT ?4",
	)?;
	let responses = statement.query_map(
		params![job, Operation::IssueDuplicateCandidates.as_str(), repo, QUERY_LIMIT + 1],
		|row| crate::ingress::candidates::snapshot(row, 0),
	)?;
	let mut issued = Vec::new();
	for (index, response) in responses.enumerate() {
		if index >= QUERY_LIMIT as usize {
			return Err(invalid());
		}
		issued.extend(
			response?.into_iter().filter(|candidate| candidate.kind == kind && candidate.id == id),
		);
	}
	if issued.is_empty() {
		return Ok(false);
	}
	let sql = format!("SELECT * FROM ({CANDIDATES}) WHERE kind=?2 AND id=?3");
	let current = conn
		.query_row(
			&sql,
			params![
				repo,
				match kind {
					CandidateKind::Lead => "lead",
					CandidateKind::Finding => "finding",
				},
				id
			],
			row,
		)
		.optional()?;
	let Some(current) = current else { return Ok(false) };
	let current = checked(current)?;
	Ok(issued.iter().any(|candidate| candidate == &current))
}

#[cfg(test)]
mod tests;
