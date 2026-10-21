use loupe_core::review_metadata::ReviewCommit;
use loupe_core::text::policy::RevisionText;
use loupe_core::text::BoundedText;
use loupe_core::unsupported_preparation::UnsupportedPreparation;
use loupe_core::WORKFLOW_CONTRACT_VERSION;
use loupe_provenance::{Db, Worker};
use rusqlite::params;

use super::{denied, Phase, PhaseScope};
use crate::{campaigns, generations, terminal_receipt, Conflict, Error, Result};

struct GenerationChoice {
	id: i64,
	commit: BoundedText<RevisionText, Db>,
	state: generations::State,
	contract: i64,
	predecessor: Option<i64>,
}

pub(super) fn pin_and_confirm(
	scope: &PhaseScope<'_, '_>, commit: &ReviewCommit<Worker>, digest: &[u8; 32],
) -> Result<Option<(Box<terminal_receipt::Receipt>, ReviewCommit<Db>)>> {
	let conn = scope.transaction.conn;
	let now = scope.transaction.now;
	let hash = scope.transaction.capability_hash.ok_or_else(denied)?;
	let campaign = campaigns::get_raw(conn, scope.job.campaign_id)?
		.filter(|c| c.repo_id == scope.job.repo_id)
		.ok_or_else(denied)?;
	let generation = if let Some(generation) = scope.job.generation_id {
		if campaign.target_commit_sha.expose() != commit.expose() {
			return Err(Error::Conflict(Conflict::CampaignPinned));
		}
		generation
	} else {
		if scope.job.phase != Phase::Survey {
			return Err(denied());
		}
		let choices=conn.prepare("SELECT generation_id,generation_commit_sha,state,workflow_contract_version,predecessor_generation_id FROM review_generations WHERE repo_id=?1 ORDER BY created_at DESC,generation_id DESC")?.query_map([scope.job.repo_id],|row|Ok(GenerationChoice {id:row.get(0)?,commit:crate::ingress::revision(row,1)?,state:crate::review::parsed(row,2)?,contract:row.get(3)?,predecessor:row.get(4)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
		let active =
			choices.iter().find(|generation| generation.state == generations::State::Active);
		let existing = active.and_then(|active| {
			if active.commit.expose() == commit.expose()
				&& active.contract == WORKFLOW_CONTRACT_VERSION
			{
				Some(active.id)
			} else if active.commit.expose() != commit.expose() {
				choices
					.iter()
					.find(|candidate| {
						candidate.state == generations::State::Building
							&& candidate.commit.expose() == commit.expose()
							&& candidate.contract == WORKFLOW_CONTRACT_VERSION
							&& candidate.predecessor == Some(active.id)
					})
					.map(|candidate| candidate.id)
			} else {
				None
			}
		});
		let generation = if let Some(existing) = existing {
			existing
		} else {
			if active.is_none() {
				conn.execute("UPDATE review_generations SET state='retired',retired_reason='superseded bootstrap',retired_at=?2 WHERE repo_id=?1 AND state='building'",params![scope.job.repo_id,now])?;
			}
			conn.execute("INSERT INTO review_generations(repo_id,predecessor_generation_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(?1,?2,?3,'building',?4,?5)",params![scope.job.repo_id,active.map(|g|g.id),commit.expose(),WORKFLOW_CONTRACT_VERSION,now])?;
			conn.last_insert_rowid()
		};
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?2,generation_id=?3 WHERE campaign_id=?1 AND repo_id=?4",params![scope.job.campaign_id,commit.expose(),generation,scope.job.repo_id])?;
		conn.execute(
			"UPDATE jobs SET generation_id=?2 WHERE id=?1 AND repo_id=?3",
			params![scope.job.id, generation, scope.job.repo_id],
		)?;
		let successor:bool=conn.query_row("SELECT state='building' AND predecessor_generation_id IS NOT NULL FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![generation,scope.job.repo_id],|row|row.get(0))?;
		if successor {
			return defer_successor(scope, generation, &campaign, commit, digest).map(Some);
		}
		generation
	};
	let exact:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM jobs j JOIN review_campaigns c ON c.campaign_id=j.campaign_id JOIN review_generations g ON g.generation_id=j.generation_id WHERE j.id=?1 AND j.repo_id=?2 AND c.repo_id=?2 AND g.repo_id=?2 AND j.generation_id=?3 AND c.generation_id=?3 AND c.target_commit_sha=?4 AND g.generation_commit_sha=?4)",params![scope.job.id,scope.job.repo_id,generation,commit.expose()],|row|row.get(0))?;
	if !exact {
		return Err(denied());
	}
	conn.execute("UPDATE jobs SET head_sha=?2,prepared_at=CASE WHEN prepared_attempt=attempts AND prepared_capability_hash=?3 AND head_sha=?2 THEN prepared_at ELSE ?4 END,prepared_attempt=attempts,prepared_capability_hash=?3 WHERE id=?1 AND repo_id=?5",params![scope.job.id,commit.expose(),hash.as_slice(),now,scope.job.repo_id])?;
	Ok(None)
}

fn defer_successor(
	scope: &PhaseScope<'_, '_>, generation: i64, campaign: &campaigns::Campaign,
	commit: &ReviewCommit<Worker>, digest: &[u8; 32],
) -> Result<(Box<terminal_receipt::Receipt>, ReviewCommit<Db>)> {
	let conn = scope.transaction.conn;
	let recipe = conn.query_row(
		"SELECT recipe FROM jobs WHERE id=?1 AND repo_id=?2",
		params![scope.job.id, scope.job.repo_id],
		|row| crate::ingress::db_payload(row, 0),
	)?;
	let previous = conn.query_row(
		"SELECT pending_follow_up FROM review_generations WHERE generation_id=?1 AND repo_id=?2",
		params![generation, scope.job.repo_id],
		|row| crate::ingress::optional_db_payload(row, 0),
	)?;
	let composition = UnsupportedPreparation::new(
		&recipe,
		&campaign.effective_policy,
		previous.as_ref(),
		&campaign.target_commit_sha,
		commit,
		scope.job.campaign_id,
		scope.job.id,
	)?;
	conn.execute("UPDATE review_generations SET pending_follow_up=?2 WHERE generation_id=?1 AND repo_id=?3 AND state='building'",params![generation,composition.follow_up(),scope.job.repo_id])?;
	let hash = scope.transaction.capability_hash.ok_or_else(denied)?;
	conn.execute("INSERT INTO job_terminal_receipts(job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,finishing_capability_hash,created_at) VALUES(?1,'survey','unsupported_recipe',?2,?3,?4,?5,?6)",params![scope.job.id,commit.expose(),composition.audit(),digest.as_slice(),hash.as_slice(),scope.transaction.now])?;
	conn.execute("UPDATE jobs SET state='cancelled',finished_at=?2,error='unsupported_recipe',job_capability_hash=NULL,lease_expires_at=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1 AND repo_id=?3",params![scope.job.id,scope.transaction.now,scope.job.repo_id])?;
	let other_work: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND state IN ('queued','leased'))",
		[scope.job.campaign_id],
		|row| row.get(0),
	)?;
	if !other_work {
		campaigns::finish_unsupported(
			conn,
			scope.job.repo_id,
			scope.job.campaign_id,
			scope.transaction.now,
		)?;
	}
	let receipt = terminal_receipt::get_raw(conn, scope.job.id)?.ok_or_else(denied)?;
	let commit = conn.query_row(
		"SELECT pinned_commit_sha FROM job_terminal_receipts WHERE job_id=?1",
		[scope.job.id],
		|row| crate::ingress::profile::commit(row, 0),
	)?;
	Ok((Box::new(receipt), commit))
}
