//! Independent disposition receipts stay inside the live phase transaction.
//! ```compile_fail,E0603
//! fn raw(conn: &rusqlite::Connection) {
//!     let _ = loupe_storage::inventory_disposition::resolve;
//! }
//! ```
use rusqlite::params;

use super::{Access, Phase, PhaseScope};
use crate::checkpoints::{self, Operation};
use crate::inventory_disposition::{self as stored, Receipt, Submission};
use crate::{Conflict, Error, Result};

impl PhaseScope<'_, '_> {
	/// Replay precedes every mutable entry/assignment/CAS/quota guard. The
	/// enclosing facade rolls back replacement and receipt on any later error,
	/// including the server's bounded response conversion.
	pub fn submit_inventory_disposition(&self, request: &Submission<'_>) -> Result<Receipt> {
		if self.access != Access::Domain || self.job.phase != Phase::Survey {
			return Err(Error::ScopeDenied);
		}
		let conn = self.transaction.conn;
		let job = &self.job;
		if let Some(receipt) = stored::replay(conn, job.repo_id, job.id, request)? {
			return Ok(receipt);
		}
		let generation = job.generation_id.ok_or(Error::ScopeDenied)?;
		let entry =
			stored::resolve(conn, job.repo_id, job.id, generation, self.bootstrap, request.path)?
				.ok_or(Error::ScopeDenied)?;
		if entry.revision() != request.expected_revision {
			return Err(Error::Conflict(Conflict::InventoryRevision(entry.revision())));
		}
		for mapping in request.mappings {
			if !self.survey_unit_reference(mapping.unit_id, mapping.assignment_epoch)? {
				return Err(Error::ScopeDenied);
			}
		}
		if checkpoints::accepted_count_raw(
			conn,
			job.repo_id,
			job.id,
			Operation::SubmitInventoryDisposition,
		)? >= stored::MAX_OPERATIONS
		{
			return Err(Error::Conflict(Conflict::CheckpointLimit));
		}
		let revision = stored::replace(
			conn,
			&entry,
			&stored::Update {
				expected_revision: request.expected_revision,
				disposition: request.disposition,
				reason: request.reason,
				mappings: request.mappings,
			},
		)?;
		let receipt = Receipt {
			inventory_entry_id: entry.id(),
			revision: revision.try_into().map_err(|_| Error::Conflict(Conflict::InventoryLimit))?,
		};
		stored::record(conn, job.repo_id, job.id, request, receipt, self.transaction.now)?;
		Ok(receipt)
	}

	/// Reference authority is not permission to submit another assessment:
	/// completed results and holds retain exact owned membership/epoch.
	fn survey_unit_reference(&self, id: i64, epoch: i64) -> Result<bool> {
		let membership = if self.bootstrap {
			"u.created_by_job_id=?3"
		} else {
			"EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?3 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?4)"
		};
		Ok(self.transaction.conn.query_row(&format!(
   "SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id
    WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND {membership}
    AND u.assignment_epoch=?4 AND g.repo_id=?5
    AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id
    WHERE a.review_unit_id=u.review_unit_id AND a.job_id<>?3 AND j.state IN ('queued','leased')))"
  ),params![id,self.job.generation_id,self.job.id,epoch,self.job.repo_id],|row|row.get(0))?)
	}
}

#[cfg(test)]
mod tests {
	use loupe_core::text::{Identifier, RepoPath};

	use super::super::tests::{fixture, identity, mutate};
	use super::super::{with_phase_transaction, PolicyDecision};
	use super::*;
	use crate::inventory::Disposition;

	fn seed_inventory(db: &crate::Db) {
		mutate(db,"UPDATE generation_manifests SET expected_entry_count=1,received_entry_count=1 WHERE generation_id=11;
   INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,raw_path,source_path,manifest_position,git_mode,blob_sha,entry_kind,created_at)
   VALUES(1,11,'a.rs',CAST('a.rs' AS BLOB),'a.rs',0,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0);");
	}

	#[test]
	fn inventory_workflow_requires_domain_and_callback_errors_roll_back() {
		let db = fixture();
		seed_inventory(&db);
		let key =
			crate::test_support::worker("request", |raw, mark| Identifier::new(mark, raw)).unwrap();
		let path =
			crate::test_support::worker("a.rs", |raw, mark| RepoPath::new(mark, raw)).unwrap();
		let request = Submission {
			key: &key,
			path: &path,
			digest: &[9; 32],
			expected_revision: 0,
			disposition: Disposition::Unresolved,
			reason: None,
			mappings: &[],
		};
		for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost] {
			with_phase_transaction(
				&db,
				identity(),
				|| 100,
				|tx| {
					let scope = tx
						.authorize(Phase::Survey, access, |_| Ok(Some(PolicyDecision::Bootstrap)))?
						.unwrap();
					assert!(matches!(
						scope.submit_inventory_disposition(&request),
						Err(Error::ScopeDenied)
					));
					Ok::<_, Error>(())
				},
			)
			.unwrap();
		}
		let failed = with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, Access::Domain, |_| {
						Ok(Some(PolicyDecision::Bootstrap))
					})?
					.unwrap();
				assert_eq!(scope.submit_inventory_disposition(&request)?.revision, 1);
				Err::<(), Error>(Error::Conflict(Conflict::CampaignSummary))
			},
		);
		assert!(matches!(failed, Err(Error::Conflict(Conflict::CampaignSummary))));
		db.with_conn(|conn| {
   assert_eq!(conn.query_row("SELECT disposition_revision FROM generation_inventory WHERE inventory_entry_id=1",[],|row|row.get::<_,i64>(0))?,0);
   assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_checkpoints",[],|row|row.get::<_,i64>(0))?,0);
   Ok(())
  }).unwrap();
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, Access::Domain, |_| {
						Ok(Some(PolicyDecision::Bootstrap))
					})?
					.unwrap();
				assert_eq!(scope.submit_inventory_disposition(&request)?.revision, 1);
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}

	#[test]
	fn queued_and_expired_leased_other_owners_still_reserve_mapping_references() {
		for (state, expected) in [("queued", false), ("leased", false), ("succeeded", true)] {
			let db = fixture();
			seed_inventory(&db);
			db.with_conn(|conn| {
    conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) VALUES(31,11,'owned','title','objective','[{\"path\":\"a.rs\"}]',3,101,0);
     INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,worker_id,lease_expires_at,enqueued_at) VALUES(102,1,'survey','queued',1,11,1,0,0);
     INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(102,31,0,3);")?;
    conn.execute("UPDATE jobs SET state=?1 WHERE id=102",[state])?;
    Ok(())
   }).unwrap();
			with_phase_transaction(
				&db,
				identity(),
				|| 100,
				|tx| {
					let scope = tx
						.authorize(Phase::Survey, Access::Domain, |_| {
							Ok(Some(PolicyDecision::Bootstrap))
						})?
						.unwrap();
					assert_eq!(scope.survey_unit_reference(31, 3)?, expected, "{state}");
					Ok::<_, Error>(())
				},
			)
			.unwrap();
		}
	}
}
