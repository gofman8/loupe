use rusqlite::Transaction;

use super::*;
use crate::secrets::MasterKey;
use crate::{review_tests, transaction, Db};

fn seed(db: &Db, policy: &CampaignPolicyV2) {
	review_tests::seed(db);
	db.with_conn(|conn| {
		conn.execute_batch("DELETE FROM jobs;
		 INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',zeroblob(32),0);")?;
		let snapshot = String::from_utf8(policy.canonical_bytes()?).unwrap();
		let digest = loupe_core::canonical::digest(snapshot.as_bytes());
		let old = serde_json::to_value(crate::scheduler::CampaignPolicy::default()).unwrap();
		let old = String::from_utf8(loupe_core::canonical::canonical_bytes(&old)).unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2 WHERE campaign_id=2",
			params![old,loupe_core::canonical::digest(old.as_bytes()).as_slice()])?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2,deadline_at=1000 WHERE campaign_id=1",
			params![snapshot,digest.as_slice()])?;
		Ok(())
	}).unwrap();
}

fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db, &CampaignPolicyV2::default());
	db
}

fn insert_job(tx: &Transaction<'_>, id: i64, kind: &str, band: &str, queued: bool) -> Result<()> {
	let hash = id.to_be_bytes().repeat(4);
	tx.execute(
		"INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,scheduling_band,
		 attempts,worker_id,job_capability_hash,lease_expires_at,enqueued_at)
		 VALUES(?1,1,?2,?3,1,11,?4,?5,1,?6,100,0)",
		params![
			id,
			kind,
			if queued { "queued" } else { "leased" },
			band,
			if queued { 0 } else { 1 },
			hash
		],
	)?;
	Ok(())
}

#[test]
fn pool_order_and_every_exhaustion_combination_follow_the_contract() {
	let policy = CampaignPolicyV2::default();
	for general_full in [false, true] {
		for urgent_full in [false, true] {
			for verification_full in [false, true] {
				let spent = Spending {
					general: if general_full { 56 } else { 0 },
					urgent: if urgent_full { 4 } else { 0 },
					verification: if verification_full { 4 } else { 0 },
				};
				for (class, eligible) in [
					(WorkClass::Preparation, vec![Pool::General]),
					(WorkClass::Survey, vec![Pool::General]),
					(WorkClass::Drilldown, vec![Pool::General]),
					(WorkClass::UrgentDrilldown, vec![Pool::General, Pool::Urgent]),
					(WorkClass::Verification, vec![Pool::General, Pool::Verification]),
					(
						WorkClass::UrgentVerification,
						vec![Pool::General, Pool::Verification, Pool::Urgent],
					),
				] {
					let expected = eligible
						.iter()
						.find(|pool| match pool {
							Pool::General => !general_full,
							Pool::Urgent => !urgent_full,
							Pool::Verification => !verification_full,
						})
						.copied();
					assert_eq!(
						choose_pool(&policy, spent, class).unwrap(),
						match expected {
							Some(pool) => Selection::Pool(pool),
							None => Selection::Refused(
								if general_full && urgent_full && verification_full {
									CapacityRefusal::CampaignBudget
								} else {
									CapacityRefusal::ProtectedCapacity
								}
							),
						}
					);
				}
			}
		}
	}
	for invalid in [
		Spending { general: -1, ..Spending::default() },
		Spending { general: 57, ..Spending::default() },
		Spending { urgent: 5, ..Spending::default() },
		Spending { general: i64::MAX, urgent: 1, ..Spending::default() },
	] {
		assert!(choose_pool(&policy, invalid, WorkClass::Preparation).is_err());
	}
}

#[test]
fn initialization_never_invents_historical_charges_or_uses_tampered_policy() {
	let db = fixture();
	db.with_conn(|conn| {
		assert!(
			transaction::immediate(conn, |tx| initialize(&crate::test_support::scope(tx, 2), 2))
				.is_err(),
			"historical v1/unknown policy never initializes"
		);
		let tx = conn.transaction()?;
		insert_job(&tx, 10, "survey", "normal", true)?;
		assert!(
			initialize(&crate::test_support::scope(&tx, 1), 1).is_err(),
			"nonempty campaigns never backfill"
		);
		tx.rollback()?;
		let tx = conn.transaction()?;
		tx.execute(
			"UPDATE review_campaigns SET effective_policy_digest=zeroblob(32) WHERE campaign_id=1",
			[],
		)?;
		assert!(initialize(&crate::test_support::scope(&tx, 1), 1).is_err());
		tx.rollback()?;
		transaction::immediate(conn, |tx| {
			assert_eq!(initialize(&crate::test_support::scope(tx, 1), 1)?, Spending::default());
			assert_eq!(initialize(&crate::test_support::scope(tx, 1), 1)?, Spending::default());
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn preparation_and_first_lease_charge_once_retries_and_cancellation_never_refund() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		initialize(&crate::test_support::scope(tx, 1),1)?;
		insert_job(tx,10,"survey","normal",true)?;
		assert_eq!(charge(&crate::test_support::scope(tx, 1),10,WorkClass::Preparation,1)?,Charged::Fresh(Pool::General));
		tx.execute("UPDATE jobs SET state='leased',attempts=1 WHERE id=10",[])?;
		assert_eq!(charge(&crate::test_support::scope(tx, 1),10,WorkClass::Survey,2)?,Charged::Replayed(Pool::General));
		tx.execute("UPDATE jobs SET state='cancelled',worker_id=NULL,job_capability_hash=NULL WHERE id=10",[])?;
		assert_eq!(charge(&crate::test_support::scope(tx, 1),10,WorkClass::Survey,3)?,Charged::Replayed(Pool::General));
		insert_job(tx,11,"drilldown","high",false)?;
		assert_eq!(charge(&crate::test_support::scope(tx, 1),11,WorkClass::Drilldown,4)?,Charged::Fresh(Pool::General));
		tx.execute("UPDATE jobs SET attempts=3 WHERE id=11",[])?;
		assert_eq!(charge(&crate::test_support::scope(tx, 1),11,WorkClass::Drilldown,4)?,Charged::Replayed(Pool::General));
		assert_eq!(get_spending(&crate::test_support::scope(tx, 1),1)?.unwrap().total()?,2);
		tx.execute("DELETE FROM jobs WHERE id IN(10,11)",[])?;
		assert_eq!(get_spending(&crate::test_support::scope(tx, 1),1)?.unwrap().total()?,2);
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM job_admission_charges",[],|row|row.get::<_,i64>(0))?,0);
		assert!(tx.execute("UPDATE campaign_admission_spending SET general_spent=0",[]).is_err());
		Ok(())
	})).unwrap();
}

#[test]
fn late_urgent_and_verification_use_protected_pools_without_raising_total() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			initialize(&crate::test_support::scope(tx, 1), 1)?;
			for id in 10..66 {
				insert_job(tx, id, "survey", "normal", false)?;
				assert_eq!(
					charge(&crate::test_support::scope(tx, 1), id, WorkClass::Survey, 1)?,
					Charged::Fresh(Pool::General)
				);
			}
			insert_job(tx, 70, "drilldown", "normal", false)?;
			assert_eq!(
				charge(&crate::test_support::scope(tx, 1), 70, WorkClass::Drilldown, 1)?,
				Charged::Refused(CapacityRefusal::ProtectedCapacity)
			);
			for id in 71..75 {
				insert_job(tx, id, "verify", "urgent", false)?;
				assert_eq!(
					charge(
						&crate::test_support::scope(tx, 1),
						id,
						WorkClass::UrgentVerification,
						1
					)?,
					Charged::Fresh(Pool::Verification)
				);
			}
			insert_job(tx, 75, "verify", "normal", false)?;
			assert_eq!(
				charge(&crate::test_support::scope(tx, 1), 75, WorkClass::Verification, 1)?,
				Charged::Refused(CapacityRefusal::ProtectedCapacity)
			);
			for id in 76..80 {
				insert_job(tx, id, "drilldown", "urgent", false)?;
				assert_eq!(
					charge(&crate::test_support::scope(tx, 1), id, WorkClass::UrgentDrilldown, 1)?,
					Charged::Fresh(Pool::Urgent)
				);
			}
			insert_job(tx, 80, "verify", "urgent", false)?;
			assert_eq!(
				charge(&crate::test_support::scope(tx, 1), 80, WorkClass::UrgentVerification, 1)?,
				Charged::Refused(CapacityRefusal::CampaignBudget)
			);
			assert_eq!(
				get_spending(&crate::test_support::scope(tx, 1), 1)?.unwrap(),
				Spending { general: 56, urgent: 4, verification: 4 }
			);
			tx.execute("UPDATE jobs SET state='queued',attempts=2 WHERE id=10", [])?;
			assert_eq!(
				charge(&crate::test_support::scope(tx, 1), 10, WorkClass::Survey, 1)?,
				Charged::Replayed(Pool::General)
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn wrong_class_and_speculative_or_expired_children_never_consume_capacity() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			initialize(&crate::test_support::scope(tx, 1), 1)?;
			insert_job(tx, 10, "drilldown", "normal", false)?;
			assert!(charge(&crate::test_support::scope(tx, 1), 10, WorkClass::UrgentDrilldown, 1)
				.is_err());
			assert!(
				charge(&crate::test_support::scope(tx, 1), 10, WorkClass::Verification, 1).is_err()
			);
			assert!(
				charge(&crate::test_support::scope(tx, 1), 10, WorkClass::Preparation, 1).is_err()
			);
			assert!(
				charge(&crate::test_support::scope(tx, 1), 10, WorkClass::Drilldown, 101).is_err()
			);
			insert_job(tx, 11, "verify", "normal", true)?;
			assert!(
				charge(&crate::test_support::scope(tx, 1), 11, WorkClass::Verification, 1).is_err()
			);
			tx.execute("UPDATE jobs SET state='leased',attempts=2 WHERE id=11", [])?;
			assert!(
				charge(&crate::test_support::scope(tx, 1), 11, WorkClass::Verification, 1).is_err(),
				"unknown historical attempt must not create its first charge"
			);
			// The composite campaign ownership FK rejects this even before the
			// accounting guard; do not disable it to fabricate a reachable row.
			assert!(tx.execute("UPDATE jobs SET repo_id=2 WHERE id=10", []).is_err());
			assert_eq!(
				get_spending(&crate::test_support::scope(tx, 1), 1)?.unwrap(),
				Spending::default()
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn failed_admission_rolls_back_job_and_charge_including_terminal_cancellation() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| initialize(&crate::test_support::scope(tx, 1), 1))?;
		let result: Result<()> = transaction::immediate(conn, |tx| {
			insert_job(tx, 10, "survey", "normal", false)?;
			charge(&crate::test_support::scope(tx, 1), 10, WorkClass::Survey, 1)?;
			Err(Error::Conflict(Conflict::Assignment))
		});
		assert!(result.is_err());
		transaction::immediate(conn, |tx| {
			assert_eq!(
				get_spending(&crate::test_support::scope(tx, 1), 1)?.unwrap(),
				Spending::default()
			);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE id=10", [], |row| row
					.get::<_, i64>(0))?,
				0
			);
			insert_job(tx, 11, "survey", "normal", false)?;
			tx.execute("UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1", [])?;
			assert!(charge(&crate::test_support::scope(tx, 1), 11, WorkClass::Survey, 1).is_err());
			assert_eq!(
				get_spending(&crate::test_support::scope(tx, 1), 1)?.unwrap(),
				Spending::default()
			);
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn spending_survives_restart_and_concurrent_last_slot_claims() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("admission.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(
		&db,
		&CampaignPolicyV2 {
			campaign_max_jobs: 1,
			campaign_urgent_reserve: 0,
			campaign_verification_reserve: 0,
			..CampaignPolicyV2::default()
		},
	);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| initialize(&crate::test_support::scope(tx, 1), 1))
	})
	.unwrap();
	drop(db);
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let handles: Vec<_> = (10..12)
		.map(|id| {
			let db = Db::open(&path, &key).unwrap();
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				barrier.wait();
				db.with_conn(|conn| {
					transaction::immediate(conn, |tx| {
						insert_job(tx, id, "survey", "normal", false)?;
						match charge(&crate::test_support::scope(tx, 1), id, WorkClass::Survey, 1)?
						{
							Charged::Fresh(_) => Ok(true),
							Charged::Refused(_) => Err(Error::Conflict(Conflict::CampaignBudget)),
							Charged::Replayed(_) => panic!("new jobs cannot replay"),
						}
					})
				})
				.is_ok()
			})
		})
		.collect();
	assert_eq!(
		handles.into_iter().map(|handle| handle.join().unwrap()).filter(|won| *won).count(),
		1
	);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(get_spending(&crate::test_support::scope(tx, 1), 1)?.unwrap().total()?, 1);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=1", [], |row| row
					.get::<_, i64>(0))?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn exact_lease_expiry_is_admissible_but_elapsed_leases_are_not() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let scope = crate::test_support::scope(tx, 1);
			initialize(&scope, 1)?;
			insert_job(tx, 10, "drilldown", "normal", false)?;
			assert_eq!(
				charge(&scope, 10, WorkClass::Drilldown, 100).ok(),
				Some(Charged::Fresh(Pool::General)),
				"exact lease expiry remains valid under landed lease policy"
			);
			insert_job(tx, 11, "drilldown", "normal", false)?;
			assert!(charge(&scope, 11, WorkClass::Drilldown, 101).is_err());
			assert_eq!(get_spending(&scope, 1)?.unwrap().total()?, 1);
			Ok(())
		})
	})
	.unwrap();
}

fn malformed_lease_cannot_charge(mutation: &str) {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let scope = crate::test_support::scope(tx, 1);
			initialize(&scope, 1)?;
			insert_job(tx, 10, "drilldown", "normal", false)?;
			insert_job(tx, 11, "drilldown", "normal", false)?;
			tx.execute(mutation, [])?;
			assert_eq!(
				charge(&scope, 11, WorkClass::Drilldown, 100)?,
				Charged::Fresh(Pool::General),
				"an integer expiry at now and genuine 32-byte BLOB capability remain valid"
			);
			let denied = charge(&scope, 10, WorkClass::Drilldown, 100);
			assert!(
				matches!(denied, Err(Error::Conflict(Conflict::JobState))),
				"malformed stored lease must not consume admission capacity: {denied:?}"
			);
			assert_eq!(get_spending(&scope, 1)?.unwrap().total()?, 1);
			assert_eq!(
				tx.query_row(
					"SELECT COUNT(*) FROM job_admission_charges WHERE job_id=10",
					[],
					|row| row.get::<_, i64>(0)
				)?,
				0
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn fresh_charge_rejects_blob_expiry() {
	malformed_lease_cannot_charge("UPDATE jobs SET lease_expires_at=x'00' WHERE id=10");
}

#[test]
fn fresh_charge_rejects_text_expiry() {
	malformed_lease_cannot_charge("UPDATE jobs SET lease_expires_at='not-an-expiry' WHERE id=10");
}

#[test]
fn fresh_charge_rejects_text_capability() {
	malformed_lease_cannot_charge(
		"UPDATE jobs SET job_capability_hash='0123456789abcdef0123456789abcdef' WHERE id=10",
	);
}

#[test]
fn upgrade_admission_accepts_only_exact_v2_policy_bytes() {
	let db = fixture();
	let valid = db.with_conn(|conn| crate::campaigns::validate_stored_rows(conn));
	assert!(valid.is_ok(), "upgrade admission must retain valid frozen v2 policies: {valid:?}");
	let canonical =
		String::from_utf8(CampaignPolicyV2::default().canonical_bytes().unwrap()).unwrap();
	let mut missing: serde_json::Value = serde_json::from_str(&canonical).unwrap();
	missing.as_object_mut().unwrap().remove("survey_token_budget");
	for (raw, wrong_digest) in [
		("broken JSON".to_owned(), false),
		(format!(" {canonical}"), false),
		(canonical.replacen('{', "{\"version\":2,", 1), false),
		(missing.to_string(), false),
		(canonical, true),
	] {
		let db = fixture();
		db.with_conn(|conn| {
			let digest = if wrong_digest { [0; 32] } else { loupe_core::canonical::digest(raw.as_bytes()) };
			conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2 WHERE campaign_id=1", params![raw,digest.as_slice()])?;
			assert!(crate::campaigns::validate_stored_rows(conn).is_err(), "malformed retained policy must be refused");
			assert!(load_policy(&crate::test_support::scope(conn, 1), 1).is_err());
			Ok(())
		}).unwrap();
	}
}

#[test]
fn public_admission_is_repository_scoped_and_mutations_require_operator() {
	use crate::scope::{with_active_lease, with_operator_repository, OperatorTarget};
	let db = fixture();
	let operator = crate::test_support::operator_ingress();
	with_operator_repository(&db, &operator, OperatorTarget::Repository(1), |scope| {
		assert_eq!(load_policy(scope, 1)?, CampaignPolicyV2::default());
		initialize(scope, 1)?;
		Ok(())
	})
	.unwrap();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		insert_job(tx, 10, "survey", "normal", false)?;
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,attempts,worker_id,job_capability_hash,lease_expires_at,enqueued_at) VALUES(20,1,'scan','leased',1,1,?1,100,0)", [[99;32].as_slice()])?;
		Ok(())
	})).unwrap();
	with_operator_repository(&db, &operator, OperatorTarget::Repository(2), |scope| {
		assert!(get_spending(scope, 1)?.is_none());
		assert!(matches!(load_policy(scope, 1), Err(Error::NotFound(Entity::Campaign, 1))));
		assert!(matches!(initialize(scope, 1), Err(Error::NotFound(Entity::Campaign, 1))));
		assert!(matches!(
			charge(scope, 10, WorkClass::Survey, 1),
			Err(Error::NotFound(Entity::Job, 10))
		));
		Ok(())
	})
	.unwrap();
	let admitted = with_active_lease(
		&db,
		crate::jobs::ActiveLease {
			identity: crate::jobs::LeaseIdentity {
				job_id: 20,
				worker_id: 1,
				capability_hash: &[99; 32],
			},
			now: 1,
		},
		|assignment| {
			assert!(matches!(initialize(assignment.repo(), 1), Err(Error::ScopeDenied)));
			assert!(matches!(
				charge(assignment.repo(), 10, WorkClass::Survey, 1),
				Err(Error::ScopeDenied)
			));
			assert_eq!(get_spending(assignment.repo(), 1)?, Some(Spending::default()));
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(admitted, Some(()), "the real worker issuer must reach the role denial");
	with_operator_repository(&db, &operator, OperatorTarget::Repository(1), |scope| {
		assert_eq!(charge(scope, 10, WorkClass::Survey, 1)?, Charged::Fresh(Pool::General));
		assert_eq!(get_spending(scope, 1)?.unwrap().total()?, 1);
		Ok(())
	})
	.unwrap();
}
