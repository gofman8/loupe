use super::*;
use crate::{review_tests, transaction, Db};

fn path(raw: &str) -> Result<RepoPath<Worker>> {
	Ok(crate::test_support::worker(raw, |raw, mark| RepoPath::new(mark, raw))?)
}
fn fixture() -> Db {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,2,2,zeroblob(32),0,1);
		INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,raw_path,source_path,manifest_position,git_mode,blob_sha,entry_kind,created_at) VALUES(1,11,'a.rs',CAST('a.rs' AS BLOB),'a.rs',0,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0),(2,11,'b.rs',CAST('b.rs' AS BLOB),'b.rs',1,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0);
		INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_at) VALUES(1,11,'a','A','Review A','[{\"path\":\"a.rs\"}]',1,0),(2,11,'b','B','Review B','[{\"path\":\"b.rs\"}]',1,0),(3,21,'foreign','Foreign','Review A','[{\"path\":\"a.rs\"}]',1,0);
		INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,1,0,1);")?;
		Ok(())
	}).unwrap();
	db
}

#[test]
fn resolution_scopes_exact_identity_before_exposing_revision() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let a = path("a.rs")?;
			let b = path("b.rs")?;
			assert!(resolve(tx, 1, 101, 11, false, &a)?.is_some());
			assert!(resolve(tx, 1, 101, 11, false, &b)?.is_none());
			assert!(resolve(tx, 1, 101, 11, true, &b)?.is_some());
			assert!(resolve(tx, 2, 201, 11, true, &a)?.is_none());
			tx.execute(
				"UPDATE generation_inventory SET manifest_position=NULL WHERE inventory_entry_id=2",
				[],
			)?;
			assert!(resolve(tx, 1, 101, 11, true, &b)?.is_none());
			tx.execute(
				"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
				[],
			)?;
			assert!(resolve(tx, 1, 101, 11, true, &a)?.is_none());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn replacement_validates_all_paths_epochs_generation_and_cas_without_partial_updates() {
	let db = fixture();
	db.with_conn(|conn| {
		let entry=transaction::immediate(conn,|tx|resolve(tx,1,101,11,false,&path("a.rs")?))?.unwrap();
		for mappings in [
			vec![Mapping{unit_id:1,assignment_epoch:1},Mapping{unit_id:2,assignment_epoch:1}],
			vec![Mapping{unit_id:1,assignment_epoch:0}],
			vec![Mapping{unit_id:3,assignment_epoch:1}],
			vec![Mapping{unit_id:1,assignment_epoch:1};2],
		] {
			assert!(transaction::immediate(conn,|tx|replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Mapped,reason:None,mappings:&mappings})).is_err());
			assert_eq!(conn.query_row("SELECT disposition_revision FROM generation_inventory WHERE inventory_entry_id=1",[],|r|r.get::<_,i64>(0))?,0);
		}
		let mappings=[Mapping{unit_id:1,assignment_epoch:1}];
		transaction::immediate(conn,|tx| {
			assert_eq!(replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Mapped,reason:None,mappings:&mappings})?,1);
			Ok(())
		})?;
		assert!(transaction::immediate(conn,|tx|replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Unresolved,reason:None,mappings:&[]})).is_err());
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM generation_inventory_units WHERE inventory_entry_id=1",[],|r|r.get::<_,i64>(0))?,1);
		Ok(())
	}).unwrap();
}

#[test]
fn numeric_receipt_replay_checks_repository_binding_and_strict_shape() {
	let db = fixture();
	let key =
		crate::test_support::worker("receipt", |raw, mark| Identifier::new(mark, raw)).unwrap();
	let path = path("a.rs").unwrap();
	let request = Submission {
		key: &key,
		path: &path,
		digest: &[9; 32],
		expected_revision: 0,
		disposition: Disposition::Unresolved,
		reason: None,
		mappings: &[],
	};
	db.with_conn(|conn| {
  record(conn,1,101,&request,Receipt{inventory_entry_id:1,revision:1},0)?;
  assert_eq!(replay(conn,1,101,&request)?,Some(Receipt{inventory_entry_id:1,revision:1}));
  for raw in [
   r#"{"protocol_version":2,"inventory_entry_id":1,"revision":1}"#.to_string(),
   r#"{"protocol_version":3,"inventory_entry_id":0,"revision":1}"#.to_string(),
   r#"{"protocol_version":3,"inventory_entry_id":1,"revision":0}"#.to_string(),
   r#"{"protocol_version":3,"inventory_entry_id":1,"revision":9223372036854775808}"#.to_string(),
   r#"{"protocol_version":3,"inventory_entry_id":1,"revision":1,"revision":1}"#.to_string(),
   r#"{"protocol_version":3,"inventory_entry_id":1,"revision":1,"secret":"private"}"#.to_string(),
   " ".repeat(1025),
  ] {
   conn.execute("UPDATE job_checkpoints SET response=?1 WHERE job_id=101",[raw])?;
   assert!(matches!(replay(conn,1,101,&request),Err(Error::Conflict(Conflict::Checkpoint))));
   assert_eq!(replay(conn,2,101,&request)?,None,"foreign malformed receipt must not decode");
  }
  conn.execute("UPDATE job_checkpoints SET operation='submit_lead',response='malformed' WHERE job_id=101",[])?;
  assert!(matches!(replay(conn,1,101,&request),Err(Error::Conflict(Conflict::Checkpoint))));
  assert_eq!(conn.query_row("SELECT disposition_revision FROM generation_inventory WHERE inventory_entry_id=1",[],|row|row.get::<_,i64>(0))?,0);
  Ok(())
 }).unwrap();
}
