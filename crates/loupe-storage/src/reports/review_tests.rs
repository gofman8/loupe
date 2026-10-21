//! Report provenance is selected from retained evidence, never agent markers.
use super::*;
use crate::findings::tests::{fixture, sample};
use crate::scope::{with_operator_repository, OperatorTarget};

fn selected(db: &Db, id: i64) -> Box<PreparedReport> {
	match with_operator_repository(
		db,
		&crate::test_support::operator_ingress(),
		OperatorTarget::Finding(id),
		|scope| prepare_operator(scope, id),
	)
	.unwrap()
	{
		Preparation::Ready(batch) => batch,
		_ => panic!("confirmed finding must produce a selected report"),
	}
}

fn finding(db: &Db, repo: i64, job: i64) -> i64 {
	db.with_conn(|conn| {
		let mut finding = sample("review:v1:spoof");
		finding.scanner_id = crate::test_support::text("llm-code-review").unwrap();
		let id = crate::findings::insert_or_ignore(conn, repo, job, &finding, false, 0)?.unwrap();
		conn.execute("UPDATE findings SET state='confirmed' WHERE id=?1", [id])?;
		conn.execute("UPDATE jobs SET head_sha='legacy-head' WHERE id=?1", [job])?;
		Ok(id)
	})
	.unwrap()
}

fn phase(db: &Db, repo: i64, job: i64) {
	db.with_conn(|conn| {
		conn.execute("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,state,effective_policy,effective_policy_digest,created_at) VALUES(1,?1,'bootstrap','manual','retained-head','active','{}',zeroblob(32),0)", [repo])?;
		conn.execute("UPDATE jobs SET campaign_id=1,kind='drilldown',head_sha=NULL,workflow_contract_version=1 WHERE id=?1", [job])?;
		Ok(())
	}).unwrap();
}

fn details(db: &Db, repo: i64, id: i64, modern: bool) {
	let identity = crate::identity::Identity {
		family: crate::test_support::identifier("allocation").unwrap(),
		anchor: crate::test_support::anchor("request allocator").unwrap(),
		instance: None,
	};
	db.with_conn(|conn| {
		conn.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at,source,evidence_payload) VALUES(?1,?2,1,1,'retained-head','allocation','request allocator',?3,?4,?5,?5,?6,'L2',0,'agent',?7)", params![id,repo,identity.fingerprint().as_slice(),(!modern).then_some("{}"),(!modern).then_some("historical evidence"),(!modern).then_some("medium"),modern.then(||String::from_utf8(crate::evidence_tests::evidence().canonical_bytes().unwrap()).unwrap())])?;
		Ok(())
	}).unwrap();
}

fn retained_review_revision_survives_missing_job_head(modern: bool) {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	phase(&db, repo, job);
	details(&db, repo, id, modern);
	let batch = selected(&db, id);
	let report = batch.entries()[0].content().unwrap();
	assert_eq!(
		report.reviewed_revision().map(BoundedText::expose),
		Some("retained-head"),
		"retained review evidence, not the nullable job head, owns the report revision"
	);
	assert_eq!(report.finding().scanner_id.expose(), "llm-code-review");
	assert_eq!(report.finding().fingerprint.expose(), "review:v1:spoof");
}

#[test]
fn historical_review_revision_survives_missing_job_head() {
	retained_review_revision_survives_missing_job_head(false);
}

#[test]
fn modern_review_revision_survives_missing_job_head() {
	retained_review_revision_survives_missing_job_head(true);
}

#[test]
fn campaign_finding_without_evidence_never_falls_back_to_legacy() {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	phase(&db, repo, job);
	assert!(
		selected(&db, id).entries()[0].content().is_err(),
		"campaign findings without retained evidence must not become legacy reports"
	);
}

fn invalid_evidence_is_not_reported(mutation: &str) {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	phase(&db, repo, job);
	details(&db, repo, id, true);
	db.with_conn(|conn| {
		conn.execute_batch(mutation)?;
		Ok(())
	})
	.unwrap();
	assert!(
		selected(&db, id).entries()[0].content().is_err(),
		"invalid retained evidence must not fall back to a job revision: {mutation}"
	);
}

#[test]
fn malformed_evidence_is_not_silently_reported() {
	invalid_evidence_is_not_reported("UPDATE finding_review_details SET evidence_payload='{}'");
}

#[test]
fn mislabelled_evidence_is_not_silently_reported() {
	invalid_evidence_is_not_reported("UPDATE finding_review_details SET source='repo'");
}

#[test]
fn evidence_identity_mismatch_is_not_silently_reported() {
	invalid_evidence_is_not_reported(
		"UPDATE finding_review_details SET identity_fingerprint=zeroblob(32)",
	);
}

#[test]
fn evidence_commit_mismatch_is_not_silently_reported() {
	invalid_evidence_is_not_reported("UPDATE jobs SET head_sha='different-head'");
}

#[test]
fn agent_markers_do_not_select_phase_layout() {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	let batch = selected(&db, id);
	let report = batch.entries()[0].content().unwrap();
	assert!(!report.is_phase_review());
	assert_eq!(report.reviewed_revision().unwrap().expose(), "legacy-head");
}

#[test]
fn phase_report_is_an_immutable_committed_selection() {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	phase(&db, repo, job);
	details(&db, repo, id, true);
	let mut batch = selected(&db, id);
	let original = batch.entries()[0].content().unwrap().finding().clone();
	db.with_conn(|conn| {
		conn.execute("UPDATE finding_review_details SET reviewed_commit_sha='later-revision' WHERE finding_id=?1", [id])?;
		conn.execute("UPDATE findings SET title='later-title' WHERE id=?1", [id])?;
		Ok(())
	}).unwrap();
	let report = batch.entries()[0].content().unwrap();
	assert!(report.is_phase_review());
	assert_eq!(report.finding(), &original);
	assert_eq!(report.reviewed_revision().unwrap().expose(), "retained-head");
	batch.mark_one(&db, id, 3).unwrap();
	assert_eq!(
		db.with_conn(|conn| Ok(crate::findings::get_raw(conn, id)?.unwrap().state)).unwrap(),
		FindingState::Reported
	);
}

#[test]
fn foreign_review_is_filtered_before_evidence_decoding() {
	let (db, repo, job) = fixture();
	let id = finding(&db, repo, job);
	phase(&db, repo, job);
	details(&db, repo, id, true);
	db.with_conn(|conn| {
		conn.execute("UPDATE finding_review_details SET evidence_payload='malformed private evidence'", [])?;
		conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(99,'foreign','example.com','foreign','repo','{\"kind\":\"email\",\"to\":[\"to\"]}',0)", [])?;
		Ok(())
	}).unwrap();
	with_operator_repository(
		&db,
		&crate::test_support::operator_ingress(),
		OperatorTarget::Repository(99),
		|scope| {
			assert!(matches!(
				crate::finding_details::read_review_evidence(scope, id)?,
				crate::StoredEvidence::Missing
			));
			assert!(
				matches!(prepare_operator(scope, id)?, Preparation::NoReport),
				"foreign input must not enter or poison this selection"
			);
			Ok(())
		},
	)
	.unwrap();
}
