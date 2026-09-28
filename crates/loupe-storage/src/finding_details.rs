//! Canonical review identity and verification-attempt provenance.
use loupe_core::review_payload::{FindingEvidenceV1, VerificationTerminalV1};
use loupe_core::text::policy::{Argument, Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection, OptionalExtension};

use crate::identity::Identity;
use crate::review::{classify, is_unique, string_enum};
use crate::scope::{Assignment, Scope, Subject, SubjectKind};
use crate::{ownership, Conflict, Error, Ownership, Result, StoredEvidence};
string_enum!(Confidence { Low=>"low", Medium=>"medium", High=>"high" });
string_enum!(SubmittedRung { L2=>"L2", L3=>"L3" });
string_enum!(EstablishedRung { L2=>"L2", L3=>"L3", L4=>"L4" });
string_enum!(Applicability { Applicable=>"applicable", NotApplicable=>"not_applicable" });
pub struct NewReview<'a, RevisionS: Source> {
	pub finding_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub identity: &'a Identity<Agent>,
	pub l2_argument: &'a BoundedJson<Payload, Agent>,
	pub counterevidence: &'a BoundedText<Argument, Agent>,
	pub assumptions_gaps: &'a BoundedText<Argument, Agent>,
	pub confidence: Confidence,
	pub submitted_rung: SubmittedRung,
	pub origin_lead: Option<i64>,
}
pub struct NewAttempt<'a, RevisionS: Source, NarrativeS: Source> {
	pub verification_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub established_rung: Option<EstablishedRung>,
	pub e2e_applicability: Applicability,
	pub e2e_rationale: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub blocker: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub retry_condition: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub verification_proof: Option<i64>,
	pub terminal_digest: &'a [u8; 32],
}
pub fn insert_review_details<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewReview<'_, RevisionS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::finding(tx, new.finding_id, scope.repo_id, Ownership::Finding)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, scope.repo_id, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result=tx.execute("INSERT INTO finding_review_details (finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18 WHERE EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",params![new.finding_id,scope.repo_id,new.workflow_contract_version,new.profile_version,new.profile_digest.map(|d|d.as_slice()),new.reviewed_commit_sha.expose(),new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.l2_argument.expose(),new.counterevidence.expose(),new.assumptions_gaps.expose(),new.confidence.as_str(),new.submitted_rung.as_str(),new.origin_lead,now,Agent::NAME]);
	review_insert_result(tx, result, scope.repo_id, &fingerprint)
}
pub fn insert_attempt_details<RevisionS: Source, NarrativeS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewAttempt<'_, RevisionS, NarrativeS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::require(tx,"SELECT f.repo_id FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1",[new.verification_id],Scope::repository(scope.repo_id),Ownership::Verification,ownership::repository_row)?;
	if let Some(proof) = new.verification_proof {
		ownership::require(tx,"SELECT repo_id,verification_id FROM verification_proofs WHERE verification_proof_id=?1",[proof],Scope { assignment: Some(Assignment::Verification(new.verification_id)), ..Scope::repository(scope.repo_id) },Ownership::VerificationProof,|r| Ok(Subject { kind: SubjectKind::Assigned(Assignment::Verification(r.get(1)?)), ..Subject::repository(r.get(0)?) }))?;
	}
	if new.e2e_applicability == Applicability::NotApplicable && new.e2e_rationale.is_none() {
		return Err(
			loupe_core::text::Error::new("e2e_rationale", loupe_core::text::Rule::Empty).into()
		);
	}
	tx.execute("INSERT INTO verification_attempt_details (verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12 WHERE EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1 AND f.repo_id=?13)",params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha.expose(),new.established_rung.map(EstablishedRung::as_str),new.e2e_applicability.as_str(),new.e2e_rationale.map(BoundedText::expose),new.blocker.map(BoundedText::expose),new.retry_condition.map(BoundedText::expose),new.verification_proof,new.terminal_digest.as_slice(),now,NarrativeS::NAME,scope.repo_id])
	.map_err(|e| classify(e, "verification_attempt_details.verification_id", Conflict::AttemptDetails))?;
	Ok(())
}

/// Modern evidence is stored once; historical projection fields remain NULL.
pub struct NewReviewEvidence<'a, RevisionS: Source> {
	pub finding_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub identity: &'a Identity<Agent>,
	pub evidence: &'a FindingEvidenceV1<Agent>,
	pub origin_lead: Option<i64>,
}

// debug-ok: narrative members delegate to source-typed redacted owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewEvidence {
	pub finding_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<[u8; 32]>,
	pub reviewed_commit_sha: BoundedText<RevisionText, Db>,
	pub identity: Identity<Agent>,
	pub evidence: FindingEvidenceV1<Agent>,
	pub origin_lead: Option<i64>,
	pub created_at: i64,
}

pub struct NewAttemptEvidence<'a, RevisionS: Source> {
	pub verification_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub evidence: &'a VerificationTerminalV1<Agent>,
}

// debug-ok: narrative members delegate to source-typed redacted owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEvidence {
	pub verification_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: BoundedText<RevisionText, Db>,
	pub evidence: VerificationTerminalV1<Agent>,
	pub created_at: i64,
}

fn review_provenance(
	conn: &Connection, finding: i64, repo: i64, commit: &str, workflow: i64,
) -> Result<()> {
	let valid: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings f JOIN jobs j ON j.id=f.job_id
		 WHERE f.id=?1 AND f.repo_id=?2 AND j.repo_id=?2 AND j.kind='drilldown'
		 AND j.campaign_id IS NOT NULL AND (j.head_sha IS NULL OR j.head_sha=?3)
		 AND (j.workflow_contract_version IS NULL OR j.workflow_contract_version=?4))",
		params![finding, repo, commit, workflow],
		|r| r.get(0),
	)?;
	if !valid {
		return Err(Error::Ownership(Ownership::Finding));
	}
	Ok(())
}

fn evidence_verdict(evidence: &VerificationTerminalV1<Agent>) -> &'static str {
	match evidence {
		VerificationTerminalV1::Verified { .. } => "confirmed",
		VerificationTerminalV1::Rejected { .. } => "dismissed",
		VerificationTerminalV1::Inconclusive { .. } => "inconclusive",
	}
}

fn attempt_provenance(
	conn: &Connection, verification: i64, repo: i64, commit: &str, workflow: i64,
	evidence: &VerificationTerminalV1<Agent>,
) -> Result<()> {
	let valid: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM finding_verifications v
		 JOIN findings f ON f.id=v.finding_id JOIN jobs j ON j.id=v.job_id
		 WHERE v.id=?1 AND f.repo_id=?2 AND j.repo_id=?2
		 AND j.kind='verify' AND j.campaign_id IS NOT NULL AND j.target_finding_id=f.id
		 AND v.verdict=?3 AND (j.head_sha IS NULL OR j.head_sha=?4)
		 AND (j.workflow_contract_version IS NULL OR j.workflow_contract_version=?5))",
		params![verification, repo, evidence_verdict(evidence), commit, workflow],
		|r| r.get(0),
	)?;
	if !valid {
		return Err(Error::Ownership(Ownership::Verification));
	}
	Ok(())
}

/// Store a complete L2 finding argument without using generic JSON normalization.
/// This is evidence persistence, not the finding-promotion transaction.
pub fn insert_review_evidence<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewReviewEvidence<'_, RevisionS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	insert_review_evidence_raw(scope.conn, scope.repo_id, new, now)
}
pub(crate) fn insert_review_evidence_raw<RevisionS: Source>(
	tx: &Connection, repo: i64, new: &NewReviewEvidence<'_, RevisionS>, now: i64,
) -> Result<()> {
	let bytes = new.evidence.canonical_bytes()?;
	review_provenance(
		tx,
		new.finding_id,
		repo,
		new.reviewed_commit_sha.expose(),
		new.workflow_contract_version,
	)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, repo, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result = tx.execute(
		"INSERT INTO finding_review_details
		(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,
		 identity_family,identity_anchor,identity_instance_key,identity_fingerprint,submitted_rung,
		 origin_lead_id,evidence_payload,created_at,source)
		 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'L2',?11,?12,?13,'agent')",
		params![
			new.finding_id,
			repo,
			new.workflow_contract_version,
			new.profile_version,
			new.profile_digest.map(|d| d.as_slice()),
			new.reviewed_commit_sha.expose(),
			new.identity.family.expose(),
			new.identity.anchor.expose(),
			new.identity.instance.as_ref().map(|v| v.expose()),
			fingerprint.as_slice(),
			new.origin_lead,
			std::str::from_utf8(&bytes).map_err(|_| loupe_core::review_payload::Error::Json)?,
			now
		],
	);
	review_insert_result(tx, result, repo, &fingerprint)
}

/// Store independently supplied verification evidence, deriving its digest and
/// checking the already-inserted authoritative verification row.
pub fn insert_attempt_evidence<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewAttemptEvidence<'_, RevisionS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	insert_attempt_evidence_raw(scope.conn, scope.repo_id, new, now)
}
pub(crate) fn insert_attempt_evidence_raw<RevisionS: Source>(
	tx: &Connection, repo: i64, new: &NewAttemptEvidence<'_, RevisionS>, now: i64,
) -> Result<()> {
	let bytes = new.evidence.canonical_bytes()?;
	attempt_provenance(
		tx,
		new.verification_id,
		repo,
		new.checkout_commit_sha.expose(),
		new.workflow_contract_version,
		new.evidence,
	)?;
	tx.execute("INSERT INTO verification_attempt_details
		(verification_id,workflow_contract_version,checkout_commit_sha,terminal_digest,evidence_payload,created_at,source)
		VALUES (?1,?2,?3,?4,?5,?6,'agent')",
		params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha.expose(),
			loupe_core::canonical::digest(&bytes).as_slice(),std::str::from_utf8(&bytes).map_err(|_| loupe_core::review_payload::Error::Json)?,now])
		.map_err(|error|classify(error,"verification_attempt_details.verification_id",Conflict::AttemptDetails))?;
	Ok(())
}

fn review_insert_result(
	tx: &Connection, result: rusqlite::Result<usize>, repo: i64, fingerprint: &[u8; 32],
) -> Result<()> {
	match result {
		Ok(_) => Ok(()),
		Err(error) if is_unique(&error, "finding_review_details.finding_id") => {
			Err(Error::Conflict(Conflict::FindingDetails))
		},
		Err(error)
			if is_unique(
				&error,
				"finding_review_details.repo_id, finding_review_details.identity_fingerprint",
			) =>
		{
			let existing=tx.query_row("SELECT finding_id FROM finding_review_details WHERE repo_id=?1 AND identity_fingerprint=?2",params![repo,fingerprint.as_slice()],|r|r.get(0))?;
			Err(Error::Conflict(Conflict::FindingIdentity(existing)))
		},
		Err(error) => Err(error.into()),
	}
}

pub(crate) fn validate_stored_reviews(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "finding_review_details", REVIEW_COLUMNS, |row| {
		let value = review_row(row)?;
		validate_review_provenance(conn, &value)
	})
}

pub(crate) fn validate_stored_attempts(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(
		conn,
		"verification_attempt_details",
		ATTEMPT_COLUMNS,
		|row| {
			let value = attempt_row(conn, row)?;
			validate_attempt_provenance(conn, &value)
		},
	)
}

const REVIEW_COLUMNS: &str = "finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at,source,evidence_payload";
const ATTEMPT_COLUMNS: &str = "verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at,source,evidence_payload";

fn row_conflict(index: usize, conflict: Conflict) -> rusqlite::Error {
	rusqlite::Error::FromSqlConversionFailure(
		index,
		rusqlite::types::Type::Text,
		Box::new(Error::Conflict(conflict)),
	)
}
fn null(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<bool> {
	Ok(matches!(row.get_ref(index)?, rusqlite::types::ValueRef::Null))
}
fn review_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvidence<ReviewEvidence>> {
	crate::ingress::require_agent_source(r, 17)?;
	let revision = crate::ingress::revision(r, 5)?;
	let identity = Identity {
		family: crate::ingress::family(r, 6)?,
		anchor: crate::ingress::anchor(r, 7)?,
		instance: crate::ingress::optional_instance(r, 8)?,
	};
	let rung = crate::review::parsed::<SubmittedRung>(r, 14)?;
	if null(r, 18)? {
		crate::ingress::agent_payload(r, 10)?;
		crate::ingress::argument(r, 11)?;
		crate::ingress::argument(r, 12)?;
		crate::review::parsed::<Confidence>(r, 13)?;
		return Ok(StoredEvidence::Historical);
	}
	if rung != SubmittedRung::L2 {
		return Err(row_conflict(18, Conflict::FindingDetails));
	}
	for index in 10..=13 {
		if !null(r, index)? {
			return Err(row_conflict(index, Conflict::FindingDetails));
		}
	}
	let evidence = crate::ingress::finding_evidence(r, 18)?;
	if identity.fingerprint().as_slice() != r.get::<_, Vec<u8>>(9)? {
		return Err(row_conflict(9, Conflict::FindingDetails));
	}
	let profile_digest = r
		.get::<_, Option<Vec<u8>>>(4)?
		.map(|bytes| bytes.try_into().map_err(|_| row_conflict(4, Conflict::FindingDetails)))
		.transpose()?;
	Ok(StoredEvidence::Recorded(ReviewEvidence {
		finding_id: r.get(0)?,
		repo_id: r.get(1)?,
		workflow_contract_version: r.get(2)?,
		profile_version: r.get(3)?,
		profile_digest,
		reviewed_commit_sha: revision,
		identity,
		evidence,
		origin_lead: r.get(15)?,
		created_at: r.get(16)?,
	}))
}
fn attempt_row(
	conn: &Connection, r: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredEvidence<AttemptEvidence>> {
	let revision = crate::ingress::revision(r, 2)?;
	if null(r, 12)? {
		crate::ingress::require_known_source(r, 11)?;
		crate::review::optional::<EstablishedRung>(r, 3)?;
		let applicability = crate::review::parsed::<Applicability>(r, 4)?;
		let rationale = crate::ingress::optional_reason(r, 5)?;
		crate::ingress::optional_reason(r, 6)?;
		crate::ingress::optional_reason(r, 7)?;
		if applicability == Applicability::NotApplicable && rationale.is_none() {
			return Err(crate::ingress::missing_value(5, "e2e_rationale"));
		}
		return Ok(StoredEvidence::Historical);
	}
	crate::ingress::require_agent_source(r, 11)?;
	for index in 3..=8 {
		if !null(r, index)? {
			return Err(row_conflict(index, Conflict::AttemptDetails));
		}
	}
	let evidence = crate::ingress::verification_terminal(r, 12)?;
	let digest = evidence
		.canonical_bytes()
		.map(|bytes| loupe_core::canonical::digest(&bytes))
		.map_err(|_| row_conflict(12, Conflict::AttemptDetails))?;
	if digest.as_slice() != r.get::<_, Vec<u8>>(9)? {
		return Err(row_conflict(9, Conflict::AttemptDetails));
	}
	let verification_id = r.get(0)?;
	let repo_id = conn.query_row("SELECT f.repo_id FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1", [verification_id], |r| r.get(0))?;
	Ok(StoredEvidence::Recorded(AttemptEvidence {
		verification_id,
		repo_id,
		workflow_contract_version: r.get(1)?,
		checkout_commit_sha: revision,
		evidence,
		created_at: r.get(10)?,
	}))
}
fn validate_review_provenance(
	conn: &Connection, value: &StoredEvidence<ReviewEvidence>,
) -> Result<()> {
	if let StoredEvidence::Recorded(record) = value {
		review_provenance(
			conn,
			record.finding_id,
			record.repo_id,
			record.reviewed_commit_sha.expose(),
			record.workflow_contract_version,
		)?;
	}
	Ok(())
}
fn validate_attempt_provenance(
	conn: &Connection, value: &StoredEvidence<AttemptEvidence>,
) -> Result<()> {
	if let StoredEvidence::Recorded(record) = value {
		attempt_provenance(
			conn,
			record.verification_id,
			record.repo_id,
			record.checkout_commit_sha.expose(),
			record.workflow_contract_version,
			&record.evidence,
		)?;
	}
	Ok(())
}

pub fn get_review_evidence(
	scope: &crate::scope::RepoScope<'_>, finding: i64,
) -> Result<StoredEvidence<ReviewEvidence>> {
	scope.require_operator()?;
	read_review_evidence(scope, finding)
}

/// Internal projections must first select their exact finding under their own
/// access policy. The original repository filter and row validation stay here.
pub(crate) fn read_review_evidence(
	scope: &crate::scope::RepoScope<'_>, finding: i64,
) -> Result<StoredEvidence<ReviewEvidence>> {
	read_review_evidence_raw(scope.conn, scope.repo_id, finding)
}
pub(crate) fn read_review_evidence_raw(
	conn: &Connection, repo: i64, finding: i64,
) -> Result<StoredEvidence<ReviewEvidence>> {
	let value = conn.query_row(&format!("SELECT {REVIEW_COLUMNS} FROM finding_review_details WHERE finding_id=?1 AND repo_id=?2 AND EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)"), params![finding,repo], review_row).optional()?.unwrap_or(StoredEvidence::Missing);
	validate_review_provenance(conn, &value)?;
	Ok(value)
}
pub fn get_attempt_evidence(
	scope: &crate::scope::RepoScope<'_>, verification: i64,
) -> Result<StoredEvidence<AttemptEvidence>> {
	scope.require_operator()?;
	let conn = scope.conn;
	let value = conn.query_row(&format!("SELECT {ATTEMPT_COLUMNS} FROM verification_attempt_details WHERE verification_id=?1 AND EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1 AND f.repo_id=?2)"), params![verification,scope.repo_id], |r| attempt_row(conn, r)).optional()?.unwrap_or(StoredEvidence::Missing);
	validate_attempt_provenance(conn, &value)?;
	Ok(value)
}
