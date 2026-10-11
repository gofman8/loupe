//! Typed proof-row persistence, without staging/finalization or garbage collection.
use loupe_core::text::policy::{Label, Payload};
pub use loupe_core::text::policy::{MediaType, OriginalName};
use loupe_core::text::{BoundedJson, BoundedText, Identifier, RepoPath};
use rusqlite::{params, Transaction};
use sha2::{Digest, Sha256};

use crate::review::{is_unique, standalone, string_enum};
use crate::scope::{Assignment, Scope, Subject, SubjectKind};
use crate::{ownership, Ownership, Result};
string_enum!(Role { ReproducerSource=>"reproducer_source", CraftedInput=>"crafted_input", TestPatch=>"test_patch", CommandStdout=>"command_stdout", CommandStderr=>"command_stderr", ExecutionTrace=>"execution_trace" });
string_enum!(Rung { L3=>"L3", L4=>"L4" });
string_enum!(NetworkPolicy { Isolated=>"isolated" });
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkingDirectory {
	Root,
	Directory(RepoPath),
}
impl WorkingDirectory {
	pub fn expose(&self) -> &str {
		match self {
			Self::Root => ".",
			Self::Directory(path) => path.expose(),
		}
	}
}
pub struct NewArtifact<'a> {
	pub repo_id: i64,
	pub blob_id: i64,
	pub role: Role,
	pub media_type: &'a BoundedText<MediaType>,
	pub label: Option<&'a Identifier<Label>>,
	pub original_name: &'a BoundedText<OriginalName>,
	pub produced_by_job: Option<i64>,
}
pub struct NewStagedArtifact<'a> {
	pub repo_id: i64,
	pub job_id: i64,
	pub blob_id: i64,
	pub role: Role,
	pub media_type: &'a BoundedText<MediaType>,
	pub label: Option<&'a Identifier<Label>>,
	pub original_name: &'a BoundedText<OriginalName>,
}
pub struct NewExecution<'a> {
	pub repo_id: i64,
	pub produced_by_job: i64,
	pub target_commit_sha: &'a str,
	pub clean_tree: bool,
	pub argv: &'a BoundedJson<Payload>,
	pub working_dir: &'a WorkingDirectory,
	pub env_names: &'a BoundedJson<Payload>,
	pub fixture_artifact_ids: Option<&'a BoundedJson<Payload>>,
	pub network_policy: NetworkPolicy,
	pub limits: &'a BoundedJson<Payload>,
	pub timeout_seconds: i64,
	pub started_at: i64,
	pub duration_ms: i64,
	pub exit_status: Option<i64>,
	pub term_signal: Option<i64>,
	pub stdout_artifact: Option<i64>,
	pub stderr_artifact: Option<i64>,
	pub output_truncated: bool,
}
pub struct NewProof<'a> {
	pub repo_id: i64,
	pub finding_id: i64,
	pub verification_id: i64,
	pub rung: Rung,
	pub pinned_commit_sha: &'a str,
	pub manifest: &'a BoundedJson<Payload>,
}
/// The capture/transport layer enforces the job's artifact-size budget.
/// Blob identity and length are derived here, never accepted from the agent.
pub fn insert_blob(tx: &Transaction<'_>, repo: i64, content: &[u8], now: i64) -> Result<i64> {
	let hash: [u8; 32] = Sha256::digest(content).into();
	let len = i64::try_from(content.len()).map_err(|_| {
		loupe_core::text::Error::new("artifact_content", loupe_core::text::Rule::Bytes)
	})?;
	match tx.execute("INSERT INTO proof_artifact_blobs (repo_id,sha256,byte_len,content,created_at) VALUES (?1,?2,?3,?4,?5)",params![repo,hash.as_slice(),len,content,now]){
  Ok(_)=>Ok(tx.last_insert_rowid()),
  Err(error) if is_unique(&error,"proof_artifact_blobs.repo_id, proof_artifact_blobs.sha256")=>Ok(tx.query_row("SELECT proof_artifact_blob_id FROM proof_artifact_blobs WHERE repo_id=?1 AND sha256=?2",params![repo,hash.as_slice()],|r|r.get(0))?),
  Err(error)=>Err(error.into())
 }
}
fn blob(tx: &Transaction<'_>, repo: i64, id: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_artifact_blobs WHERE proof_artifact_blob_id=?1",
		[id],
		Scope::repository(repo),
		Ownership::ArtifactBlob,
		ownership::repository_row,
	)
}
fn job(tx: &Transaction<'_>, repo: i64, id: i64, relation: Ownership) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM jobs WHERE id=?1",
		[id],
		Scope::repository(repo),
		relation,
		ownership::repository_row,
	)
}
pub fn insert_artifact(tx: &Transaction<'_>, new: &NewArtifact<'_>, now: i64) -> Result<i64> {
	blob(tx, new.repo_id, new.blob_id)?;
	if let Some(id) = new.produced_by_job {
		job(tx, new.repo_id, id, Ownership::ArtifactJob)?;
	}
	tx.execute("INSERT INTO proof_artifacts (repo_id,proof_artifact_blob_id,artifact_role,media_type,label,original_name,sha256,byte_len,produced_by_job_id,created_at)
 SELECT ?1,?2,?3,?4,?5,?6,sha256,byte_len,?7,?8 FROM proof_artifact_blobs WHERE repo_id=?1 AND proof_artifact_blob_id=?2",params![new.repo_id,new.blob_id,new.role.as_str(),new.media_type.expose(),new.label.map(Identifier::expose),new.original_name.expose(),new.produced_by_job,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_staged_artifact(
	tx: &Transaction<'_>, new: &NewStagedArtifact<'_>, now: i64,
) -> Result<i64> {
	blob(tx, new.repo_id, new.blob_id)?;
	job(tx, new.repo_id, new.job_id, Ownership::ArtifactJob)?;
	tx.execute("INSERT INTO staged_proof_artifacts (job_id,repo_id,proof_artifact_blob_id,artifact_role,media_type,label,original_name,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![new.job_id,new.repo_id,new.blob_id,new.role.as_str(),new.media_type.expose(),new.label.map(Identifier::expose),new.original_name.expose(),now])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_execution(tx: &Transaction<'_>, new: &NewExecution<'_>, now: i64) -> Result<i64> {
	job(tx, new.repo_id, new.produced_by_job, Ownership::ExecutionJob)?;
	for id in [new.stdout_artifact, new.stderr_artifact].into_iter().flatten() {
		ownership::require(
			tx,
			"SELECT repo_id FROM proof_artifacts WHERE proof_artifact_id=?1",
			[id],
			Scope::repository(new.repo_id),
			Ownership::ExecutionArtifact,
			ownership::repository_row,
		)?;
	}
	if let Some(fixtures) = new.fixture_artifact_ids {
		let ids: Vec<i64> = serde_json::from_str(fixtures.expose()).map_err(|_| {
			loupe_core::text::Error::new("fixture_artifact_ids", loupe_core::text::Rule::JsonSyntax)
		})?;
		for id in ids {
			ownership::require(tx,"SELECT repo_id,job_id FROM staged_proof_artifacts WHERE staged_proof_artifact_id=?1",[id],Scope { assignment: Some(Assignment::Job(new.produced_by_job)), ..Scope::repository(new.repo_id) },Ownership::ExecutionArtifact,|r| Ok(Subject { kind: SubjectKind::Assigned(Assignment::Job(r.get(1)?)), ..Subject::repository(r.get(0)?) }))?;
		}
	}
	tx.execute("INSERT INTO proof_executions (repo_id,produced_by_job_id,target_commit_sha,clean_tree,argv,working_dir,env_names,fixture_artifact_ids,network_policy,limits,timeout_seconds,started_at,duration_ms,exit_status,term_signal,stdout_artifact_id,stderr_artifact_id,output_truncated,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",params![new.repo_id,new.produced_by_job,new.target_commit_sha,new.clean_tree,new.argv.expose(),new.working_dir.expose(),new.env_names.expose(),new.fixture_artifact_ids.map(BoundedJson::expose),new.network_policy.as_str(),new.limits.expose(),new.timeout_seconds,new.started_at,new.duration_ms,new.exit_status,new.term_signal,new.stdout_artifact,new.stderr_artifact,new.output_truncated,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_proof(tx: &Transaction<'_>, new: &NewProof<'_>, now: i64) -> Result<i64> {
	ownership::finding(tx, new.finding_id, new.repo_id, Ownership::ProofFinding)?;
	ownership::require(
		tx,
		"SELECT f.repo_id,v.finding_id FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1",
		[new.verification_id],
		Scope { assignment: Some(Assignment::Finding(new.finding_id)), ..Scope::repository(new.repo_id) },
		Ownership::ProofVerification,
		|r| Ok(Subject { kind: SubjectKind::Assigned(Assignment::Finding(r.get(1)?)), ..Subject::repository(r.get(0)?) }),
	)?;
	tx.execute("INSERT INTO verification_proofs (finding_id,verification_id,repo_id,rung,pinned_commit_sha,manifest,manifest_digest,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![new.finding_id,new.verification_id,new.repo_id,new.rung.as_str(),new.pinned_commit_sha,new.manifest.expose(),new.manifest.digest().as_slice(),now])?;
	Ok(tx.last_insert_rowid())
}
pub fn link_artifact(tx: &Transaction<'_>, repo: i64, proof: i64, artifact: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM verification_proofs WHERE verification_proof_id=?1",
		[proof],
		Scope::repository(repo),
		Ownership::ProofArtifact,
		ownership::repository_row,
	)?;
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_artifacts WHERE proof_artifact_id=?1",
		[artifact],
		Scope::repository(repo),
		Ownership::ProofArtifact,
		ownership::repository_row,
	)?;
	tx.execute("INSERT INTO verification_proof_artifacts (repo_id,verification_proof_id,proof_artifact_id) VALUES (?1,?2,?3)",params![repo,proof,artifact])?;
	Ok(())
}
pub fn link_execution(tx: &Transaction<'_>, repo: i64, proof: i64, execution: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM verification_proofs WHERE verification_proof_id=?1",
		[proof],
		Scope::repository(repo),
		Ownership::ProofExecution,
		ownership::repository_row,
	)?;
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_executions WHERE proof_execution_id=?1",
		[execution],
		Scope::repository(repo),
		Ownership::ProofExecution,
		ownership::repository_row,
	)?;
	tx.execute("INSERT INTO verification_proof_executions (repo_id,verification_proof_id,proof_execution_id) VALUES (?1,?2,?3)",params![repo,proof,execution])?;
	Ok(())
}
standalone! {insert_blob(repo:i64,content:&[u8],now:i64)->i64;insert_artifact(new:&NewArtifact<'_>,now:i64)->i64;
insert_staged_artifact(new:&NewStagedArtifact<'_>,now:i64)->i64;insert_execution(new:&NewExecution<'_>,now:i64)->i64;
insert_proof(new:&NewProof<'_>,now:i64)->i64;link_artifact(repo:i64,proof:i64,artifact:i64)->();link_execution(repo:i64,proof:i64,execution:i64)->();}
