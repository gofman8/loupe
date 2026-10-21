//! Current ordinary coverage is a read-only derivation, never a repair cache.
//! Named ingress shares canonical typed decoders with evidence reads; SQL owns
//! relational provenance, ownership and manifest checks.
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;

/// Private connection bootstrap; missing registration is a loud SQL error.
pub(crate) fn register(conn: &Connection) -> rusqlite::Result<()> {
	let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
	conn.create_scalar_function("loupe_unit_refs_contain", 3, flags, |ctx| {
		Ok(crate::ingress::coverage::unit_refs_contain(ctx))
	})?;
	conn.create_scalar_function("loupe_review_profile_valid", 3, flags, |ctx| {
		Ok(crate::ingress::coverage::profile_valid(ctx))
	})?;
	conn.create_scalar_function("loupe_unit_result_epoch", 10, flags, |ctx| {
		crate::ingress::coverage::unit_result_epoch(ctx)
	})
}

// Both predicates must remain const &str for the existing SQL consumers. This
// small internal macro avoids a second copy of the current-result relation.
// Retain modern signals independently of content/source validity. When every
// signal is absent, unreadable payloads cannot invent lost provenance: the
// original unmanaged historical compatibility boundary still applies.
macro_rules! managed_generation {
	() => { "(EXISTS(SELECT 1 FROM generation_manifests m WHERE m.generation_id=g.generation_id)
		 OR EXISTS(SELECT 1 FROM review_campaigns c WHERE (c.generation_id=g.generation_id
		  OR EXISTS(SELECT 1 FROM jobs linked WHERE linked.campaign_id=c.campaign_id AND linked.generation_id=g.generation_id))
		  AND (EXISTS(SELECT 1 FROM campaign_admission_spending s WHERE s.campaign_id=c.campaign_id AND s.policy_version>=2)
		   OR CASE WHEN typeof(c.effective_policy)='text' AND json_valid(c.effective_policy)
		    THEN json_extract(c.effective_policy,'$.version')>=2 ELSE 0 END))
		 OR EXISTS(SELECT 1 FROM job_checkpoints cp JOIN jobs j ON j.id=cp.job_id
		  WHERE j.generation_id=g.generation_id AND cp.operation IN('publish_profile','submit_unit_result'))
		 OR EXISTS(SELECT 1 FROM review_unit_results tagged JOIN review_units tu ON tu.review_unit_id=tagged.review_unit_id
		  WHERE tu.generation_id=g.generation_id AND CASE WHEN typeof(tagged.result_payload)='text'
		   AND length(CAST(tagged.result_payload AS BLOB))<=65536 AND json_valid(tagged.result_payload)
		   THEN json_extract(tagged.result_payload,'$.format') LIKE 'loupe.%' ELSE 0 END))" };
}
pub(crate) use managed_generation;

macro_rules! generation_ready {
	() => { "(typeof(g.profile_version)='integer' AND g.profile_version BETWEEN 1 AND 4294967295
		 AND loupe_review_profile_valid(g.generated_profile,g.generated_profile_digest,g.generated_profile_source)
		 AND g.workflow_contract_version=2 AND typeof(g.generation_commit_sha)='text'
		 AND length(g.generation_commit_sha) IN(40,64) AND g.generation_commit_sha NOT GLOB '*[^0-9a-f]*'
		 AND EXISTS(SELECT 1 FROM generation_manifests m WHERE m.generation_id=g.generation_id
		  AND m.format_version=1 AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count))" };
}
pub(crate) use generation_ready;

pub(crate) const GENERATION_READY: &str =
	concat!("CASE WHEN ", managed_generation!(), " THEN ", generation_ready!(), " ELSE 1 END");

macro_rules! ordinary_result {
	($disposition:literal) => { concat!(
		"EXISTS(SELECT 1 FROM review_unit_results r WHERE r.review_unit_id=u.review_unit_id
		AND r.invalidated=0 AND r.commit_sha=g.generation_commit_sha AND r.profile_version=g.profile_version
		AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL
		AND ", $disposition, " AND CASE WHEN ", $crate::review_coverage::managed_generation!(),
		" THEN ", $crate::review_coverage::generation_ready!(), " AND u.stale=0 AND u.status IN('open','deferred')
		 AND loupe_unit_result_epoch(r.result_payload,r.result_digest,r.review_unit_id,r.disposition,
		  r.inspected_refs,r.counterevidence,r.proof_gaps,r.corroborates_review_unit_result_id,r.corroborates_inventory_exclusion_id,r.source)=u.assignment_epoch
		 AND EXISTS(SELECT 1 FROM jobs producer WHERE producer.id=r.produced_by_job_id
		  AND producer.kind='survey' AND producer.repo_id=g.repo_id AND producer.generation_id=g.generation_id
		  AND producer.workflow_contract_version=2 AND producer.head_sha=g.generation_commit_sha
		  AND ((u.created_by_job_id=producer.id AND u.assignment_epoch=0)
		   OR EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=producer.id
		    AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=u.assignment_epoch))
		  AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units other JOIN jobs live ON live.id=other.job_id
		   WHERE other.review_unit_id=u.review_unit_id AND other.job_id<>producer.id AND live.state IN('queued','leased')))
		 AND NOT EXISTS(SELECT 1 FROM json_each(CASE WHEN typeof(r.inspected_refs)='text'
		  AND length(CAST(r.inspected_refs AS BLOB))<=65536 AND json_valid(r.inspected_refs)
		  THEN r.inspected_refs ELSE '[]' END) ref
		  WHERE NOT EXISTS(SELECT 1 FROM generation_inventory i WHERE i.generation_id=g.generation_id
		   AND i.manifest_position IS NOT NULL AND i.source_path=json_extract(CASE WHEN ref.type='object' THEN ref.value ELSE '{}' END,'$.path')))
		ELSE 1 END)"
	) };
}
pub(crate) use ordinary_result;

pub(crate) const UNIT_FOLLOW_UP: &str = ordinary_result!("r.disposition='needs_follow_up'");
