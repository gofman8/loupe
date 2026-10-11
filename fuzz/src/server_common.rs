use loupe_core::ReportingDestination;
use loupe_storage::repos::RepoRow;

/// Operator-owned repository metadata, independent of every fuzzed finding.
pub fn repo() -> RepoRow {
	RepoRow {
		id: 1,
		clone_url: "https://github.com/example/repo.git".into(),
		host: "github.com".into(),
		owner: "example".into(),
		repo: "repo".into(),
		default_branch: None,
		scan_interval_seconds: None,
		scanner_config: serde_json::Value::Null,
		reporting: ReportingDestination::Manual,
		verification_enabled: false,
		require_approval: None,
		last_scanned_sha: None,
		last_scanned_at: None,
		created_at: 0,
		disabled_at: None,
	}
}
