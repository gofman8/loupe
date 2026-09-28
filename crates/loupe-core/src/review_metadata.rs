//! Exact review identifiers shared by wire and durable storage owners. Each
//! owner admits its actual input source; these policies confer no authority.

use crate::text::{IdentPolicy, Identifier};

// debug-ok: policy marker with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitPolicy;
impl IdentPolicy for CommitPolicy {
	const FIELD: &'static str = "commit_sha";
	const MAX_LEN: usize = 64;
	fn accepts(value: &str) -> bool {
		crate::inventory_manifest::is_git_oid(value)
	}
}

// debug-ok: policy marker with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestPolicy;
impl IdentPolicy for DigestPolicy {
	const FIELD: &'static str = "digest";
	const MAX_LEN: usize = 64;
	fn accepts(value: &str) -> bool {
		value.len() == 64
			&& value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	}
}

pub type ReviewCommit<S> = Identifier<CommitPolicy, S>;
pub type ReviewDigest<S> = Identifier<DigestPolicy, S>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn identifiers_keep_the_existing_exact_lowercase_hex_policies() {
		for length in [0, 1, 39, 40, 41, 63, 64, 65] {
			assert_eq!(CommitPolicy::accepts(&"a".repeat(length)), matches!(length, 40 | 64));
			assert_eq!(DigestPolicy::accepts(&"b".repeat(length)), length == 64);
		}
		for raw in ["A".repeat(64), "g".repeat(64), format!("{} ", "a".repeat(63))] {
			assert!(!CommitPolicy::accepts(&raw));
			assert!(!DigestPolicy::accepts(&raw));
		}
		assert!(CommitPolicy::accepts(&"0123456789abcdef".repeat(4)));
		assert!(DigestPolicy::accepts(&"0123456789abcdef".repeat(4)));
	}
}
