//! Lossless, streaming format-1 inventory identity shared by host and server.
//!
//! Entries retain the source of their exact Git observations. Their digest is
//! source-neutral, so the host and server can compare the same manifest.
//! ```compile_fail,E0308
//! use loupe_core::inventory_manifest::ManifestEntry;
//! use loupe_provenance::{Repo, Worker};
//! fn relabel(entry: ManifestEntry<Worker>) -> ManifestEntry<Repo> { entry }
//! ```

use std::marker::PhantomData;

use loupe_provenance::{Mark, Source};

use crate::text::{IdentPolicy, Identifier};

pub const MAX_ENTRIES: u64 = 1_000_000;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CHUNK_ENTRIES: usize = 4096;
pub const MAX_CHUNK_BYTES: u64 = 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 64 * 1024;

pub struct ManifestEntry<S: Source> {
	raw_path: Vec<u8>,
	git_mode: u32,
	object_id: String,
	source: PhantomData<S>,
}
record_impls!(ManifestEntry { raw_path, git_mode, object_id, source });

pub fn is_git_oid(value: &str) -> bool {
	matches!(value.len(), 40 | 64)
		&& value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Gitlink entries name commits; every other supported mode names a blob.
pub fn is_submodule_mode(mode: u32) -> Result<bool, &'static str> {
	match mode {
		0o100644 | 0o100755 | 0o120000 => Ok(false),
		0o160000 => Ok(true),
		_ => Err("unsupported inventory mode"),
	}
}

fn oid_bytes(value: &str) -> Result<Vec<u8>, &'static str> {
	if !is_git_oid(value) {
		return Err("invalid inventory object id");
	}
	Ok(hex_bytes(value))
}

// Callers first enforce lowercase, even-length hex and the appropriate cap.
fn hex_bytes(value: &str) -> Vec<u8> {
	fn digit(byte: u8) -> u8 {
		if byte <= b'9' {
			byte - b'0'
		} else {
			byte - b'a' + 10
		}
	}
	value
		.as_bytes()
		.as_chunks::<2>()
		.0
		.iter()
		.map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
		.collect()
}

impl<S: Source> ManifestEntry<S> {
	/// Admit original Git/SQLite observations under their actual input mark.
	pub fn new(
		_mark: &Mark<'_, S>, raw_path: &[u8], git_mode: u32, object_id: &str,
	) -> Result<Self, &'static str> {
		Self::from_parts(raw_path, git_mode, object_id)
	}

	/// Compose already labelled wire identifiers without minting a new source.
	/// The identifier policies are not trusted to enforce manifest semantics.
	pub fn from_encoded<P: IdentPolicy, Q: IdentPolicy>(
		raw_path_hex: &Identifier<P, S>, git_mode: u32, object_id: &Identifier<Q, S>,
	) -> Result<Self, &'static str> {
		let raw = raw_path_hex.expose();
		if raw.is_empty()
			|| raw.len() > MAX_PATH_BYTES * 2
			|| !raw.len().is_multiple_of(2)
			|| !raw.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
		{
			return Err("invalid raw inventory path encoding");
		}
		Self::from_parts(&hex_bytes(raw), git_mode, object_id.expose())
	}

	fn from_parts(raw_path: &[u8], git_mode: u32, object_id: &str) -> Result<Self, &'static str> {
		if raw_path.is_empty()
			|| raw_path.len() > MAX_PATH_BYTES
			|| raw_path.contains(&0)
			|| raw_path
				.split(|byte| *byte == b'/')
				.any(|part| part.is_empty() || part == b"." || part == b"..")
		{
			return Err("invalid raw inventory path");
		}
		is_submodule_mode(git_mode)?;
		if !is_git_oid(object_id) {
			return Err("invalid inventory object id");
		}
		Ok(Self {
			raw_path: raw_path.to_vec(),
			git_mode,
			object_id: object_id.to_owned(),
			source: PhantomData,
		})
	}

	pub fn raw_path(&self) -> &[u8] {
		&self.raw_path
	}
	pub fn git_mode(&self) -> u32 {
		self.git_mode
	}
	pub fn object_id(&self) -> &str {
		&self.object_id
	}
	/// Exact, validated persistence projection, never a percent-decoded alias.
	pub fn source_path(&self) -> Option<&str> {
		let text = std::str::from_utf8(&self.raw_path).ok()?;
		crate::text::checked::path(text).ok()?;
		Some(text)
	}
	/// Visible persistence rendering. Raw identity remains in this source owner.
	pub fn display_path(&self) -> std::borrow::Cow<'_, str> {
		if let Some(path) = self.source_path() {
			return std::borrow::Cow::Borrowed(path);
		}
		let mut rendering = String::new();
		for &byte in &self.raw_path {
			if (0x20..=0x7e).contains(&byte) {
				rendering.push(char::from(byte));
			} else {
				use std::fmt::Write;
				#[expect(
					clippy::expect_used,
					reason = "formatting one u8 into an owned String has no fallible writer or custom formatter"
				)]
				write!(&mut rendering, "%{byte:02X}").expect("writing a String");
			}
		}
		std::borrow::Cow::Owned(rendering)
	}
	pub fn canonical_len(&self) -> Result<u64, &'static str> {
		Ok(4 + self.raw_path.len() as u64 + 4 + 1 + self.object_id.len() as u64 / 2)
	}
}

pub struct ManifestHasher {
	hasher: blake3::Hasher,
	expected: u64,
	received: u64,
	bytes: u64,
	previous: Option<Vec<u8>>,
}

impl ManifestHasher {
	pub fn new(commit: &str, expected: u64) -> Result<Self, &'static str> {
		if expected > MAX_ENTRIES {
			return Err("inventory entry limit exceeded");
		}
		let commit = oid_bytes(commit)?;
		let mut hasher = blake3::Hasher::new();
		hasher.update(b"loupe.inventory.v1\0");
		hasher.update(&[commit.len() as u8]);
		hasher.update(&commit);
		hasher.update(&expected.to_be_bytes());
		Ok(Self { hasher, expected, received: 0, bytes: 0, previous: None })
	}

	pub fn push<S: Source>(&mut self, entry: &ManifestEntry<S>) -> Result<(), &'static str> {
		let len = entry.canonical_len()?;
		if self.received >= self.expected
			|| self.previous.as_ref().is_some_and(|previous| previous >= &entry.raw_path)
		{
			return Err("inventory is not an ordered complete set");
		}
		let bytes = self
			.bytes
			.checked_add(len)
			.filter(|bytes| *bytes <= MAX_BYTES)
			.ok_or("inventory byte limit exceeded")?;
		let oid = oid_bytes(&entry.object_id)?;
		self.hasher.update(&(entry.raw_path.len() as u32).to_be_bytes());
		self.hasher.update(&entry.raw_path);
		self.hasher.update(&entry.git_mode.to_be_bytes());
		self.hasher.update(&[oid.len() as u8]);
		self.hasher.update(&oid);
		self.received += 1;
		self.bytes = bytes;
		self.previous = Some(entry.raw_path.clone());
		Ok(())
	}

	pub fn bytes(&self) -> u64 {
		self.bytes
	}

	pub fn finish(self) -> Result<[u8; 32], &'static str> {
		if self.received != self.expected {
			return Err("incomplete inventory");
		}
		Ok(*self.hasher.finalize().as_bytes())
	}
}

#[cfg(test)]
mod tests {
	use loupe_provenance::Agent;

	use super::*;

	// Deliberately weaker than the wire policies: the manifest owner must
	// independently reject malformed encodings, modes, paths and object IDs.
	struct LoosePolicy;
	impl IdentPolicy for LoosePolicy {
		const FIELD: &'static str = "manifest_fixture";
		const MAX_LEN: usize = MAX_PATH_BYTES * 2 + 2;
		fn accepts(_: &str) -> bool {
			true
		}
	}
	fn encoded(raw: &str, mode: u32, oid: &str) -> Result<ManifestEntry<Agent>, &'static str> {
		let raw = crate::test_support::identifier::<LoosePolicy>(raw).unwrap();
		let oid = crate::test_support::identifier::<LoosePolicy>(oid).unwrap();
		ManifestEntry::from_encoded(&raw, mode, &oid)
	}
	fn entry(raw: &[u8], mode: u32, oid: &str) -> Result<ManifestEntry<Agent>, &'static str> {
		let hex: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
		encoded(&hex, mode, oid)
	}

	#[test]
	fn diagnostics_do_not_reveal_manifest_contents() {
		let entry = entry(b"private-manifest-path", 0o100644, &"a1".repeat(20)).unwrap();
		let diagnostic = format!("{entry:?}");
		assert!(!diagnostic.contains(&entry.object_id), "object id escaped manifest diagnostics");
		assert!(
			!diagnostic.contains(&format!("{:?}", entry.raw_path)),
			"raw path escaped manifest diagnostics"
		);
	}

	#[test]
	fn format_is_exact_and_lossless() {
		let entry = entry(&[b'a', 0xff], 0o100644, &"22".repeat(20)).unwrap();
		let mut hasher = ManifestHasher::new(&"11".repeat(20), 1).unwrap();
		hasher.push(&entry).unwrap();
		assert_eq!(hasher.bytes(), 31);
		let mut exact = b"loupe.inventory.v1\0".to_vec();
		exact.push(20);
		exact.extend([0x11; 20]);
		exact.extend(1u64.to_be_bytes());
		exact.extend(2u32.to_be_bytes());
		exact.extend([b'a', 0xff]);
		exact.extend(0o100644u32.to_be_bytes());
		exact.push(20);
		exact.extend([0x22; 20]);
		assert_eq!(hasher.finish().unwrap(), *blake3::hash(&exact).as_bytes());
	}

	#[test]
	fn refuses_invalid_paths_modes_oids_and_incomplete_or_unordered_sets() {
		let oid = "22".repeat(32);
		// Empty raw input cannot enter through Identifier; exercise the common
		// marked-constructor admission directly, before an owned entry exists.
		assert!(ManifestEntry::<Agent>::from_parts(b"", 0o100644, &oid).is_err());
		for path in [b"/a".as_slice(), b"a/", b"a//b", b"a/../b", b"a/./b", b"a\0"] {
			assert!(entry(path, 0o100644, &oid).is_err());
		}
		assert!(entry(b"a", 0o040000, &oid).is_err());
		assert!(entry(b"a", 0o100644, &"AB".repeat(20)).is_err());
		for raw in ["0", "AA", "gg"] {
			assert!(encoded(raw, 0o100644, &oid).is_err());
		}
		assert!(entry(&vec![b'a'; MAX_PATH_BYTES], 0o100644, &oid).is_ok());
		assert!(entry(&vec![b'a'; MAX_PATH_BYTES + 1], 0o100644, &oid).is_err());
		let entry = entry(b"a", 0o100644, &oid).unwrap();
		let mut hasher = ManifestHasher::new(&"11".repeat(32), 2).unwrap();
		hasher.push(&entry).unwrap();
		assert!(hasher.push(&entry).is_err());
		assert!(hasher.finish().is_err());
		assert!(ManifestHasher::new(&"11".repeat(20), 0).unwrap().finish().is_ok());
	}

	#[test]
	fn raw_identity_never_uses_display_or_unicode_normalization() {
		let oid = "22".repeat(20);
		let paths = [b"a\xff".as_slice(), b"a%FF", b"e\xcc\x81", b"\xc3\xa9", b"a\\b"];
		let mut digests = Vec::new();
		for path in paths {
			let entry = entry(path, 0o100644, &oid).unwrap();
			assert_eq!(entry.raw_path(), path);
			let mut hasher = ManifestHasher::new(&oid, 1).unwrap();
			hasher.push(&entry).unwrap();
			let digest = hasher.finish().unwrap();
			assert!(!digests.contains(&digest));
			digests.push(digest);
		}
	}

	#[test]
	fn persistence_projections_preserve_exact_paths_and_visible_exclusions() {
		let oid = "22".repeat(20);
		for path in ["bad%FF.rs", "e\u{301}.rs", "é.rs"] {
			let entry = entry(path.as_bytes(), 0o100644, &oid).unwrap();
			assert_eq!(entry.source_path(), Some(path));
			assert_eq!(entry.display_path(), path);
		}
		for (path, display) in
			[(b"bad\xff.rs".as_slice(), "bad%FF.rs"), (b"a\\b", "a\\b"), (b"a\nb", "a%0Ab")]
		{
			let entry = entry(path, 0o100644, &oid).unwrap();
			assert_eq!(entry.source_path(), None);
			assert_eq!(entry.display_path(), display);
			assert_eq!(entry.raw_path(), path);
		}
	}

	#[test]
	fn rejected_push_does_not_change_stream_state() {
		let oid = "22".repeat(20);
		let a = entry(b"a", 0o100644, &oid).unwrap();
		let b = entry(b"b", 0o160000, &oid).unwrap();
		let mut retry = ManifestHasher::new(&oid, 2).unwrap();
		retry.push(&a).unwrap();
		let bytes = retry.bytes();
		assert!(retry.push(&a).is_err());
		assert_eq!(retry.bytes(), bytes);
		retry.push(&b).unwrap();
		assert!(retry.push(&b).is_err());
		let mut exact = ManifestHasher::new(&oid, 2).unwrap();
		exact.push(&a).unwrap();
		exact.push(&b).unwrap();
		assert_eq!(retry.finish().unwrap(), exact.finish().unwrap());
	}

	#[test]
	fn source_markers_add_no_incidental_trait_bounds() {
		fn traits<S: Source>() {
			fn check<T: Clone + Eq + std::fmt::Debug>() {}
			check::<ManifestEntry<S>>();
		}
		traits::<Agent>();
	}
}
