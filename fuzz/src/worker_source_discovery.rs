//! Byte zero selects ordinary/outside/inside symlinks. The remaining bytes
//! are NUL-separated root Cargo.toml, member Cargo.toml and exclusion pattern;
//! bit 3 instead sends every remaining byte verbatim to the root manifest.
//! Every selection uses the production manifest parser, glob rules and walker.
//! A 64 KiB input cap bounds filesystem churn, not the product parser's policy.

use std::fs;
use std::path::Path;

use loupe_worker::scanners::fuzz_source_discovery;

use crate::utils::test_logger;

const PACKAGE: &[u8] = b"[package]\nname=\"fixture\"\nversion=\"0.1.0\"\n";

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let (&mode, bytes) = data.split_first().unwrap_or((&0, &[]));
	let mut fields = bytes.splitn(3, |byte| *byte == 0);
	let (manifest, member, pattern) = if mode & 8 != 0 {
		(bytes, PACKAGE, &[][..])
	} else {
		(
			fields.next().unwrap_or_default(),
			fields.next().unwrap_or(PACKAGE),
			fields.next().unwrap_or_default(),
		)
	};
	let exclude = String::from_utf8_lossy(pattern);
	let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("create discovery fixture"));
	let root = temp.path().join("repo");
	for directory in ["repo/src", "repo/internal", "repo/modules/member/src", "outside"] {
		fs::create_dir_all(temp.path().join(directory))
			.unwrap_or_else(|_| panic!("create discovery directories"));
	}
	write(&root.join("Cargo.toml"), manifest);
	write(&root.join("modules/member/Cargo.toml"), member);
	write(&root.join("modules/member/src/lib.rs"), b"pub fn member() {}\n");
	write(&root.join("src/lib.rs"), b"pub fn local() {}\n");
	write(&root.join("internal/inside.rs"), b"pub fn inside() {}\n");
	write(&root.join("internal/build.rs"), b"fn main() {}\n");
	write(&temp.path().join("outside/secret.rs"), b"private outside source\n");
	write(&temp.path().join("outside/build.rs"), b"private outside build\n");
	#[cfg(unix)]
	{
		use std::os::unix::fs::symlink;
		let destination =
			if mode & 4 == 0 { temp.path().join("outside") } else { root.join("internal") };
		if mode & 1 != 0 {
			fs::remove_dir_all(root.join("src"))
				.unwrap_or_else(|_| panic!("replace source directory"));
			symlink(&destination, root.join("src"))
				.unwrap_or_else(|_| panic!("create source symlink"));
		}
		if mode & 2 != 0 {
			symlink(destination.join("build.rs"), root.join("build.rs"))
				.unwrap_or_else(|_| panic!("create build symlink"));
		}
	}
	#[cfg(not(unix))]
	let _ = mode;

	for path in [root.join("Cargo.toml"), root.join("modules/member/Cargo.toml")] {
		let parsed = fuzz_source_discovery::parse_manifest(&path);
		let workspace = fuzz_source_discovery::workspace_excludes(&path);
		assert_eq!(
			workspace.is_some(),
			parsed.as_ref().and_then(|value| value.get("workspace")).is_some(),
			"workspace presence disagrees with actual manifest"
		);
		if let Some(excludes) = workspace {
			let values = parsed
				.as_ref()
				.and_then(|value| value.get("workspace"))
				.and_then(|value| value.get("exclude"))
				.and_then(|value| value.as_array());
			let expected: Vec<_> =
				values.into_iter().flatten().filter_map(|value| value.as_str()).collect();
			assert_eq!(excludes, expected, "workspace excludes must preserve only string entries");
		}
	}
	let excludes: Vec<_> =
		(!exclude.is_empty()).then(|| exclude.into_owned()).into_iter().collect();
	let selected = fuzz_source_discovery::walk(&root, &excludes);
	#[cfg(unix)]
	if manifest == PACKAGE && member == PACKAGE && excludes.is_empty() {
		let mut expected = vec![root.join("modules/member/src/lib.rs")];
		if mode & 1 == 0 {
			expected.push(root.join("src/lib.rs"));
		} else if mode & 4 != 0 {
			expected.push(root.join("src/inside.rs"));
			expected.push(root.join("src/build.rs"));
		}
		if mode & 2 != 0 && mode & 4 != 0 {
			expected.push(root.join("build.rs"));
		}
		expected.sort();
		assert_eq!(selected, expected, "fixture must retain every legitimate source");
	}
	let canonical_root = root.canonicalize().unwrap_or_else(|_| panic!("canonicalize fixture"));
	for path in &selected {
		assert!(path.starts_with(&root), "selected path has escaped spelling");
		let resolved = path.canonicalize().unwrap_or_else(|_| panic!("resolve selected source"));
		assert!(resolved.starts_with(&canonical_root), "selected source escapes repository");
		assert!(resolved.is_file(), "selected source is not a file");
		assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("rs"));
	}
	assert!(selected.windows(2).all(|pair| pair[0] < pair[1]), "sources must be sorted and unique");
	assert_eq!(
		selected,
		fuzz_source_discovery::walk(&root, &excludes),
		"discovery must be deterministic"
	);
}

fn write(path: &Path, bytes: &[u8]) {
	fs::write(path, bytes).unwrap_or_else(|_| panic!("write discovery fixture"));
}

pub fn worker_source_discovery_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_source_discovery_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
