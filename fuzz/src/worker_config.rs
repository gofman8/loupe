//! Raw TOML bytes pass through the actual path-based loader and validation.
//! The fixture parent is absolute; relative TLS/cache paths must resolve there.

use loupe_worker::config::{fuzzing, FileConfig, WorkerConfig, WorkerConfigOverrides};
use loupe_worker::sandbox::SandboxNetworkMode;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 128 * 1024 {
		return;
	}
	let fixture = tempfile::tempdir().unwrap_or_else(|_| panic!("create config fixture"));
	let path = fixture.path().join("worker.toml");
	std::fs::write(&path, data).unwrap_or_else(|_| panic!("write config fixture"));
	let loaded = WorkerConfig::load(Some(&path), WorkerConfigOverrides::default());
	let parsed = FileConfig::load(&path);
	let Ok(file) = parsed else {
		assert!(loaded.is_err());
		return;
	};
	for value in
		[&file.tls.ca_cert, &file.tls.cert, &file.tls.key, &file.cache.dir].into_iter().flatten()
	{
		assert!(value.is_absolute(), "config path was not resolved against its absolute parent");
	}
	let Ok(config) = fuzzing::merge(file) else {
		assert!(loaded.is_err());
		return;
	};
	let expected = allowed(&config);
	assert_eq!(
		fuzzing::validate(&config).is_ok(),
		expected,
		"worker config validation differs from oracle"
	);
	assert_eq!(loaded.is_ok(), expected, "config load skipped or changed validation");
	if let Ok(loaded) = loaded {
		assert!(allowed(&loaded));
		assert!(loaded.cache.dir.is_absolute());
		for value in [&loaded.tls.ca_cert, &loaded.tls.cert, &loaded.tls.key].into_iter().flatten()
		{
			assert!(value.is_absolute());
		}
	}
}

fn allowed(config: &WorkerConfig) -> bool {
	let url = url::Url::parse(&config.bkb.api_url).ok();
	let bkb = url.as_ref().is_some_and(|url| {
		["http", "https"].contains(&url.scheme())
			&& url.host_str().is_some_and(crate::worker_network_host::allowed)
	});
	!config.agents.claude.model.trim().is_empty()
		&& !config.agents.codex.model.trim().is_empty()
		&& ["low", "medium", "high", "xhigh", "max"].contains(&config.agents.claude.effort.as_str())
		&& ["none", "low", "medium", "high", "xhigh"].contains(&config.agents.codex.effort.as_str())
		&& ["trace", "debug", "info", "warn", "error"].contains(&config.logging.level.as_str())
		&& config.cache.max_gb > 0
		&& config.scanner_defaults.max_concurrent_files > 0
		&& config.scanner_defaults.max_file_bytes > 0
		&& config.scanner_defaults.per_request_timeout.as_secs() > 0
		&& (config.sandbox.mode == SandboxNetworkMode::Allowlist
			|| config.sandbox.allowlist.is_empty())
		&& config.sandbox.allowlist.iter().all(|host| crate::worker_network_host::allowed(host))
		&& bkb
		&& config.broker.request_ceiling > 0
		&& config.broker.output_ceiling_bytes > 0
		&& config.broker.token_ceiling != Some(0)
}

pub fn worker_config_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_config_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
