#!/usr/bin/env bash
# Exercise deployment and container forwarding without SSH or a container engine.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin" "$scratch/cache"
touch "$scratch/secrets.env" "$scratch/worker.conf"

cat > "$scratch/bin/scp" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${!#}" == *.worker-config ]]; then cp "$1" "$TEST_SCRATCH/worker.toml"; fi
MOCK
cat > "$scratch/bin/ssh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'bash -s'* | *'sudo bash -c'*) cat >/dev/null ;;
esac
MOCK
cat > "$scratch/bin/podman" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$TEST_SCRATCH/podman.args"
MOCK
cat > "$scratch/bin/install" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$scratch/bin/"*

deploy() {
	env -i PATH="$scratch/bin:$PATH" TEST_SCRATCH="$scratch" \
		LOUPE_WORKER_SSH=fixture LOUPE_WORKER_IMAGE=fixture \
		LOUPE_SERVER_URL=https://example.invalid LOUPE_WORKER_START_GRACE_SECONDS=0 \
		LOUPE_WORKER_CA_CERT_PEM_B64=test-ca LOUPE_WORKER_CERT_PEM_B64=test-cert \
		LOUPE_WORKER_KEY_PEM_B64=test-key CODEX_API_KEY=test-key \
		"${mode_env[@]}" bash "$root/contrib/docker/deploy-worker.sh" > "$scratch/deploy.log" 2>&1
}

for mode in unset default off blue red; do
	mode_env=()
	if [[ "$mode" != unset ]]; then mode_env+=("LOUPE_CODEX_DAYBREAK=$mode"); fi
	deploy
	if [[ "$mode" == unset ]]; then
		if grep -q '^daybreak' "$scratch/worker.toml"; then
			echo 'unset Daybreak must preserve Codex defaults' >&2; exit 1
		fi
	else
		grep -Fx "daybreak = \"$mode\"" "$scratch/worker.toml" >/dev/null || {
			echo "deployment lost Daybreak mode $mode" >&2; exit 1
		}
	fi
	# The launcher only checks that TUN is a character device. Bind a harmless
	# fixture inside a private /dev; the stub Podman never starts a container.
	env -i PATH="$scratch/bin:$PATH" TEST_SCRATCH="$scratch" \
		LOUPE_CONTAINER_WORKER_CONF="$scratch/worker.conf" LOUPE_CONTAINER_IMAGE=fixture \
		LOUPE_SECRET_FILE="$scratch/secrets.env" LOUPE_WORKER_CACHE_DIR="$scratch/cache" \
		LOUPE_WORKER_CONFIG_HOST="$scratch/worker.toml" "${mode_env[@]}" \
		bwrap --unshare-user --ro-bind / / --bind "$scratch" "$scratch" \
		--dev /dev --dir /dev/net --dev-bind /dev/null /dev/net/tun \
		bash "$root/contrib/docker/run-worker-container.sh"
	if [[ "$mode" == unset ]]; then
		if grep -q '^LOUPE_CODEX_DAYBREAK=' "$scratch/podman.args"; then
			echo 'container launcher supplied an unset Daybreak override' >&2; exit 1
		fi
	else
		grep -Fx "LOUPE_CODEX_DAYBREAK=$mode" "$scratch/podman.args" >/dev/null || {
			echo "container launcher lost Daybreak mode $mode" >&2; exit 1
		}
	fi
done

for mode in '' true BLUE unknown; do
	mode_env=("LOUPE_CODEX_DAYBREAK=$mode")
	rm "$scratch/worker.toml"
	if deploy; then
		echo 'deployment must reject invalid Daybreak values' >&2; exit 1
	fi
	[[ ! -e "$scratch/worker.toml" ]] || {
		echo 'invalid Daybreak configuration was uploaded' >&2; exit 1
	}
	# Restore the fixture so each iteration starts with an existing file.
	touch "$scratch/worker.toml"
done
echo 'worker Daybreak deployment tests passed'
