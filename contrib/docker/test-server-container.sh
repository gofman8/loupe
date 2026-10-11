#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin" "$scratch/data"

cat > "$scratch/bin/scp" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${!#}" == *.conf ]]; then cp "$1" "$TEST_SCRATCH/captured.conf"; fi
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

config='/var/lib/loupe/server config.toml'
env -i PATH="$scratch/bin:$PATH" TEST_SCRATCH="$scratch" \
	LOUPE_CONFIG="$config" LOUPE_SERVER_SSH=fixture LOUPE_SERVER_IMAGE=fixture \
	LOUPE_SERVER_SECRET_FILE="$scratch/secrets.env" LOUPE_SERVER_DATA_DIR="$scratch/data" \
	LOUPE_MASTER_KEY=test-key LOUPE_SERVER_CERT_PEM_B64=test-cert \
	LOUPE_SERVER_KEY_PEM_B64=test-key LOUPE_CA_CERT_PEM_B64=test-ca \
	LOUPE_CA_KEY_PEM_B64=test-key \
	bash "$root/contrib/docker/deploy-server.sh" > "$scratch/deploy.log"

saved_config=$(bash -c '. "$1"; printf "%s" "${LOUPE_CONFIG-}"' bash "$scratch/captured.conf")
[[ "$saved_config" == "$config" ]] || {
	echo 'deployment lost the server configuration path' >&2
	exit 1
}
touch "$scratch/secrets.env"
env -i PATH="$scratch/bin:$PATH" TEST_SCRATCH="$scratch" \
	LOUPE_CONTAINER_SERVER_CONF="$scratch/captured.conf" \
	LOUPE_SECRET_FILE="$scratch/secrets.env" \
	LOUPE_SERVER_DATA_DIR="$scratch/data" \
	bash "$root/contrib/docker/run-server-container.sh"
grep -Fx -- "LOUPE_CONFIG=$config" "$scratch/podman.args" >/dev/null || {
	echo 'container launcher lost the server configuration path' >&2
	exit 1
}
echo 'server container configuration tests passed'
