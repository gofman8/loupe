#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"
cat > "$scratch/bin/scp" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
cat > "$scratch/bin/ssh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
shift
case "$*" in
  'sudo bash -s -- '*) bash -c "${1#sudo }" ;;
  *'bash -s'* | *'sudo bash -c'*) cat >/dev/null ;;
esac
MOCK
cat > "$scratch/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
polls=$(cat "$TEST_SCRATCH/polls")
case "$*" in
  *InvocationID*)
    if [[ "$TEST_SCENARIO" == restart && "$polls" -gt 0 ]]; then
      echo bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    else
      echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    fi ;;
  *NRestarts*) echo 0 ;;
  'is-active '*) [[ "$TEST_SCENARIO" != failed || "$polls" -eq 0 ]] ;;
esac
MOCK
cat > "$scratch/bin/journalctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *'_SYSTEMD_INVOCATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'* ]] || {
  echo 'readiness must exclude earlier server invocations' >&2
  exit 1
}
polls=$(cat "$TEST_SCRATCH/polls")
polls=$((polls + 1))
echo "$polls" > "$TEST_SCRATCH/polls"
if [[ "$TEST_SCENARIO" == delayed && "$polls" -ge 3 ]]; then
  echo '{"fields":{"message":"loupe-server listening"}}'
else
  echo 'loupe-server: database ready'
fi
MOCK
chmod +x "$scratch/bin/"*

for scenario in delayed failed restart timeout; do
	echo 0 > "$scratch/polls"
	result=0
	start_timeout=3
	if [[ "$scenario" == delayed ]]; then
		# Three polls include two sleeps and subprocess overhead on busy runners.
		# Keep the timeout scenario short without making success race its deadline.
		start_timeout=30
	fi
	env -i PATH="$scratch/bin:$PATH" TEST_SCRATCH="$scratch" TEST_SCENARIO="$scenario" \
		LOUPE_SERVER_SSH=fixture LOUPE_SERVER_IMAGE=fixture \
		LOUPE_SERVER_START_TIMEOUT_SECONDS="$start_timeout" \
		LOUPE_MASTER_KEY=test-key LOUPE_SERVER_CERT_PEM_B64=test-cert \
		LOUPE_SERVER_KEY_PEM_B64=test-key LOUPE_CA_CERT_PEM_B64=test-ca \
		LOUPE_CA_KEY_PEM_B64=test-key \
		bash "$root/contrib/docker/deploy-server.sh" > "$scratch/$scenario.log" 2>&1 || result=$?
	if [[ "$scenario" == delayed ]]; then
		[[ "$result" -eq 0 && "$(cat "$scratch/polls")" -ge 3 ]] || {
			cat "$scratch/$scenario.log" >&2
			echo 'deployment returned before listener readiness' >&2
			exit 1
		}
	else
		[[ "$result" -ne 0 ]] || {
			echo "deployment must fail for $scenario startup" >&2
			exit 1
		}
		if grep -F 'server container deployed' "$scratch/$scenario.log"; then
			echo 'failed startup reported success' >&2
			exit 1
		fi
	fi
done
echo 'server readiness tests passed'
