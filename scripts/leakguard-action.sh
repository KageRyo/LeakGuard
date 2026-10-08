#!/usr/bin/env bash
set -Eeuo pipefail
fail() { printf '%s\n' "LeakGuard Action error: $1" >&2; exit 2; }
trap 'fail "download, checksum or setup failed"' ERR
[[ "${RUNNER_OS:-}" == Linux && "${RUNNER_ARCH:-}" == X64 ]] || fail 'only Linux x86_64 runners are supported'
[[ -n "${GITHUB_ACTION_PATH:-}" ]] || fail 'missing Action directory'
version=$(<"$GITHUB_ACTION_PATH/action-version.txt")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'invalid Action version'
mode=${INPUT_MODE:-tracked}
paths=${INPUT_PATHS:-}
[[ -z "$paths" || "$mode" == tracked ]] || fail 'explicit paths cannot be combined with a Git mode'
[[ "$mode" == diff || -z "${INPUT_BASE:-}" ]] || fail 'base is only valid in diff mode'
args=(scan --format "${INPUT_FORMAT:-annotations}" --fail-on "${INPUT_FAIL_ON:-high}" --max-file-bytes "${INPUT_MAX_FILE_BYTES:-10485760}")
case "$mode" in
  tracked) ;;
  staged) args+=(--staged) ;;
  history) args+=(--history) ;;
  diff) [[ -n "${INPUT_BASE:-}" ]] || fail 'diff mode requires base'; args+=("--diff=$INPUT_BASE") ;;
  *) fail 'invalid scan mode' ;;
esac
if [[ -n "${INPUT_OUTPUT:-}" ]]; then args+=(--output "$INPUT_OUTPUT"); fi
if [[ -n "${INPUT_CONFIG:-}" ]]; then args+=("--config=$INPUT_CONFIG"); fi
if [[ -n "$paths" ]]; then
  args+=(--)
  while IFS= read -r path || [[ -n "$path" ]]; do
    [[ -z "$path" ]] || args+=("$path")
  done <<< "$paths"
fi
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/leakguard.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
archive="leakguard-v$version-x86_64-unknown-linux-gnu.tar.gz"
# Override exists only for local integration testing, not as an Action input.
base_url=${LEAKGUARD_RELEASE_BASE_URL:-https://github.com/KageRyo/LeakGuard/releases/download}
curl --fail --silent --show-error --location --output "$scratch/$archive" "$base_url/v$version/$archive"
curl --fail --silent --show-error --location --output "$scratch/SHA256SUMS" "$base_url/v$version/SHA256SUMS"
expected=$(awk -v name="$archive" '$2 == name {print $1}' "$scratch/SHA256SUMS")
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'missing or invalid checksum entry'
actual=$(sha256sum "$scratch/$archive")
[[ "${actual%% *}" == "${expected,,}" ]] || fail 'release archive checksum mismatch'
# Releases contain exactly one top-level executable. Reject other archive layouts.
[[ "$(tar -tzf "$scratch/$archive")" == leakguard ]] || fail 'unexpected release archive layout'
tar -xzf "$scratch/$archive" -C "$scratch" --no-same-owner --no-same-permissions
[[ -f "$scratch/leakguard" && ! -L "$scratch/leakguard" ]] || fail 'release executable is not a regular file'
chmod +x "$scratch/leakguard"
[[ "$("$scratch/leakguard" --version)" == "leakguard $version" ]] || fail 'release executable version mismatch'
# A scanner finding is an expected exit 1; setup failures remain exit 2.
trap - ERR
set +e
"$scratch/leakguard" "${args[@]}"
status=$?
set -e
case "$status" in 0|1|2) exit "$status" ;; *) fail 'scanner terminated unexpectedly' ;; esac
