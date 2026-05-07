#!/usr/bin/env bash
# Filesystem secret scan via TruffleHog. Inputs come from env vars set by
# the composite action wrapper (action.yml). All consumer-controlled values
# are validated before they reach docker arguments.
set -euo pipefail

: "${TRUFFLEHOG_IMAGE:?TRUFFLEHOG_IMAGE must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

# Validate that the image reference matches a known-safe shape: registry/path:tag.
# This is defence-in-depth — the action input default is hard-coded — but the
# input is overridable, so reject anything that isn't a plain image:tag.
if ! printf '%s' "$TRUFFLEHOG_IMAGE" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$'; then
  echo "::error::Refusing to use TRUFFLEHOG_IMAGE='$TRUFFLEHOG_IMAGE' — not a plain image:tag reference."
  exit 1
fi

WORK_DIR="$RUNNER_TEMP/trufflehog"
RESULTS_FILE="$WORK_DIR/results.json"
SCAN_ROOT="$WORK_DIR/repo"
EXCLUDE_FILE="$WORK_DIR/exclude-paths.txt"

mkdir -p "$SCAN_ROOT"

# Use git archive HEAD so the scanner sees only tracked content at the current
# checkout — never untracked files, runner artifacts, or the .git directory.
git archive HEAD | tar -x -C "$SCAN_ROOT"

# Exclude SC encrypted secrets — these are ciphertext managed by Simple
# Container, not leaked credentials. Glob is interpreted by TruffleHog.
{
  echo '.sc/secrets.yaml'
  echo '.sc/stacks/*/secrets.yaml'
} > "$EXCLUDE_FILE"

# Run TruffleHog inside Docker. Mount source read-only; mount exclude file
# read-only. We must distinguish three cases:
#   - exit 0   : tool ran fine, parse JSON for findings
#   - exit 183 : tool ran fine, --fail mode found secrets (treated like 0)
#   - other    : infrastructure failure (image pull, TruffleHog crash, …) —
#                MUST fail the job so a broken scan can't masquerade as 0
#                findings.
docker_log="$WORK_DIR/trufflehog.log"
set +e
docker run --rm \
  -v "$SCAN_ROOT:/repo:ro" \
  -v "$EXCLUDE_FILE:/exclude-paths.txt:ro" \
  "$TRUFFLEHOG_IMAGE" \
  filesystem /repo \
  --json \
  --no-update \
  --exclude-paths=/exclude-paths.txt \
  > "$RESULTS_FILE" 2> "$docker_log"
exit_code=$?
set -e
case "$exit_code" in
  0|183) ;;
  *)
    echo "::error::TruffleHog exited with code $exit_code (likely infrastructure error). Logs:"
    cat -- "$docker_log" >&2
    exit 1
    ;;
esac

# TruffleHog emits one JSON object per line. Count via jq -s. A parse failure
# here means the scanner produced garbage — fail the job, don't silently zero.
findings_count=0
if [ -s "$RESULTS_FILE" ]; then
  if ! findings_count=$(jq -s 'length' "$RESULTS_FILE" 2>"$WORK_DIR/jq-err.log"); then
    echo '::error::TruffleHog output is not valid JSON-lines:'
    cat -- "$WORK_DIR/jq-err.log" >&2
    exit 1
  fi
fi

if ! printf '%s' "$findings_count" | grep -qE '^[0-9]+$'; then
  echo "::error::TruffleHog findings count not an integer: '$findings_count'"
  exit 1
fi

has_findings=false
if [ "$findings_count" -gt 0 ]; then
  has_findings=true
fi

{
  printf 'findings-count=%s\n' "$findings_count"
  printf 'has-findings=%s\n' "$has_findings"
  printf 'results-file=%s\n' "$RESULTS_FILE"
} >> "$GITHUB_OUTPUT"

printf 'TruffleHog scan completed. Found %s potential secret(s).\n' "$findings_count"
