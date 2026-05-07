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
# Container, not leaked credentials. TruffleHog's --exclude-paths takes
# Go regex patterns (NOT globs); each is substring-matched against the
# full file path the scanner sees (e.g. `/repo/.sc/secrets.yaml`), so
# patterns are intentionally UNanchored — they match the relevant
# fragment anywhere in the path.
{
  echo '\.sc/secrets\.yaml'
  echo '\.sc/stacks/[^/]+/secrets\.yaml'
} > "$EXCLUDE_FILE"

# Append consumer-supplied extra excludes (one regex per line).
# TruffleHog patterns are Go regex, not glob — use `\.` for literal
# dot, `[^/]+` for "one path segment", `.*` for "anything". Patterns
# are substring-matched against the full path the scanner sees, so
# leading `^` anchors are usually wrong (the container path begins
# with `/repo/`); end-anchor `$` works fine.
# Examples:
#   docs/.*\.md$           (md files anywhere under docs/)
#   /testdata/             (any path containing /testdata/)
#   _test\.go$             (Go test files)
#
# Validation REJECTS lines containing shell-control characters
# (`;`, `&`, backtick, `$(`) or control bytes as defence-in-depth.
# Regex metacharacters are otherwise allowed.
if [ -n "${EXTRA_EXCLUDES:-}" ]; then
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    if printf '%s' "$line" | LC_ALL=C grep -qE '[`;&]|\$\('; then
      echo "::error::EXTRA_EXCLUDES line contains shell-control characters: '$line'"
      exit 1
    fi
    if printf '%s' "$line" | LC_ALL=C grep -qP '[\x00-\x1f]'; then
      echo "::error::EXTRA_EXCLUDES line contains control characters: '$line'"
      exit 1
    fi
    printf '%s\n' "$line" >> "$EXCLUDE_FILE"
  done <<< "$EXTRA_EXCLUDES"
fi

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
  --exclude-detectors=FormBucket \
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
