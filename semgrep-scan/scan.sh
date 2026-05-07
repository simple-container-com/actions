#!/usr/bin/env bash
# Run Semgrep against the workspace using:
#   - the SC ruleset shipped with this composite action ($ACTION_PATH/rules)
#   - optionally a consumer-supplied rules dir/file (CONSUMER_RULES)
#   - optionally Semgrep registry packs (REGISTRY_PACKS)
#
# Outputs per-severity counts and a JSON results file. Does NOT post comments
# or fail the build by itself — the calling workflow's status job decides.
set -euo pipefail

: "${SEMGREP_IMAGE:?SEMGREP_IMAGE must be set}"
: "${ACTION_PATH:?ACTION_PATH must be set (provided by composite action)}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

CONSUMER_RULES="${CONSUMER_RULES:-}"
REGISTRY_PACKS="${REGISTRY_PACKS:-}"
FAIL_ON_SEVERITY="${FAIL_ON_SEVERITY:-ERROR}"

# Validate image ref shape.
if ! printf '%s' "$SEMGREP_IMAGE" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$'; then
  echo "::error::Refusing SEMGREP_IMAGE='$SEMGREP_IMAGE' — not a plain image:tag reference."
  exit 1
fi

# Validate consumer rules path: relative path with no '..' segments.
if [ -n "$CONSUMER_RULES" ]; then
  case "$CONSUMER_RULES" in
    /*|*..*)
      echo "::error::CONSUMER_RULES must be a relative path with no '..' segments: '$CONSUMER_RULES'"
      exit 1
      ;;
  esac
  if ! printf '%s' "$CONSUMER_RULES" | grep -qE '^[A-Za-z0-9._/-]+$'; then
    echo "::error::CONSUMER_RULES contains forbidden characters: '$CONSUMER_RULES'"
    exit 1
  fi
fi

# Validate registry packs: comma-separated tokens of [A-Za-z0-9._/-].
if [ -n "$REGISTRY_PACKS" ]; then
  if ! printf '%s' "$REGISTRY_PACKS" | grep -qE '^[A-Za-z0-9._/-]+(,[A-Za-z0-9._/-]+)*$'; then
    echo "::error::REGISTRY_PACKS contains forbidden characters: '$REGISTRY_PACKS'"
    exit 1
  fi
fi

# Validate severity threshold.
case "$FAIL_ON_SEVERITY" in
  ERROR|WARNING|INFO) ;;
  *)
    echo "::error::FAIL_ON_SEVERITY must be ERROR / WARNING / INFO, got '$FAIL_ON_SEVERITY'"
    exit 1
    ;;
esac

OUTPUT_DIR="$RUNNER_TEMP/semgrep"
RESULTS_FILE="$OUTPUT_DIR/results.json"
mkdir -p "$OUTPUT_DIR"

# Build --config arguments. Inside the container, $ACTION_PATH is mounted at
# /action and $GITHUB_WORKSPACE at /src.
configs=('--config' '/action/rules')

if [ -n "$CONSUMER_RULES" ]; then
  if [ -e "$GITHUB_WORKSPACE/$CONSUMER_RULES" ]; then
    configs+=('--config' "/src/$CONSUMER_RULES")
    echo "Including consumer rules from: $CONSUMER_RULES"
  else
    echo "::warning::consumer-rules path '$CONSUMER_RULES' not present in workspace; skipping."
  fi
fi

if [ -n "$REGISTRY_PACKS" ]; then
  IFS=',' read -ra packs <<< "$REGISTRY_PACKS"
  for pack in "${packs[@]}"; do
    configs+=('--config' "$pack")
    echo "Including registry pack: $pack"
  done
fi

# Run Semgrep. Mount workspace and action dir read-only; never execute code.
# We deliberately don't pass --error here so the script can capture the JSON
# and emit per-severity outputs; the orchestrator status job decides on fail.
#
# Semgrep exit codes:
#   0  : no findings
#   1  : findings present (treated as success here; status job gates on counts)
#   2+ : config error, parser error, internal bug — MUST fail the job.
SEMGREP_LOG="$OUTPUT_DIR/semgrep.log"
set +e
docker run --rm \
  -v "$GITHUB_WORKSPACE:/src:ro" \
  -v "$ACTION_PATH:/action:ro" \
  -v "$OUTPUT_DIR:/output" \
  -w /src \
  "$SEMGREP_IMAGE" \
  semgrep scan \
  "${configs[@]}" \
  --metrics=off \
  --json \
  --output /output/results.json \
  > "$SEMGREP_LOG" 2>&1
exit_code=$?
set -e

if [ "$exit_code" -gt 1 ]; then
  echo "::error::Semgrep exited with code $exit_code (config / runtime error). Logs:"
  cat -- "$SEMGREP_LOG" >&2
  exit 1
fi

if [ ! -s "$RESULTS_FILE" ]; then
  echo '::error::Semgrep produced no JSON output despite exit code 0/1. Logs:'
  cat -- "$SEMGREP_LOG" >&2
  exit 1
fi

if ! jq -e . "$RESULTS_FILE" >/dev/null 2>&1; then
  echo '::error::Semgrep output is not valid JSON.'
  cat -- "$SEMGREP_LOG" >&2
  exit 1
fi

# Even with a zero exit code, semgrep can report config / parse problems via
# the .errors array in the JSON. Treat a non-empty .errors as a failure so
# silent rule-config issues don't masquerade as a successful zero-finding scan.
errors_in_json=$(jq '.errors | length' "$RESULTS_FILE" 2>/dev/null || printf '0')
if ! printf '%s' "$errors_in_json" | grep -qE '^[0-9]+$'; then
  errors_in_json=0
fi
if [ "$errors_in_json" -gt 0 ]; then
  echo "::error::Semgrep reported $errors_in_json error(s) in results JSON:"
  jq -r '.errors[]? | "\(.type // "error"): \(.message // "(no message)")"' "$RESULTS_FILE" >&2 || true
  exit 1
fi

# Count findings by severity. semgrep marks rule severity as ERROR/WARNING/INFO
# via .extra.severity in JSON output.
errors=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$RESULTS_FILE" 2>/dev/null || printf '0')
warnings=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "$RESULTS_FILE" 2>/dev/null || printf '0')
infos=$(jq '[.results[] | select(.extra.severity == "INFO")] | length' "$RESULTS_FILE" 2>/dev/null || printf '0')
total=$(jq '.results | length' "$RESULTS_FILE" 2>/dev/null || printf '0')

# Defensive normalisation.
for var in errors warnings infos total; do
  val="${!var}"
  if ! printf '%s' "$val" | grep -qE '^[0-9]+$'; then
    printf -v "$var" '%s' '0'
  fi
done

{
  printf 'errors=%s\n' "$errors"
  printf 'warnings=%s\n' "$warnings"
  printf 'infos=%s\n' "$infos"
  printf 'total=%s\n' "$total"
  printf 'results-file=%s\n' "$RESULTS_FILE"
} >> "$GITHUB_OUTPUT"

printf 'Semgrep: %s error(s), %s warning(s), %s info, %s total\n' \
  "$errors" "$warnings" "$infos" "$total"
