#!/usr/bin/env bash
# Render the Semgrep PR comment body into an artifact directory. The
# privileged post step (post-pr-comment, run via workflow_run) reads this
# artifact and posts the comment, so this script must NOT post anything.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"

sanitise() {
  printf '%s' "${1:-}" | tr -c 'A-Za-z0-9._/-' '_'
}

valid_int_or_zero() {
  if printf '%s' "${1:-}" | grep -qE '^[0-9]+$'; then
    printf '%s' "$1"
  else
    printf '0'
  fi
}

PRODUCT_NAME_RAW="${PRODUCT_NAME_INPUT:-}"
if [ -z "$PRODUCT_NAME_RAW" ]; then
  PRODUCT_NAME_RAW="${DEFAULT_PRODUCT_NAME:-unknown}"
fi
PRODUCT_NAME="$(sanitise "$PRODUCT_NAME_RAW")"

GIT_SHA_RAW="${GIT_SHA:-}"
if printf '%s' "$GIT_SHA_RAW" | grep -qE '^[0-9a-f]{7,40}$'; then
  SHORT_SHA="${GIT_SHA_RAW:0:7}"
else
  SHORT_SHA='unknown'
fi

PR_NUMBER_RAW="${PR_NUMBER:-}"
if ! printf '%s' "$PR_NUMBER_RAW" | grep -qE '^[0-9]+$'; then
  echo "::error::PR_NUMBER must be a positive integer, got: '$PR_NUMBER_RAW'"
  exit 1
fi

SCAN_RESULT="$(sanitise "${SCAN_RESULT:-skipped}")"
ERRORS="$(valid_int_or_zero "${ERRORS:-0}")"
WARNINGS="$(valid_int_or_zero "${WARNINGS:-0}")"
INFOS="$(valid_int_or_zero "${INFOS:-0}")"
TOTAL="$(valid_int_or_zero "${TOTAL:-0}")"

OUT_DIR="$RUNNER_TEMP/pr-comment-semgrep"
BODY_FILE="$OUT_DIR/body.md"
PR_FILE="$OUT_DIR/pr-number.txt"
MARKER_FILE="$OUT_DIR/marker.txt"

mkdir -p "$OUT_DIR"
printf '%s\n' "$PR_NUMBER_RAW" > "$PR_FILE"
printf '%s\n' '## Semgrep Scan Results' > "$MARKER_FILE"

{
  printf '## Semgrep Scan Results\n\n'
  printf '**Repository:** `%s` | **Commit:** `%s`\n\n' "$PRODUCT_NAME" "$SHORT_SHA"
  printf '| Check | Status | Details |\n'
  printf '|-------|--------|---------|\n'

  case "$SCAN_RESULT" in
    success)
      if [ "$ERRORS" -gt 0 ]; then
        printf '| :rotating_light: Semgrep | **ERROR** | %s error(s), %s warning(s), %s total |\n' "$ERRORS" "$WARNINGS" "$TOTAL"
      elif [ "$WARNINGS" -gt 0 ]; then
        printf '| :warning: Semgrep | Warning | %s warning(s), %s total |\n' "$WARNINGS" "$TOTAL"
      else
        printf '| :white_check_mark: Semgrep | Pass | %s total findings (no error/warning) |\n' "$TOTAL"
      fi
      ;;
    failure)
      printf '| :x: Semgrep | Failed | Check workflow logs |\n'
      ;;
    *)
      printf '| :fast_forward: Semgrep | Skipped | - |\n'
      ;;
  esac

  printf '\n*Scanned at %s*\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
} > "$BODY_FILE"

printf 'Generated Semgrep PR comment body:\n'
cat -- "$BODY_FILE"
