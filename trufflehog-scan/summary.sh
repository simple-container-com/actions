#!/usr/bin/env bash
# Append a TruffleHog summary section to the GitHub step summary.
set -euo pipefail

: "${FINDINGS_COUNT:?FINDINGS_COUNT must be set}"
: "${RESULTS_FILE:?RESULTS_FILE must be set}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY must be set (provided by GitHub runner)}"

# Validate findings count is a non-negative integer; if not, treat as zero.
if ! printf '%s' "$FINDINGS_COUNT" | grep -qE '^[0-9]+$'; then
  FINDINGS_COUNT=0
fi

{
  printf '## Secret Scanning Results (TruffleHog)\n\n'
  if [ "$FINDINGS_COUNT" -eq 0 ]; then
    printf '**Status:** No secrets detected\n'
  else
    printf '**Status:** %s potential secret(s) detected\n\n' "$FINDINGS_COUNT"
    printf '<details><summary>View Findings</summary>\n\n'
    printf '```\n'
    if [ -s "$RESULTS_FILE" ]; then
      jq -r '.DetectorName + " in " + .SourceMetadata.Data.Filesystem.file' \
        "$RESULTS_FILE" 2>/dev/null \
        || printf 'See artifacts for details\n'
    else
      printf 'See artifacts for details\n'
    fi
    printf '```\n'
    printf '</details>\n'
  fi
} >> "$GITHUB_STEP_SUMMARY"
