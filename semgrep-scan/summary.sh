#!/usr/bin/env bash
# Append a Semgrep summary section to the GitHub step summary.
set -euo pipefail

: "${RESULTS_FILE:?RESULTS_FILE must be set}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY must be set (provided by GitHub runner)}"

ERRORS="${ERRORS:-0}"
WARNINGS="${WARNINGS:-0}"
INFOS="${INFOS:-0}"
TOTAL="${TOTAL:-0}"

for var in ERRORS WARNINGS INFOS TOTAL; do
  val="${!var}"
  if ! printf '%s' "$val" | grep -qE '^[0-9]+$'; then
    printf -v "$var" '%s' '0'
  fi
done

{
  printf '## Semgrep Scan Results\n\n'
  printf '| Severity | Count |\n'
  printf '|----------|-------|\n'
  printf '| **ERROR** | %s |\n' "$ERRORS"
  printf '| **WARNING** | %s |\n' "$WARNINGS"
  printf '| **INFO** | %s |\n' "$INFOS"
  printf '| **Total** | %s |\n\n' "$TOTAL"

  if [ "$TOTAL" -gt 0 ] && [ -s "$RESULTS_FILE" ]; then
    # Show ERROR + WARNING findings as a flat table (file:line, rule, message snippet).
    printf '### Findings (ERROR + WARNING)\n\n'
    printf '| Severity | File:Line | Rule | Message |\n'
    printf '|----------|-----------|------|---------|\n'
    jq -r '
      [.results[] | select(.extra.severity == "ERROR" or .extra.severity == "WARNING")]
      | sort_by(.extra.severity | if . == "ERROR" then 0 else 1 end)
      | .[] | "| \(.extra.severity) | \(.path):\(.start.line) | \(.check_id | split(".") | last) | \((.extra.message // "" | gsub("\\|"; "\\\\|") | gsub("\\n"; " "))[:200]) |"
    ' "$RESULTS_FILE" 2>/dev/null || printf '| - | - | - | (failed to render) |\n'
    printf '\n'

    info_count="$INFOS"
    if [ "$info_count" -gt 0 ]; then
      printf '<details><summary>INFO findings (%s)</summary>\n\n' "$info_count"
      printf '| File:Line | Rule | Message |\n'
      printf '|-----------|------|---------|\n'
      jq -r '
        [.results[] | select(.extra.severity == "INFO")]
        | .[] | "| \(.path):\(.start.line) | \(.check_id | split(".") | last) | \((.extra.message // "" | gsub("\\|"; "\\\\|") | gsub("\\n"; " "))[:200]) |"
      ' "$RESULTS_FILE" 2>/dev/null || printf '| - | - | (failed to render) |\n'
      printf '\n</details>\n\n'
    fi
  fi
} >> "$GITHUB_STEP_SUMMARY"
