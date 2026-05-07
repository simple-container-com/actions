#!/usr/bin/env bash
# Append the SBOM + dependency scan severity summary to the GitHub step
# summary. Reads markdown table fragments staged by scan.sh.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY must be set (provided by GitHub runner)}"

OUTPUT_DIR="$RUNNER_TEMP/vuln-scan"

# Defensive: every count must be a non-negative integer; coerce otherwise.
for var in T_CRITICAL T_HIGH T_MEDIUM T_LOW T_UNKNOWN T_TOTAL \
           G_CRITICAL G_HIGH G_MEDIUM G_LOW G_UNKNOWN G_TOTAL; do
  val="${!var:-0}"
  if ! printf '%s' "$val" | grep -qE '^[0-9]+$'; then
    val='0'
  fi
  printf -v "$var" '%s' "$val"
done

{
  printf '## SBOM + Vulnerability Scan Results\n\n'
  printf '### Severity Breakdown\n\n'
  printf '| Scanner | Critical | High | Medium | Low | Unknown | Total |\n'
  printf '|---------|----------|------|--------|-----|---------|-------|\n'
  printf '| **Trivy** | %s | %s | %s | %s | %s | %s |\n' \
    "$T_CRITICAL" "$T_HIGH" "$T_MEDIUM" "$T_LOW" "$T_UNKNOWN" "$T_TOTAL"
  printf '| **Grype** | %s | %s | %s | %s | %s | %s |\n\n' \
    "$G_CRITICAL" "$G_HIGH" "$G_MEDIUM" "$G_LOW" "$G_UNKNOWN" "$G_TOTAL"

  for scanner in trivy grype; do
    case "$scanner" in
      trivy) scanner_title='Trivy' ;;
      grype) scanner_title='Grype' ;;
    esac
    ch_file="$OUTPUT_DIR/${scanner}-critical-high.txt"
    if [ -s "$ch_file" ]; then
      printf '### Critical & High Vulnerabilities (%s)\n\n' "$scanner_title"
      printf '| CVE | Severity | Package | Installed | Fixed |\n'
      printf '|-----|----------|---------|-----------|-------|\n'
      cat -- "$ch_file"
      printf '\n'
    fi
  done

  for scanner in trivy grype; do
    case "$scanner" in
      trivy) scanner_title='Trivy' ;;
      grype) scanner_title='Grype' ;;
    esac
    for sev in medium low; do
      sev_title="${sev^^}"
      f="$OUTPUT_DIR/${scanner}-${sev}.txt"
      if [ -s "$f" ]; then
        count=$(wc -l < "$f")
        printf '<details><summary>%s Vulnerabilities — %s (%s)</summary>\n\n' \
          "$sev_title" "$scanner_title" "$count"
        printf '| CVE | Package | Installed | Fixed |\n'
        printf '|-----|---------|-----------|-------|\n'
        cat -- "$f"
        printf '\n</details>\n\n'
      fi
    done
  done
} >> "$GITHUB_STEP_SUMMARY"
