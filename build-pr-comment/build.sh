#!/usr/bin/env bash
# Render the PR comment body into an artifact directory. The PRIVILEGED post
# step (post-pr-comment, run from a workflow_run trigger) reads this artifact
# and posts the comment, so this script must NOT post anything itself.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"

# All inputs are passed via env. Treat them as untrusted strings; sanitise.
sanitise() {
  # Allow only [A-Za-z0-9._/-]; replace anything else with '_'.
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

SECRET_RESULT="$(sanitise "${SECRET_RESULT:-skipped}")"
SBOM_RESULT="$(sanitise "${SBOM_RESULT:-skipped}")"
SECRET_HAS_FINDINGS="${SECRET_HAS_FINDINGS:-false}"
SECRET_FINDINGS_COUNT="$(valid_int_or_zero "${SECRET_FINDINGS_COUNT:-0}")"
SBOM_COMPONENT_COUNT="$(valid_int_or_zero "${SBOM_COMPONENT_COUNT:-0}")"
T_CRITICAL="$(valid_int_or_zero "${T_CRITICAL:-0}")"
T_HIGH="$(valid_int_or_zero "${T_HIGH:-0}")"
T_TOTAL="$(valid_int_or_zero "${T_TOTAL:-0}")"
G_CRITICAL="$(valid_int_or_zero "${G_CRITICAL:-0}")"
G_HIGH="$(valid_int_or_zero "${G_HIGH:-0}")"
G_TOTAL="$(valid_int_or_zero "${G_TOTAL:-0}")"

OUT_DIR="$RUNNER_TEMP/pr-comment"
BODY_FILE="$OUT_DIR/body.md"
PR_FILE="$OUT_DIR/pr-number.txt"

mkdir -p "$OUT_DIR"
printf '%s\n' "$PR_NUMBER_RAW" > "$PR_FILE"

{
  printf '## Security Scan Results\n\n'
  printf '**Repository:** `%s` | **Commit:** `%s`\n\n' "$PRODUCT_NAME" "$SHORT_SHA"
  printf '| Check | Status | Details |\n'
  printf '|-------|--------|---------|\n'

  # --- Secret scan row ---
  case "$SECRET_RESULT" in
    success)
      if [ "$SECRET_HAS_FINDINGS" = 'true' ]; then
        printf '| :rotating_light: Secret Scan | **SECRETS FOUND** | %s potential secret(s) detected |\n' "$SECRET_FINDINGS_COUNT"
      else
        printf '| :white_check_mark: Secret Scan | Pass | No secrets detected |\n'
      fi
      ;;
    failure)
      printf '| :x: Secret Scan | Failed | Check workflow logs |\n'
      ;;
    *)
      printf '| :fast_forward: Secret Scan | Skipped | - |\n'
      ;;
  esac

  # --- Dependency scan rows ---
  case "$SBOM_RESULT" in
    success)
      max_critical=$((T_CRITICAL > G_CRITICAL ? T_CRITICAL : G_CRITICAL))
      max_high=$((T_HIGH > G_HIGH ? T_HIGH : G_HIGH))

      if [ "$max_critical" -gt 0 ]; then
        printf '| :rotating_light: Dependencies (Trivy) | **Critical** | %s critical, %s high, %s total |\n' "$T_CRITICAL" "$T_HIGH" "$T_TOTAL"
        printf '| :rotating_light: Dependencies (Grype) | **Critical** | %s critical, %s high, %s total |\n' "$G_CRITICAL" "$G_HIGH" "$G_TOTAL"
      elif [ "$max_high" -gt 0 ]; then
        printf '| :warning: Dependencies (Trivy) | High | %s high, %s total |\n' "$T_HIGH" "$T_TOTAL"
        printf '| :warning: Dependencies (Grype) | High | %s high, %s total |\n' "$G_HIGH" "$G_TOTAL"
      else
        printf '| :white_check_mark: Dependencies (Trivy) | Pass | %s total (no critical/high) |\n' "$T_TOTAL"
        printf '| :white_check_mark: Dependencies (Grype) | Pass | %s total (no critical/high) |\n' "$G_TOTAL"
      fi
      printf '| :package: SBOM | Generated | %s components (CycloneDX) |\n' "$SBOM_COMPONENT_COUNT"
      ;;
    failure)
      printf '| :x: Dependencies | Failed | Check workflow logs |\n'
      ;;
    *)
      printf '| :fast_forward: Dependencies | Skipped | - |\n'
      ;;
  esac

  printf '\n*Scanned at %s*\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
} > "$BODY_FILE"

printf 'Generated PR comment body:\n'
cat -- "$BODY_FILE"
