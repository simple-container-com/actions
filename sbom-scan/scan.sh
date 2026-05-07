#!/usr/bin/env bash
# Scan a CycloneDX SBOM with Trivy and Grype in parallel. Each scanner runs
# in its own pinned Docker container and writes JSON output to a shared dir.
# The script then parses both outputs to produce per-severity counts on the
# action's outputs and stages markdown table fragments for the summary.
set -euo pipefail

: "${SBOM_FILE:?SBOM_FILE must be set}"
: "${TRIVY_IMAGE:?TRIVY_IMAGE must be set}"
: "${GRYPE_IMAGE:?GRYPE_IMAGE must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

# Validate image refs.
for img_var in TRIVY_IMAGE GRYPE_IMAGE; do
  img_val="${!img_var}"
  if ! printf '%s' "$img_val" | grep -qE '^[a-zA-Z0-9._/-]+:[A-Za-z0-9._-]+(@sha256:[a-f0-9]{64})?$'; then
    echo "::error::Refusing to use $img_var='$img_val' — not a plain image:tag reference."
    exit 1
  fi
done

# Validate the SBOM path exists and resolve to absolute.
if [ ! -f "$SBOM_FILE" ]; then
  echo "::error::SBOM file not found: $SBOM_FILE"
  exit 1
fi
SBOM_ABS="$(cd "$(dirname -- "$SBOM_FILE")" && pwd)/$(basename -- "$SBOM_FILE")"

OUTPUT_DIR="$RUNNER_TEMP/vuln-scan"
TRIVY_JSON="$OUTPUT_DIR/trivy-scan.json"
GRYPE_JSON="$OUTPUT_DIR/grype-scan.json"

mkdir -p "$OUTPUT_DIR"

# Run Trivy in background.
echo 'Starting Trivy scan...'
docker run --rm \
  -v "$SBOM_ABS:/sbom.json:ro" \
  -v "$OUTPUT_DIR:/output" \
  "$TRIVY_IMAGE" \
  sbom /sbom.json \
  --severity 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL' \
  --format json \
  --output /output/trivy-scan.json &
TRIVY_PID=$!

# Run Grype in background.
echo 'Starting Grype scan...'
docker run --rm \
  -v "$SBOM_ABS:/sbom.json:ro" \
  -v "$OUTPUT_DIR:/output" \
  "$GRYPE_IMAGE" \
  "sbom:/sbom.json" \
  -o json \
  --file /output/grype-scan.json &
GRYPE_PID=$!

# Wait for both. Don't error out the script on scanner non-zero — we still
# parse whatever was produced and surface counts.
echo 'Waiting for parallel scans to complete...'
wait "$TRIVY_PID" || echo "::warning::Trivy exited non-zero"
wait "$GRYPE_PID" || echo "::warning::Grype exited non-zero"

# --- Parse Trivy results ---
T_TOTAL=0; T_CRITICAL=0; T_HIGH=0; T_MEDIUM=0; T_LOW=0; T_UNKNOWN=0
if [ -s "$TRIVY_JSON" ]; then
  T_TOTAL=$(jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' "$TRIVY_JSON" 2>/dev/null || printf '0')
  T_CRITICAL=$(jq '[.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "CRITICAL")] | length' "$TRIVY_JSON" 2>/dev/null || printf '0')
  T_HIGH=$(jq '[.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "HIGH")] | length' "$TRIVY_JSON" 2>/dev/null || printf '0')
  T_MEDIUM=$(jq '[.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "MEDIUM")] | length' "$TRIVY_JSON" 2>/dev/null || printf '0')
  T_LOW=$(jq '[.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "LOW")] | length' "$TRIVY_JSON" 2>/dev/null || printf '0')
  T_UNKNOWN=$(jq '[.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "UNKNOWN")] | length' "$TRIVY_JSON" 2>/dev/null || printf '0')
  printf 'Trivy: %s critical, %s high, %s medium, %s low, %s unknown, %s total\n' \
    "$T_CRITICAL" "$T_HIGH" "$T_MEDIUM" "$T_LOW" "$T_UNKNOWN" "$T_TOTAL"

  jq -r '
    [.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "CRITICAL" or .Severity == "HIGH")]
    | sort_by(.Severity | if . == "CRITICAL" then 0 else 1 end)
    | .[] | "| \(.VulnerabilityID) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "n/a") |"
  ' "$TRIVY_JSON" 2>/dev/null > "$OUTPUT_DIR/trivy-critical-high.txt" || true

  jq -r '
    [.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "MEDIUM")]
    | .[] | "| \(.VulnerabilityID) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "n/a") |"
  ' "$TRIVY_JSON" 2>/dev/null > "$OUTPUT_DIR/trivy-medium.txt" || true

  jq -r '
    [.Results[]?.Vulnerabilities // [] | .[] | select(.Severity == "LOW")]
    | .[] | "| \(.VulnerabilityID) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "n/a") |"
  ' "$TRIVY_JSON" 2>/dev/null > "$OUTPUT_DIR/trivy-low.txt" || true
else
  echo "::warning::Trivy scan produced no output"
fi

# --- Parse Grype results ---
G_TOTAL=0; G_CRITICAL=0; G_HIGH=0; G_MEDIUM=0; G_LOW=0; G_UNKNOWN=0
if [ -s "$GRYPE_JSON" ]; then
  G_TOTAL=$(jq '[.matches[]?] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  G_CRITICAL=$(jq '[.matches[]? | select(.vulnerability.severity == "Critical")] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  G_HIGH=$(jq '[.matches[]? | select(.vulnerability.severity == "High")] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  G_MEDIUM=$(jq '[.matches[]? | select(.vulnerability.severity == "Medium")] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  G_LOW=$(jq '[.matches[]? | select(.vulnerability.severity == "Low")] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  G_UNKNOWN=$(jq '[.matches[]? | select(.vulnerability.severity == "Unknown" or .vulnerability.severity == "Negligible")] | length' "$GRYPE_JSON" 2>/dev/null || printf '0')
  printf 'Grype: %s critical, %s high, %s medium, %s low, %s unknown, %s total\n' \
    "$G_CRITICAL" "$G_HIGH" "$G_MEDIUM" "$G_LOW" "$G_UNKNOWN" "$G_TOTAL"

  jq -r '
    [.matches[]? | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")]
    | sort_by(.vulnerability.severity | if . == "Critical" then 0 else 1 end)
    | .[] | "| \(.vulnerability.id) | \(.vulnerability.severity) | \(.artifact.name) | \(.artifact.version) | \(.vulnerability.fix.versions[0] // "n/a") |"
  ' "$GRYPE_JSON" 2>/dev/null > "$OUTPUT_DIR/grype-critical-high.txt" || true

  jq -r '
    [.matches[]? | select(.vulnerability.severity == "Medium")]
    | .[] | "| \(.vulnerability.id) | \(.artifact.name) | \(.artifact.version) | \(.vulnerability.fix.versions[0] // "n/a") |"
  ' "$GRYPE_JSON" 2>/dev/null > "$OUTPUT_DIR/grype-medium.txt" || true

  jq -r '
    [.matches[]? | select(.vulnerability.severity == "Low")]
    | .[] | "| \(.vulnerability.id) | \(.artifact.name) | \(.artifact.version) | \(.vulnerability.fix.versions[0] // "n/a") |"
  ' "$GRYPE_JSON" 2>/dev/null > "$OUTPUT_DIR/grype-low.txt" || true
else
  echo "::warning::Grype scan produced no output"
fi

# Defensive normalisation (parse failures default to 0).
for var in T_TOTAL T_CRITICAL T_HIGH T_MEDIUM T_LOW T_UNKNOWN \
           G_TOTAL G_CRITICAL G_HIGH G_MEDIUM G_LOW G_UNKNOWN; do
  val="${!var}"
  if ! printf '%s' "$val" | grep -qE '^[0-9]+$'; then
    printf -v "$var" '%s' '0'
  fi
done

{
  printf 'trivy-total=%s\n' "$T_TOTAL"
  printf 'trivy-critical=%s\n' "$T_CRITICAL"
  printf 'trivy-high=%s\n' "$T_HIGH"
  printf 'trivy-medium=%s\n' "$T_MEDIUM"
  printf 'trivy-low=%s\n' "$T_LOW"
  printf 'trivy-unknown=%s\n' "$T_UNKNOWN"
  printf 'grype-total=%s\n' "$G_TOTAL"
  printf 'grype-critical=%s\n' "$G_CRITICAL"
  printf 'grype-high=%s\n' "$G_HIGH"
  printf 'grype-medium=%s\n' "$G_MEDIUM"
  printf 'grype-low=%s\n' "$G_LOW"
  printf 'grype-unknown=%s\n' "$G_UNKNOWN"
} >> "$GITHUB_OUTPUT"
