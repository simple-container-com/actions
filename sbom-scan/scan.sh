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
  if ! printf '%s' "$img_val" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$'; then
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

TRIVY_LOG="$OUTPUT_DIR/trivy.log"
GRYPE_LOG="$OUTPUT_DIR/grype.log"

# Optional OpenVEX inputs.
#
# VEX_FILES is a whitespace-separated list of repo-local OpenVEX
# documents (typically `.sc/vex/*.openvex.json` in the consumer repo).
# Each path is mounted into the Trivy container and passed to both
# Trivy and Grype as `--vex <path>`. Statements with
# `status: not_affected` or `status: fixed` matching the SBOM's
# components are suppressed at the scanner — no `.trivyignore`, no
# DefectDojo-side ignore rules.
#
# Backward-compatible: if VEX_FILES is empty or unset, both scanners
# behave exactly as before. The wiring is no-op for consumers that
# don't ship a `.sc/vex/` directory.
#
# Authors of VEX docs: the two non-obvious gotchas are
#   (a) Trivy and Grype need a DUAL product shape per statement
#       (bare pURL for Trivy + image-pURL with subcomponent for Grype),
#   (b) Trivy keys on CVE IDs while Grype keys on GHSA IDs —
#       duplicate each statement once per key.
# See https://github.com/Integrail/everworker/blob/main/.vex/README.md
# for a worked example.
TRIVY_VEX_FLAGS=()
GRYPE_VEX_FLAGS=()
TRIVY_VEX_MOUNTS=()
if [ -n "${VEX_FILES:-}" ]; then
  echo 'OpenVEX documents detected — wiring into Trivy + Grype:'
  # Parse VEX_FILES into an array via read -ra so word-splitting cannot
  # re-evaluate shell globs / metacharacters in pathological filenames.
  read -ra _vex_paths <<< "$VEX_FILES"
  for vex_path in "${_vex_paths[@]}"; do
    if [ ! -f "$vex_path" ]; then
      echo "::warning::VEX file not found, skipping: $vex_path"
      continue
    fi
    vex_abs="$(cd "$(dirname -- "$vex_path")" && pwd)/$(basename -- "$vex_path")"
    vex_base="$(basename -- "$vex_abs")"
    echo "  $vex_abs  ->  /vex/$vex_base (in Trivy container)"
    # Trivy runs inside Docker — mount each VEX into /vex/<basename>
    # and reference that path. Grype also runs inside Docker (the SC
    # `grype-image` is a pinned docker image), so the same mount goes
    # to both.
    TRIVY_VEX_MOUNTS+=(-v "$vex_abs:/vex/$vex_base:ro")
    TRIVY_VEX_FLAGS+=(--vex "/vex/$vex_base")
    GRYPE_VEX_FLAGS+=(--vex "/vex/$vex_base")
  done
fi

# Run Trivy in background. Without --exit-code, Trivy returns 0 on success
# regardless of findings; any non-zero indicates an infra failure.
echo 'Starting Trivy scan...'
docker run --rm \
  -v "$SBOM_ABS:/sbom.json:ro" \
  -v "$OUTPUT_DIR:/output" \
  "${TRIVY_VEX_MOUNTS[@]}" \
  "$TRIVY_IMAGE" \
  sbom /sbom.json \
  --severity 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL' \
  --format json \
  "${TRIVY_VEX_FLAGS[@]}" \
  --output /output/trivy-scan.json \
  > "$TRIVY_LOG" 2>&1 &
TRIVY_PID=$!

# Run Grype in background. Without --fail-on, Grype returns 0 on success
# regardless of findings; any non-zero indicates an infra failure.
echo 'Starting Grype scan...'
docker run --rm \
  -v "$SBOM_ABS:/sbom.json:ro" \
  -v "$OUTPUT_DIR:/output" \
  "${TRIVY_VEX_MOUNTS[@]}" \
  "$GRYPE_IMAGE" \
  "sbom:/sbom.json" \
  "${GRYPE_VEX_FLAGS[@]}" \
  -o json \
  --file /output/grype-scan.json \
  > "$GRYPE_LOG" 2>&1 &
GRYPE_PID=$!

# Wait for both. Capture each scanner's exit code; fail the whole job on any
# non-zero so a broken scanner can't masquerade as 0 findings.
echo 'Waiting for parallel scans to complete...'
trivy_status=0
grype_status=0
wait "$TRIVY_PID" || trivy_status=$?
wait "$GRYPE_PID" || grype_status=$?

if [ "$trivy_status" -ne 0 ]; then
  echo "::error::Trivy exited with code $trivy_status. Logs:"
  cat -- "$TRIVY_LOG" >&2
  exit 1
fi
if [ "$grype_status" -ne 0 ]; then
  echo "::error::Grype exited with code $grype_status. Logs:"
  cat -- "$GRYPE_LOG" >&2
  exit 1
fi

# Both scanners must produce parseable JSON output AND match the expected
# top-level shape. A scanner that exits 0 with `{}` would otherwise still
# count as "0 findings" — bad.
for f in "$TRIVY_JSON" "$GRYPE_JSON"; do
  if [ ! -s "$f" ]; then
    echo "::error::Scanner output missing or empty: $f"
    exit 1
  fi
  if ! jq -e . "$f" >/dev/null 2>&1; then
    echo "::error::Scanner output is not valid JSON: $f"
    exit 1
  fi
done
# Trivy SBOM scan ships `Results` (array or null when no vulns).
trivy_shape=$(jq -r '.Results | type' "$TRIVY_JSON" 2>/dev/null || printf 'missing')
case "$trivy_shape" in
  array|null) ;;
  *)
    echo "::error::Trivy output schema unexpected: .Results is '$trivy_shape' (want array or null)."
    exit 1
    ;;
esac
# Grype always ships `matches` as an array.
grype_shape=$(jq -r '.matches | type' "$GRYPE_JSON" 2>/dev/null || printf 'missing')
if [ "$grype_shape" != 'array' ]; then
  echo "::error::Grype output schema unexpected: .matches is '$grype_shape' (want array)."
  exit 1
fi

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
