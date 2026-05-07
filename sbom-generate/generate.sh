#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the workspace via Syft.
set -euo pipefail

: "${SYFT_IMAGE:?SYFT_IMAGE must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

if ! printf '%s' "$SYFT_IMAGE" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$'; then
  echo "::error::Refusing to use SYFT_IMAGE='$SYFT_IMAGE' — not a plain image:tag reference."
  exit 1
fi

# GITHUB_WORKSPACE is owned by the runner, but Syft mounts it read-only so PR
# code is never executed.
case "$GITHUB_WORKSPACE" in
  /*) ;; # absolute path, OK
  *)
    echo "::error::GITHUB_WORKSPACE must be an absolute path: '$GITHUB_WORKSPACE'"
    exit 1
    ;;
esac

OUTPUT_DIR="$RUNNER_TEMP/sbom"
SBOM_FILE="$OUTPUT_DIR/sbom-cyclonedx.json"

mkdir -p "$OUTPUT_DIR"

docker run --rm \
  -v "$GITHUB_WORKSPACE:/repo:ro" \
  -v "$OUTPUT_DIR:/output" \
  "$SYFT_IMAGE" \
  dir:/repo \
  --exclude '**/.github/**' \
  --exclude '**/.git/**' \
  -o cyclonedx-json=/output/sbom-cyclonedx.json

if [ ! -f "$SBOM_FILE" ]; then
  echo "::error::Failed to generate SBOM"
  exit 1
fi

component_count=$(jq '.components | length' "$SBOM_FILE" 2>/dev/null || printf '0')
if ! printf '%s' "$component_count" | grep -qE '^[0-9]+$'; then
  component_count=0
fi

{
  printf 'sbom-file=%s\n' "$SBOM_FILE"
  printf 'component-count=%s\n' "$component_count"
} >> "$GITHUB_OUTPUT"

printf 'SBOM generated with %s components\n' "$component_count"

if [ "$component_count" = "0" ]; then
  echo "::warning::SBOM contains 0 components. Repo may have no detectable dependencies."
fi
