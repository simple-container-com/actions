#!/usr/bin/env bash
# Diff (or propagate) tool image pins between versions/Dockerfile and the
# consumer files (composite-action defaults + scripts).
#
# Usage:
#   tools/sync-tool-versions.sh --check    # exit 1 if any consumer is out of sync
#   tools/sync-tool-versions.sh --apply    # rewrite consumers to match the Dockerfile
#
# Why this exists:
#   Dependabot tracks `versions/Dockerfile` (docker ecosystem) and opens
#   auto-bump PRs there. It cannot parse `image:tag@sha256:...` inside
#   `action.yml` `default:` values or shell scripts. This script bridges
#   that gap. The CI workflow `tool-version-sync.yml` runs `--check` on
#   every PR; `--apply` is a 1-command propagation a human runs locally
#   on a Dependabot PR before merging.
set -euo pipefail

usage() {
  printf 'Usage: %s --check|--apply\n' "$0" >&2
  exit 2
}

MODE="${1:-}"
case "$MODE" in
  --check|--apply) ;;
  *) usage ;;
esac

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$REPO_ROOT/versions/Dockerfile"

if [ ! -f "$DOCKERFILE" ]; then
  echo "::error::versions/Dockerfile not found at $DOCKERFILE"
  exit 1
fi

# Map: stage name → space-separated list of files that must contain the pin.
# Adding a new tool requires three things: a FROM stage in the Dockerfile,
# the actual reference in a consumer file, and a row added below.
declare -A targets=(
  [trufflehog]='trufflehog-scan/action.yml'
  [syft]='sbom-generate/action.yml'
  [trivy]='sbom-scan/action.yml'
  [grype]='sbom-scan/action.yml'
  [semgrep]='semgrep-scan/action.yml semgrep-scan/run-tests.sh'
  [actionlint]='.github/workflows/lint.yml'
  [shellcheck]='.github/workflows/lint.yml'
)

drift=0
applied=0

# Parse FROM lines: `FROM <image>:<tag>@sha256:<digest> AS <name>`
while IFS= read -r line; do
  if [[ ! "$line" =~ ^FROM[[:space:]]+([^[:space:]]+)[[:space:]]+AS[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]*$ ]]; then
    continue
  fi
  pin="${BASH_REMATCH[1]}"
  stage="${BASH_REMATCH[2]}"

  if [[ ! "$pin" =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$ ]]; then
    echo "::error::Bad FROM in versions/Dockerfile: '$line' (must be image:tag@sha256:digest)"
    exit 1
  fi

  files="${targets[$stage]:-}"
  if [ -z "$files" ]; then
    echo "::error::Stage '$stage' in Dockerfile has no entry in tools/sync-tool-versions.sh"
    drift=1
    continue
  fi

  # Strip the tag and digest to get just the image base (e.g. ghcr.io/anchore/syft).
  base_with_colon="${pin%%@*}"
  base="${base_with_colon%:*}"

  # Escape regex metachars in $base for grep -E. Only `.` and `/` actually
  # appear in our image bases (e.g. ghcr.io/anchore/syft).
  base_re="${base//./\\.}"
  pin_re="${base_re}:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}"

  for f in $files; do
    abs="$REPO_ROOT/$f"
    if [ ! -f "$abs" ]; then
      echo "::error::Target file '$f' (for stage '$stage') not found"
      drift=1
      continue
    fi

    # All distinct pins for this base in the file (should be exactly one,
    # but we tolerate multiples as long as they all match).
    mapfile -t current < <(grep -oE "$pin_re" -- "$abs" | sort -u)

    if [ "${#current[@]}" -eq 0 ]; then
      echo "::error::No image ref found for '$base' in '$f'"
      drift=1
      continue
    fi

    for c in "${current[@]}"; do
      if [ "$c" != "$pin" ]; then
        if [ "$MODE" = "--apply" ]; then
          # In-place replace: literal-string match, no regex
          python3 -c '
import sys, pathlib
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text()
new_text = text.replace(old, new)
if new_text != text:
    p.write_text(new_text)
            ' "$abs" "$c" "$pin"
          printf 'updated %s: %s -> %s\n' "$f" "$c" "$pin"
          applied=1
        else
          printf '::error file=%s::%s has %s, Dockerfile says %s. Run tools/sync-tool-versions.sh --apply.\n' \
            "$f" "$f" "$c" "$pin"
          drift=1
        fi
      fi
    done
  done
done < "$DOCKERFILE"

if [ "$MODE" = "--apply" ]; then
  if [ "$applied" -eq 0 ]; then
    echo 'Already in sync — no changes.'
  fi
  exit 0
fi

if [ "$drift" -ne 0 ]; then
  echo '::error::Tool version drift detected. See errors above.'
  exit 1
fi
echo 'All tool versions in sync with versions/Dockerfile.'
