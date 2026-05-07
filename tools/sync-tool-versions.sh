#!/usr/bin/env bash
# Diff (or propagate) tool image pins between versions/Dockerfile and the
# consumer files (composite-action defaults + scripts).
#
# Usage:
#   tools/sync-tool-versions.sh --check    # exit 1 if any consumer is out of sync
#   tools/sync-tool-versions.sh --apply    # rewrite consumers; re-runs check at the end
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

run_pass() {
  # Args: $1 = pass mode (--check|--apply). Echoes drift count to stdout's
  # last line; logs everything else to stderr. Returns 0 on no drift, 1 on
  # any drift (or invalid Dockerfile). Re-entrant (called twice in --apply).
  local pass_mode="$1"
  local drift=0
  local applied=0
  declare -A seen_stages=()

  while IFS= read -r line; do
    # Strip CR / trailing whitespace.
    line="${line%$'\r'}"
    if [[ ! "$line" =~ ^FROM[[:space:]]+([^[:space:]]+)[[:space:]]+AS[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]*$ ]]; then
      continue
    fi
    local pin="${BASH_REMATCH[1]}"
    local stage="${BASH_REMATCH[2]}"

    if [[ ! "$pin" =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$ ]]; then
      echo "::error::Bad FROM in versions/Dockerfile: '$line' (must be image:tag@sha256:digest)" >&2
      drift=1
      continue
    fi

    if [ -n "${seen_stages[$stage]:-}" ]; then
      echo "::error::Stage '$stage' appears more than once in versions/Dockerfile" >&2
      drift=1
      continue
    fi
    seen_stages[$stage]=1

    local files="${targets[$stage]:-}"
    if [ -z "$files" ]; then
      echo "::error::Stage '$stage' in Dockerfile has no entry in tools/sync-tool-versions.sh targets map" >&2
      drift=1
      continue
    fi

    # Strip the tag and digest to get just the image base (e.g. ghcr.io/anchore/syft).
    local base_with_colon="${pin%%@*}"
    local base="${base_with_colon%:*}"

    # Escape regex metachars in $base for grep -E. Only `.` and `/` actually
    # appear in our image bases (e.g. ghcr.io/anchore/syft).
    local base_re="${base//./\\.}"
    local pin_re="${base_re}:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}"

    local f
    for f in $files; do
      local abs="$REPO_ROOT/$f"
      if [ ! -f "$abs" ]; then
        echo "::error::Target file '$f' (for stage '$stage') not found" >&2
        drift=1
        continue
      fi

      local current
      mapfile -t current < <(grep -oE "$pin_re" -- "$abs" | sort -u)

      if [ "${#current[@]}" -eq 0 ]; then
        echo "::error::No image ref found for '$base' in '$f'" >&2
        drift=1
        continue
      fi

      local c
      for c in "${current[@]}"; do
        if [ "$c" != "$pin" ]; then
          if [ "$pass_mode" = '--apply' ]; then
            python3 -c '
import sys, pathlib
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text()
new_text = text.replace(old, new)
if new_text != text:
    p.write_text(new_text)
              ' "$abs" "$c" "$pin"
            printf 'updated %s: %s -> %s\n' "$f" "$c" "$pin" >&2
            applied=1
          else
            printf '::error file=%s::%s has %s, Dockerfile says %s. Run tools/sync-tool-versions.sh --apply.\n' \
              "$f" "$f" "$c" "$pin" >&2
            drift=1
          fi
        fi
      done
    done
  done < "$DOCKERFILE"

  # Detect REMOVED stages: every key in `targets` must have appeared in the
  # Dockerfile pass above. A targets row without a Dockerfile FROM means
  # someone deleted the FROM, leaving the consumer file untracked.
  local k
  for k in "${!targets[@]}"; do
    if [ -z "${seen_stages[$k]:-}" ]; then
      echo "::error::Stage '$k' is in tools/sync-tool-versions.sh targets but missing from versions/Dockerfile" >&2
      drift=1
    fi
  done

  printf '%s\n%s\n' "$drift" "$applied"
  return 0
}

# First pass.
out="$(run_pass "$MODE")"
drift="$(printf '%s\n' "$out" | sed -n '1p')"
applied="$(printf '%s\n' "$out" | sed -n '2p')"

if [ "$MODE" = '--apply' ]; then
  # Re-run --check after the propagation pass: catches the case where the
  # apply pass was aborted by an unrelated drift error (unknown stage,
  # missing target, etc.) and the working tree is now PARTIALLY synced.
  if [ "$drift" -ne 0 ]; then
    echo '::error::--apply could not fully resolve drift (see errors above). Refusing to declare success.' >&2
    exit 1
  fi
  echo "Re-running --check after --apply to confirm propagation..." >&2
  out2="$(run_pass --check)"
  recheck_drift="$(printf '%s\n' "$out2" | sed -n '1p')"
  if [ "$recheck_drift" -ne 0 ]; then
    echo '::error::--apply completed but post-apply --check still reports drift.' >&2
    exit 1
  fi
  if [ "$applied" -eq 0 ]; then
    echo 'Already in sync — no changes applied.' >&2
  else
    echo 'All tool versions propagated successfully.' >&2
  fi
  exit 0
fi

if [ "$drift" -ne 0 ]; then
  echo '::error::Tool version drift detected. See errors above.' >&2
  exit 1
fi
echo 'All tool versions in sync with versions/Dockerfile.' >&2
