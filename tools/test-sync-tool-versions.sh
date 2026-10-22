#!/usr/bin/env bash
# Behavioural test for tools/sync-tool-versions.sh.
#
# Copies the tracked tree into a scratch directory, rewrites one pin in
# versions/Dockerfile the way Dependabot would, runs --apply there, and
# asserts EXACTLY which files the propagation touched.
#
# Why the file set is asserted rather than just "it worked": the actionlint
# and shellcheck stages resolve to .github/workflows/lint.yml, and a
# GITHUB_TOKEN push cannot carry changes under .github/workflows/. That
# constraint stays invisible until you look at which files a bump rewrites,
# which is what this test makes explicit.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
# shellcheck disable=SC2064  # expand WORK now: it is fixed for the run.
trap "rm -rf -- '$WORK'" EXIT

failures=0

snapshot() {
  find . -type f -print0 | sort -z | xargs -0 sha256sum
}

# run_case <stage> <image-base> <new-tag> <expected-changed-file>...
run_case() {
  local stage="$1" base="$2" new_tag="$3"
  shift 3
  local expected=("$@")
  local case_failures=0
  local tree="$WORK/$stage"

  mkdir -p -- "$tree"
  ( cd -- "$REPO_ROOT" && git ls-files -z | tar --null -T - -cf - ) \
    | tar -xf - -C "$tree"

  local dockerfile="$tree/versions/Dockerfile"
  local old_pin new_pin new_digest base_re
  base_re="${base//./\\.}"
  old_pin="$(grep -oE "${base_re}:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}" -- "$dockerfile" | head -n 1)"
  if [ -z "$old_pin" ]; then
    echo "  FAIL  $stage: no pin for '$base' in versions/Dockerfile"
    failures=$((failures + 1))
    return 0
  fi
  # Synthetic digest: nothing is pulled, the test only checks that the exact
  # literal propagates to the right files.
  new_digest="$(printf '%064d' 0 | tr '0' 'a')"
  new_pin="${base}:${new_tag}@sha256:${new_digest}"

  python3 - "$dockerfile" "$old_pin" "$new_pin" <<'PY'
import pathlib
import sys

path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
p.write_text(p.read_text().replace(old, new))
PY

  cd -- "$tree"

  local rc=0
  ./tools/sync-tool-versions.sh --check >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "  FAIL  $stage: --check passed on a drifted tree (expected non-zero)"
    case_failures=$((case_failures + 1))
  fi

  local before after changed want f
  before="$(snapshot)"
  rc=0
  ./tools/sync-tool-versions.sh --apply >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAIL  $stage: --apply exited $rc (expected 0)"
    failures=$((failures + case_failures + 1))
    cd -- "$REPO_ROOT"
    return 0
  fi
  after="$(snapshot)"

  # `diff` exits 1 when the snapshots differ, which is the expected case.
  changed="$(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") \
    | sed -n 's|^> [0-9a-f]\{64\}  \./||p' | sort -u || true)"
  want="$(printf '%s\n' "${expected[@]}" | sort -u)"

  if [ "$changed" != "$want" ]; then
    echo "  FAIL  $stage: --apply changed the wrong files"
    echo "        want: ${want//$'\n'/, }"
    echo "        got : ${changed//$'\n'/, }"
    case_failures=$((case_failures + 1))
  fi

  for f in "${expected[@]}"; do
    if ! grep -qF -- "$new_pin" "$tree/$f"; then
      echo "  FAIL  $stage: new pin did not reach $f"
      case_failures=$((case_failures + 1))
    fi
  done

  rc=0
  ./tools/sync-tool-versions.sh --check >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAIL  $stage: --check still reports drift after --apply"
    case_failures=$((case_failures + 1))
  fi

  if [ "$case_failures" -eq 0 ]; then
    echo "  ok    $stage -> ${want//$'\n'/, }"
  fi
  failures=$((failures + case_failures))
  cd -- "$REPO_ROOT"
}

echo 'Testing tools/sync-tool-versions.sh --apply on synthetic bumps...'

# The stage whose only consumer is a workflow file. This is the bump a
# GITHUB_TOKEN push cannot complete.
run_case actionlint rhysd/actionlint 1.7.99 \
  .github/workflows/lint.yml

# A stage with two consumers, neither of them a workflow file.
run_case semgrep semgrep/semgrep 1.999.0 \
  semgrep-scan/action.yml semgrep-scan/run-tests.sh

if [ "$failures" -ne 0 ]; then
  echo "::error::sync-tool-versions tests failed ($failures failure(s))."
  exit 1
fi
echo 'All sync-tool-versions tests passed.'
