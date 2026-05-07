#!/usr/bin/env bash
# Validate the custom Semgrep rules in .semgrep/rules/ against the
# fixture files in .semgrep/tests/. For each `# ruleid: <id>` marker we
# expect a finding for that rule on the next non-comment line. For each
# `# ok: <id>` we expect NO finding for that rule on the next non-comment
# line. Exits non-zero on any deviation.
#
# This script is the "test" entrypoint — invoked from the lint workflow.
set -euo pipefail

: "${SEMGREP_IMAGE:=semgrep/semgrep:1.161.0}"

if ! printf '%s' "$SEMGREP_IMAGE" | grep -qE '^[a-zA-Z0-9._/-]+:[A-Za-z0-9._-]+$'; then
  echo "::error::Refusing SEMGREP_IMAGE='$SEMGREP_IMAGE'"
  exit 1
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="$REPO_ROOT/.semgrep/rules"
TESTS_DIR="$REPO_ROOT/.semgrep/tests"

# Pair each test fixture with its rules file by basename.
declare -A pairs=(
  ["$RULES_DIR/shell.yml"]="$TESTS_DIR/shell.bash"
  ["$RULES_DIR/github-actions.yml"]="$TESTS_DIR/.github/workflows/cases.yml"
)

failed=0

run_semgrep_json() {
  local rule_file="$1"
  local target="$2"
  docker run --rm \
    -v "$REPO_ROOT:/src:ro" \
    -w /src \
    "$SEMGREP_IMAGE" \
    semgrep scan \
    --config "${rule_file#"$REPO_ROOT/"}" \
    --metrics=off \
    --json \
    "${target#"$REPO_ROOT/"}" 2>/dev/null
}

validate_pair() {
  local rule_file="$1"
  local fixture="$2"
  python3 - "$rule_file" "$fixture" "$3" <<'PY'
import json, re, sys, pathlib
rule_file, fixture_path, json_payload = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(json_payload)
findings = {(r["check_id"].split(".")[-1], r["start"]["line"], r["end"]["line"]) for r in data.get("results", [])}
text = pathlib.Path(fixture_path).read_text().splitlines()
expected = []
for i, line in enumerate(text, 1):
    m = re.match(r'\s*#\s*(ruleid|ok):\s*([\w-]+)\b', line)
    if not m: continue
    kind, rid = m.group(1), m.group(2)
    target = i + 1
    while target <= len(text) and (text[target-1].lstrip().startswith("#") or not text[target-1].strip()):
        target += 1
    expected.append((rid, kind, target))

failures = 0
for rid, kind, line in expected:
    matched = any(r == rid and sl <= line <= el for (r, sl, el) in findings)
    is_ok = (kind == "ruleid" and matched) or (kind == "ok" and not matched)
    if not is_ok:
        failures += 1
        print(f"  FAIL  {rid}@L{line}  expected={kind}  matched={matched}")
print(f"  {len(expected) - failures}/{len(expected)} cases passed for {pathlib.Path(fixture_path).name}")
sys.exit(0 if failures == 0 else 1)
PY
}

for rule_file in "${!pairs[@]}"; do
  fixture="${pairs[$rule_file]}"
  echo "Testing $(basename "$rule_file") against $(basename "$fixture")..."
  if [ ! -f "$rule_file" ] || [ ! -f "$fixture" ]; then
    echo "::error::Missing rule or fixture: $rule_file / $fixture"
    failed=1
    continue
  fi
  payload="$(run_semgrep_json "$rule_file" "$fixture")"
  if ! validate_pair "$rule_file" "$fixture" "$payload"; then
    failed=1
  fi
done

echo
echo 'Running full repo scan (must produce zero findings)...'
docker run --rm \
  -v "$REPO_ROOT:/src:ro" \
  -w /src \
  "$SEMGREP_IMAGE" \
  semgrep scan \
  --config .semgrep/rules/ \
  --metrics=off \
  --error \
  --exclude=.semgrep/tests

if [ "$failed" -ne 0 ]; then
  echo '::error::Semgrep rule tests failed.'
  exit 1
fi
echo 'All semgrep rule tests passed.'
