#!/usr/bin/env bash
# Read the rendered comment artifact and post or update a sticky PR comment.
# Runs in the BASE-REPO context after a workflow_run trigger, so it has
# pull-requests:write on a public consumer. Trust posture:
#
#   - PR number: input from caller (caller derives from workflow_run event,
#     never from the artifact).
#   - Marker: input from caller (hardcoded per caller workflow), never from
#     the artifact.
#   - Body: read from artifact (rendered by trusted workflow code on the
#     unprivileged side; size-capped here as defence-in-depth).
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${REPO:?REPO must be set (owner/repo)}"
: "${MARKER:?MARKER must be set}"
: "${PR_NUMBER:?PR_NUMBER must be set}"
: "${ARTIFACT_DIR:?ARTIFACT_DIR must be set}"

BODY_FILE="$ARTIFACT_DIR/body.md"

if [ ! -f "$BODY_FILE" ]; then
  echo '::warning::pr-comment artifact missing body.md — skipping comment.'
  exit 0
fi

# Validate REPO is owner/repo, no shell metacharacters.
if ! printf '%s' "$REPO" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
  echo "::error::Invalid REPO: '$REPO'"
  exit 1
fi

# Validate PR number is a positive integer.
if ! printf '%s' "$PR_NUMBER" | grep -qE '^[1-9][0-9]*$'; then
  echo "::error::Invalid PR_NUMBER: '$PR_NUMBER'"
  exit 1
fi

# Marker must be a Markdown H2 header with a safe charset so it can't smuggle
# metacharacters into a jq string. Caller-controlled; we still defence-validate.
if ! printf '%s' "$MARKER" | grep -qE '^## [A-Za-z0-9 ()._/+&,:-]+$'; then
  echo "::error::Marker '$MARKER' is not a safe '## Heading' string."
  exit 1
fi

if [ ! -s "$BODY_FILE" ]; then
  echo '::warning::body.md is empty — skipping comment.'
  exit 0
fi

# Cap body size at 64 KiB. GitHub itself limits comments to 65 536 chars; any
# larger body is almost certainly a bug or attempted abuse.
BODY_SIZE="$(wc -c < "$BODY_FILE")"
if [ "$BODY_SIZE" -gt 65536 ]; then
  echo "::error::body.md is $BODY_SIZE bytes (>64 KiB). Refusing to post."
  exit 1
fi

# Find existing bot comment by marker. We list comments via the API into a
# temp file so jq parsing failures and gh API errors are caught — `|| true`
# previously hid them.
COMMENTS_FILE="$(mktemp)"
trap 'rm -f -- "$COMMENTS_FILE"' EXIT

if ! gh api "repos/$REPO/issues/$PR_NUMBER/comments" --paginate > "$COMMENTS_FILE" 2>&1; then
  echo "::error::gh api failed listing comments on PR #$PR_NUMBER"
  cat -- "$COMMENTS_FILE" >&2
  exit 1
fi

# Match marker on a line of its own (anchored), not via substring contains —
# prevents `## X` from matching inside `### X`, code blocks, quoted text.
COMMENT_ID="$(jq -r --arg marker "$MARKER" '
  .[]
  | select(.user.login == "github-actions[bot]")
  | select((.body // "") | split("\n") | .[0] == $marker)
  | .id
' "$COMMENTS_FILE" | head -n 1)"

# Post via --input - + jq --rawfile to avoid any argv length / quoting issues.
if [ -n "$COMMENT_ID" ]; then
  printf 'Updating existing comment %s on PR #%s\n' "$COMMENT_ID" "$PR_NUMBER"
  jq -n --rawfile body "$BODY_FILE" '{body: $body}' \
    | gh api "repos/$REPO/issues/comments/$COMMENT_ID" -X PATCH --input -
else
  printf 'Creating new comment on PR #%s\n' "$PR_NUMBER"
  jq -n --rawfile body "$BODY_FILE" '{body: $body}' \
    | gh api "repos/$REPO/issues/$PR_NUMBER/comments" -X POST --input -
fi
