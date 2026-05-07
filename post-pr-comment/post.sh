#!/usr/bin/env bash
# Read the rendered comment artifact and post or update a sticky PR comment.
# Runs in the BASE-REPO context after a workflow_run trigger, so it has
# pull-requests:write on a public consumer. It must not read any PR code; the
# only inputs it consumes are the artifact files (body.md, pr-number.txt).
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${REPO:?REPO must be set (owner/repo)}"
: "${MARKER_INPUT:?MARKER_INPUT must be set}"
: "${ARTIFACT_DIR:?ARTIFACT_DIR must be set}"

BODY_FILE="$ARTIFACT_DIR/body.md"
PR_FILE="$ARTIFACT_DIR/pr-number.txt"
MARKER_FILE="$ARTIFACT_DIR/marker.txt"

if [ ! -f "$BODY_FILE" ] || [ ! -f "$PR_FILE" ]; then
  echo '::warning::pr-comment artifact missing — skipping comment.'
  exit 0
fi

# Validate REPO is owner/repo, no shell metacharacters.
if ! printf '%s' "$REPO" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
  echo "::error::Invalid REPO: '$REPO'"
  exit 1
fi

# Validate PR number is digits only — defensive against artifact tampering.
PR_NUMBER="$(tr -d '[:space:]' < "$PR_FILE")"
if ! printf '%s' "$PR_NUMBER" | grep -qE '^[1-9][0-9]*$'; then
  echo "::error::Invalid PR number in artifact: '$PR_NUMBER'"
  exit 1
fi

# Marker resolution: artifact's marker.txt wins if present and well-formed.
MARKER="$MARKER_INPUT"
if [ -f "$MARKER_FILE" ]; then
  marker_from_artifact="$(head -n 1 "$MARKER_FILE" | tr -d '\r')"
  if printf '%s' "$marker_from_artifact" | grep -qE '^## [A-Za-z0-9 ()._/+&,:-]+$'; then
    MARKER="$marker_from_artifact"
  else
    echo "::warning::marker.txt content rejected (not a Markdown H2 header), falling back to input marker."
  fi
fi

# Marker must be a Markdown H2 header (literal `## ...`) with a safe charset
# so it cannot smuggle metacharacters into a jq string.
if ! printf '%s' "$MARKER" | grep -qE '^## [A-Za-z0-9 ()._/+&,:-]+$'; then
  echo "::error::Marker '$MARKER' is not a safe '## Heading' string."
  exit 1
fi

if [ ! -s "$BODY_FILE" ]; then
  echo '::warning::body.md is empty — skipping comment.'
  exit 0
fi

# Read body via env var; never inlined into shell. Used by gh api -f below.
BODY_CONTENT="$(cat -- "$BODY_FILE")"

# Find existing bot comment by marker. Use jq --arg to safely pass the marker
# as a variable instead of string-interpolating it into the filter.
COMMENT_ID="$(gh api "repos/$REPO/issues/$PR_NUMBER/comments" --paginate \
  | jq -r --arg marker "$MARKER" \
      '.[] | select(.user.login == "github-actions[bot]" and (.body | contains($marker))) | .id' \
  | head -n 1 || true)"

if [ -n "$COMMENT_ID" ]; then
  printf 'Updating existing comment %s\n' "$COMMENT_ID"
  gh api "repos/$REPO/issues/comments/$COMMENT_ID" \
    -X PATCH \
    -f "body=$BODY_CONTENT"
else
  printf 'Creating new comment on PR #%s\n' "$PR_NUMBER"
  gh api "repos/$REPO/issues/$PR_NUMBER/comments" \
    -X POST \
    -f "body=$BODY_CONTENT"
fi
