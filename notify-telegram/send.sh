#!/usr/bin/env bash
# Send a Telegram message via the Bot API.
#
# Inputs come from env vars set by action.yml. All values are validated
# before they reach curl, and the bot token is registered with
# `::add-mask::` so any subsequent log output (debug traces, set -x,
# downstream tools) sees `***` instead of the live secret.
set -euo pipefail

: "${TG_CHAT:?chat-id is required}"
: "${TG_TOKEN:?token is required}"
: "${TG_TEXT:?text is required}"
: "${TG_HOST:?api-host is required}"

# --- Mask the token immediately ---------------------------------------
# The runner consumes the workflow command before logging, so this line
# itself does not leak the token; subsequent occurrences of the value in
# any log line are replaced with `***`.
echo "::add-mask::$TG_TOKEN"

# --- Validate inputs ---------------------------------------------------
# Telegram chat IDs are signed integers. Bot tokens have the shape
# `<bot_id>:<35+ url-safe chars>`. Hostnames are restricted to a known
# alphabet; anything weirder is a sign of either a typo or injection.
if ! printf '%s' "$TG_CHAT" | LC_ALL=C grep -qE '^-?[0-9]+$'; then
  echo "::error::chat-id must be a signed integer, got: '$TG_CHAT'"
  exit 1
fi
if ! printf '%s' "$TG_TOKEN" | LC_ALL=C grep -qE '^[0-9]+:[A-Za-z0-9_-]+$'; then
  echo '::error::token does not match the Telegram bot-token shape <bot_id>:<auth>.'
  exit 1
fi
if ! printf '%s' "$TG_HOST" | LC_ALL=C grep -qE '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$'; then
  echo "::error::api-host must be a plain hostname, got: '$TG_HOST'"
  exit 1
fi

# --- Send --------------------------------------------------------------
# `--data-urlencode` URL-encodes the value, so commit messages with `&`,
# `=`, newlines, etc. cannot break the request body. `parse_mode` is
# intentionally omitted: text is sent literally, so attacker-controlled
# message bodies cannot inject Markdown / HTML formatting tricks. Output
# is discarded; `continue-on-error: true` on the caller step decides
# whether a Telegram outage should fail the job.
curl --fail --silent --show-error \
     --max-time 30 \
     --retry 2 --retry-delay 2 --retry-connrefused \
     -X POST "https://${TG_HOST}/bot${TG_TOKEN}/sendMessage" \
     --data-urlencode "chat_id=${TG_CHAT}" \
     --data-urlencode "text=${TG_TEXT}" \
     -o /dev/null
