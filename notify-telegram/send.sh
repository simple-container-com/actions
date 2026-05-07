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
TG_LINK_URL="${TG_LINK_URL:-}"
TG_LINK_TEXT="${TG_LINK_TEXT:-}"
TG_SUFFIX="${TG_SUFFIX:-}"

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
# When a link is requested, restrict its scheme to https://. Telegram does
# not need to render `javascript:` / `data:` / `tg://` — refusing them up
# front prevents a consumer that interpolates user-controlled values into
# `link-url` from turning the link into something nasty.
if [ -n "$TG_LINK_URL" ]; then
  if ! printf '%s' "$TG_LINK_URL" | LC_ALL=C grep -qE '^https://[A-Za-z0-9._~:/?#@!$&'\''()*+,;=%-]+$'; then
    echo "::error::link-url must be an https:// URL, got: '$TG_LINK_URL'"
    exit 1
  fi
fi

# --- Compose body ------------------------------------------------------
# We send with parse_mode=HTML so a caller-supplied link can render as a
# proper anchor (`<a href="...">title</a>`). Because of that, ALL
# attacker-reachable values must be HTML-escaped first — otherwise a
# commit message like `</a><script>` could break out of the format.
# Escaping covers `&`, `<`, `>`, `"` (the four characters that can have
# special meaning inside HTML text or quoted attribute values).
html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' \
                         -e 's/</\&lt;/g' \
                         -e 's/>/\&gt;/g' \
                         -e 's/"/\&quot;/g'
}

text_html="$(html_escape "$TG_TEXT")"
suffix_html="$(html_escape "$TG_SUFFIX")"

if [ -n "$TG_LINK_URL" ]; then
  link_url_html="$(html_escape "$TG_LINK_URL")"
  if [ -n "$TG_LINK_TEXT" ]; then
    link_label_html="$(html_escape "$TG_LINK_TEXT")"
  else
    # Default anchor text: the URL itself. Same effect as a plain URL but
    # consistent under parse_mode=HTML.
    link_label_html="$link_url_html"
  fi
  body="${text_html}<a href=\"${link_url_html}\">${link_label_html}</a>${suffix_html}"
else
  body="${text_html}${suffix_html}"
fi

# --- Send --------------------------------------------------------------
# `--data-urlencode` URL-encodes every value, so commit messages with `&`,
# `=`, newlines, etc. cannot break the request body. `parse_mode=HTML`
# requires the escaping done above. `disable_web_page_preview=true`
# suppresses the inline preview card that Telegram would otherwise render
# for the link — these are CI status messages, the link is for click-thru,
# not a thumbnail. Output is discarded; `continue-on-error: true` on the
# caller step decides whether a Telegram outage should fail the job.
curl --fail --silent --show-error \
     --max-time 30 \
     --retry 2 --retry-delay 2 --retry-connrefused \
     -X POST "https://${TG_HOST}/bot${TG_TOKEN}/sendMessage" \
     --data-urlencode "chat_id=${TG_CHAT}" \
     --data-urlencode "text=${body}" \
     --data-urlencode "parse_mode=HTML" \
     --data-urlencode "disable_web_page_preview=true" \
     -o /dev/null
