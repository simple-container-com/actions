#!/usr/bin/env bash
# Test fixtures for .semgrep/rules/shell.yml
#
# Lines marked `# ruleid: <id>` MUST match that rule.
# Lines marked `# ok: <id>` MUST NOT match that rule.
#
# This file is never executed; it exists to validate rule precision.
# shellcheck disable=all

# --------------------------------------------------------------------
# shell-eval-usage
# --------------------------------------------------------------------

# ruleid: shell-eval-usage
eval "$user_input"

# ruleid: shell-eval-usage
eval "VAR=$value"

# ok: shell-eval-usage
printf -v VAR '%s' "$value"

# ok: shell-eval-usage
declare -n ref="$var"; ref="$value"

# --------------------------------------------------------------------
# shell-curl-pipe-to-shell
# --------------------------------------------------------------------

# ruleid: shell-curl-pipe-to-shell
curl -sSL https://example.com/install.sh | sh

# ruleid: shell-curl-pipe-to-shell
curl -fsS https://example.com/install.sh | bash

# ruleid: shell-curl-pipe-to-shell
wget -qO- https://example.com/install.sh | sh

# ok: shell-curl-pipe-to-shell
curl -O https://example.com/file.tar.gz
tar xzf file.tar.gz

# ok: shell-curl-pipe-to-shell
docker run --rm pinned/image:1.2.3 some-cmd

# --------------------------------------------------------------------
# shell-rm-rf-root
# --------------------------------------------------------------------

# ruleid: shell-rm-rf-root
rm -rf /

# ruleid: shell-rm-rf-root
rm -rf /*

# ok: shell-rm-rf-root
rm -rf "$RUNNER_TEMP/work"

# ok: shell-rm-rf-root
rm -rf "$WORK_DIR"

# --------------------------------------------------------------------
# shell-source-of-variable-path
# --------------------------------------------------------------------

# ruleid: shell-source-of-variable-path
source $UNTRUSTED_PATH

# ruleid: shell-source-of-variable-path
. ${SOMETHING}/lib.sh

# ok: shell-source-of-variable-path
source ./scripts/lib.sh

# ok: shell-source-of-variable-path
. /etc/profile

# --------------------------------------------------------------------
# shell-cat-without-double-dash
# --------------------------------------------------------------------

# ruleid: shell-cat-without-double-dash
cat "$FILE"

# ok: shell-cat-without-double-dash
cat -- "$FILE"
