#!/usr/bin/env bash
# Dockerhub login via an SC secrets registry.
#
# Flow — mirrors the pattern api/.github/workflows/push.yaml ships:
#
#   1. Write SC_CONFIG to .sc/cfg.default.yaml (the SC CLI reads this
#      automatically when it can't find a passphrase elsewhere).
#   2. `sc secrets reveal` — decrypts every .sc/stacks/*/secrets.yaml
#      the config knows about.
#   3. `sc stack secret-get -s <stack> <key>` — pulls the Dockerhub
#      token.
#   4. Pipe into `docker login --password-stdin` — never materialises
#      the token on argv or in a log line.
#
# Inputs come via env (set by action.yml):
#   SC_CONFIG          — literal cfg.default.yaml contents (REQUIRED)
#   SC_STACK           — stack name (default `dist`)
#   SC_SECRET_KEY      — secret name (default `dockerhub-cicd-token`)
#   DOCKERHUB_USERNAME — docker login username (default `simplecontainer`)
#   SC_CFG_PATH        — override of .sc/cfg.default.yaml path
set -euo pipefail

: "${SC_CONFIG:?sc-config input is required}"
: "${SC_STACK:=dist}"
: "${SC_SECRET_KEY:=dockerhub-cicd-token}"
: "${DOCKERHUB_USERNAME:=simplecontainer}"
: "${SC_CFG_PATH:=.sc/cfg.default.yaml}"

# Preflight: required tools present. We don't install them — the
# fleet convention is for the consumer to call install-sc first, and
# every stock runner carries docker.
command -v sc >/dev/null 2>&1 || {
  echo "::error title=sc not found::call simple-container-com/actions/install-sc before this action" >&2
  exit 2
}
command -v docker >/dev/null 2>&1 || {
  echo "::error title=docker not found::runner needs the docker daemon available" >&2
  exit 2
}

# Write the config bundle. Create the parent dir idempotently so a
# consumer whose checkout has no .sc/ yet still works.
mkdir -p "$(dirname "$SC_CFG_PATH")"
printf '%s' "$SC_CONFIG" > "$SC_CFG_PATH"

# Reveal the encrypted .sc/stacks/*/secrets.yaml files.
sc secrets reveal

# Pull the token, mask it, pipe into docker login. The token value
# never touches an argv position + is registered as a log mask so a
# subsequent step that accidentally echoes it stays redacted.
token="$(sc stack secret-get -s "$SC_STACK" "$SC_SECRET_KEY")"
if [ -z "$token" ]; then
  echo "::error title=secret not found::'sc stack secret-get -s $SC_STACK $SC_SECRET_KEY' returned empty — check the stack + key exist in the fleet's SC registry" >&2
  exit 3
fi
echo "::add-mask::$token"

printf '%s' "$token" | docker login --username "$DOCKERHUB_USERNAME" --password-stdin >/dev/null
echo "Logged in to Dockerhub as $DOCKERHUB_USERNAME (token from sc://$SC_STACK/$SC_SECRET_KEY)"
