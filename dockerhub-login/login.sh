#!/usr/bin/env bash
# Dockerhub login via the fleet's SC secrets registry — hosted inside
# the PARENT repo (simple-container-com/api by default).
#
# Why we clone the parent.
#
# `cfg.github.yaml`'s `privateKey` is only authoritative over the SC
# registry inside the repo it was issued for. Running `sc secrets reveal`
# against that key in a consumer repo (say sc-component-backup) decrypts
# the consumer's own `.sc/stacks/*/secrets.yaml` only — which usually
# doesn't exist for a plugin/component repo. The fleet-wide Dockerhub
# token lives in `api/.sc/stacks/dist/secrets.yaml`, so we must clone
# api, drop SC_CONFIG into it as `.sc/cfg.github.yaml`, and reveal
# inside that checkout.
#
# Flow:
#   1. Write SC_CONFIG to /tmp/sc-config.yaml.
#   2. Extract `privateKey` into a 0600 identity file.
#   3. git clone the parent repo via that identity.
#   4. Copy SC_CONFIG as `.sc/cfg.github.yaml` into the checkout.
#   5. `sc secrets reveal` inside the checkout.
#   6. `sc stack secret-get -s <stack> <key>` → Dockerhub token.
#   7. `::add-mask::` the token, pipe into `docker login --password-stdin`.
#   8. Clean up the temp identity + checkout.
#
# Inputs come via env (set by action.yml):
#   SC_CONFIG          — literal cfg.github.yaml contents (REQUIRED)
#   SC_PARENT_REPO     — ssh URL (default `git@github.com:simple-container-com/api.git`)
#   SC_PARENT_REF      — git ref (default `main`)
#   SC_STACK           — stack (default `dist`)
#   SC_SECRET_KEY      — secret name (default `dockerhub-cicd-token`)
#   DOCKERHUB_USERNAME — docker login username (default `simplecontainer`)
set -euo pipefail

: "${SC_CONFIG:?sc-config input is required}"
: "${SC_PARENT_REPO:=git@github.com:simple-container-com/api.git}"
: "${SC_PARENT_REF:=main}"
: "${SC_STACK:=dist}"
: "${SC_SECRET_KEY:=dockerhub-cicd-token}"
: "${DOCKERHUB_USERNAME:=simplecontainer}"

# Preflight: required tools present. install-sc provides `sc`; stock
# runners carry `docker` + `git` + `python3`.
for bin in sc docker git python3; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "::error title=$bin not found::call simple-container-com/actions/install-sc before this action (and ensure the runner has docker + git + python3)" >&2
    exit 2
  }
done

workdir="$(mktemp -d -t sc-dockerhub-login-XXXXXX)"
trap 'rm -rf "$workdir"' EXIT

cfg_file="$workdir/cfg.github.yaml"
printf '%s' "$SC_CONFIG" > "$cfg_file"

# Pull `privateKey:` (YAML literal-block) out. Minimal Python because
# `yq` isn't guaranteed on every runner; stdlib only.
id_file="$workdir/id"
python3 - "$cfg_file" "$id_file" <<'PY'
import sys
cfg_path, out_path = sys.argv[1], sys.argv[2]
with open(cfg_path) as f:
    in_block, block = False, []
    for raw in f:
        line = raw.rstrip("\n")
        if line.startswith("privateKey:"):
            # Literal-block (`|`) or inline (`"..."` / bare).
            rest = line.split(":", 1)[1].strip()
            if rest and rest not in ("|", "|-", ">", ">-"):
                block = [rest]
                break
            in_block = True
            continue
        if in_block:
            if line and not line.startswith(" ") and not line.startswith("\t"):
                break
            if line.strip() == "":
                continue
            # YAML literal-block indent = 2 by default.
            block.append(line.lstrip())
if not block:
    sys.exit("privateKey not found in cfg.github.yaml")
with open(out_path, "w") as f:
    f.write("\n".join(block))
    if not block[-1].endswith("\n"):
        f.write("\n")
PY
chmod 0600 "$id_file"

# Use GIT_SSH_COMMAND so we never permanently write the key to ~/.ssh.
export GIT_SSH_COMMAND="ssh -i $id_file -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$workdir/known_hosts"

parent_dir="$workdir/parent"
git clone --depth=1 --branch "$SC_PARENT_REF" "$SC_PARENT_REPO" "$parent_dir" >/dev/null 2>&1 || {
  echo "::error title=parent clone failed::could not git clone $SC_PARENT_REPO at $SC_PARENT_REF — check SC_CONFIG's privateKey has read access" >&2
  exit 3
}

# Lay cfg.github.yaml in the parent checkout so `sc secrets reveal`
# resolves the registry's passphrase from the right file. mkdir -p is
# idempotent: every SC-owned repo already has a .sc/ directory, but a
# future parent that didn't would still work.
mkdir -p "$parent_dir/.sc"
cp "$cfg_file" "$parent_dir/.sc/cfg.github.yaml"

# Reveal the encrypted `.sc/stacks/*/secrets.yaml` files + pull the
# token. Run from the parent dir because `sc secrets reveal` scans the
# `.sc/` tree in cwd.
pushd "$parent_dir" >/dev/null
sc secrets reveal
token="$(sc stack secret-get -s "$SC_STACK" "$SC_SECRET_KEY")"
popd >/dev/null

if [ -z "$token" ]; then
  echo "::error title=secret not found::'sc stack secret-get -s $SC_STACK $SC_SECRET_KEY' returned empty on parent $SC_PARENT_REPO — check the stack + key exist in the fleet's registry" >&2
  exit 4
fi
echo "::add-mask::$token"

printf '%s' "$token" | docker login --username "$DOCKERHUB_USERNAME" --password-stdin >/dev/null
echo "Logged in to Dockerhub as $DOCKERHUB_USERNAME (token from $SC_PARENT_REPO :: $SC_STACK/$SC_SECRET_KEY)"
