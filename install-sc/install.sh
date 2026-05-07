#!/usr/bin/env bash
# Download and install the `sc` binary from dist.simple-container.com.
# Replaces the curl-pipe install bootstrap. The script:
#   - Pins to a versioned URL if `SC_VERSION` is set; otherwise uses the
#     un-versioned (`latest`) URL.
#   - Downloads the tarball with a 3-attempt retry (the dist server is
#     fronted by Cloudflare, which has been observed to occasionally
#     truncate large bodies — same retry rationale as integrail/devops's
#     install-sc action).
#   - Optionally verifies a caller-provided SHA256 hex digest. SC does not
#     currently publish per-release checksums or signatures, so this is
#     opt-in defense-in-depth: a consumer that wants byte-for-byte
#     reproducibility can compute the SHA256 once locally and pin it.
#   - Extracts ONLY the `sc` binary into `~/.local/bin/sc` and adds that
#     directory to `$GITHUB_PATH` so subsequent steps see the binary.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_PATH:?GITHUB_PATH must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

SC_VERSION="${SC_VERSION:-}"
SC_SHA256="${SC_SHA256:-}"

# --- Validate inputs ---------------------------------------------------
if [ -n "$SC_VERSION" ]; then
  if ! printf '%s' "$SC_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "::error::SC version must match semver X.Y.Z, got: '$SC_VERSION'"
    exit 1
  fi
fi
if [ -n "$SC_SHA256" ]; then
  if ! printf '%s' "$SC_SHA256" | grep -qE '^[a-f0-9]{64}$'; then
    echo "::error::SC SHA256 must be 64 lowercase hex chars, got: '$SC_SHA256'"
    exit 1
  fi
fi

# --- Resolve platform / arch ------------------------------------------
case "$(uname -s)" in
  Linux)  PLATFORM=linux ;;
  Darwin) PLATFORM=darwin ;;
  *)      echo "::error::Unsupported OS: $(uname -s)"; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)   ARCH=amd64 ;;
  aarch64|arm64)  ARCH=arm64 ;;
  *)              echo "::error::Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

if [ -n "$SC_VERSION" ]; then
  URL="https://dist.simple-container.com/sc-${PLATFORM}-${ARCH}-v${SC_VERSION}.tar.gz"
  RESOLVED_VERSION="$SC_VERSION"
else
  URL="https://dist.simple-container.com/sc-${PLATFORM}-${ARCH}.tar.gz"
  RESOLVED_VERSION="latest"
fi

# --- Download with retry ----------------------------------------------
work="$RUNNER_TEMP/install-sc"
mkdir -p "$work"
tarball="$work/sc.tar.gz"

echo "Downloading sc (${RESOLVED_VERSION}, ${PLATFORM}/${ARCH}) from ${URL}"
for attempt in 1 2 3; do
  if curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 \
       "$URL" -o "$tarball"; then
    break
  fi
  if [ "$attempt" -eq 3 ]; then
    echo "::error::Failed to download sc from $URL after 3 attempts"
    exit 1
  fi
  echo "::warning::sc download attempt $attempt failed, retrying after 5s"
  sleep 5
done

# --- Verify SHA256 (optional) -----------------------------------------
if [ -n "$SC_SHA256" ]; then
  echo 'Verifying SHA256 against caller-supplied digest...'
  printf '%s  %s\n' "$SC_SHA256" "$tarball" | sha256sum -c -
fi

# Always log the actual digest for forensics.
ACTUAL_SHA256="$(sha256sum "$tarball" | awk '{print $1}')"
echo "sc tarball SHA256: $ACTUAL_SHA256"

# --- Extract binary ---------------------------------------------------
bindir="$HOME/.local/bin"
mkdir -p "$bindir"
tar -xzf "$tarball" -C "$bindir" sc
chmod +x "$bindir/sc"

# --- Wire into PATH for subsequent steps -----------------------------
echo "$bindir" >> "$GITHUB_PATH"

# --- Smoke test -------------------------------------------------------
"$bindir/sc" --version

{
  printf 'version=%s\n' "$RESOLVED_VERSION"
  printf 'binary=%s/sc\n' "$bindir"
} >> "$GITHUB_OUTPUT"
