#!/usr/bin/env bash
# Download and install the `welder` binary from welder.simple-container.com.
# Replaces the curl-pipe install bootstrap. Same shape as the
# install-sc action — see install-sc/install.sh for the design rationale.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (provided by GitHub runner)}"
: "${GITHUB_PATH:?GITHUB_PATH must be set (provided by GitHub runner)}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (provided by GitHub runner)}"

WELDER_VERSION="${WELDER_VERSION:-}"
WELDER_SHA256="${WELDER_SHA256:-}"

# --- Validate inputs ---------------------------------------------------
if [ -n "$WELDER_VERSION" ]; then
  if ! printf '%s' "$WELDER_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "::error::Welder version must match semver X.Y.Z, got: '$WELDER_VERSION'"
    exit 1
  fi
fi
if [ -n "$WELDER_SHA256" ]; then
  if ! printf '%s' "$WELDER_SHA256" | grep -qE '^[a-f0-9]{64}$'; then
    echo "::error::Welder SHA256 must be 64 lowercase hex chars, got: '$WELDER_SHA256'"
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

if [ -n "$WELDER_VERSION" ]; then
  URL="https://welder.simple-container.com/releases/${WELDER_VERSION}/welder-${PLATFORM}-${ARCH}.tar.gz"
  RESOLVED_VERSION="$WELDER_VERSION"
else
  URL="https://welder.simple-container.com/releases/latest/welder-${PLATFORM}-${ARCH}.tar.gz"
  RESOLVED_VERSION="latest"
fi

# Probe the URL with HEAD before downloading. Welder's dist server (Mkdocs
# behind Cloudflare) returns HTTP 200 with the docs index page for any
# missing path, so a normal 404 check would not catch a typo'd version.
# We assert content-type is `application/x-gzip`; anything else means the
# version isn't published.
echo "Probing ${URL}..."
content_type="$(curl -fsSIL "$URL" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1) == "content-type" {ct=$2} END {print ct}')"
case "$content_type" in
  application/x-gzip|application/gzip|application/octet-stream) ;;
  *)
    if [ -n "$WELDER_VERSION" ]; then
      echo "::error::Welder version '$WELDER_VERSION' not found at $URL (content-type=${content_type:-none}). The welder dist server currently only publishes versioned URLs for some releases; leave the version input empty to install 'latest'."
    else
      echo "::error::welder 'latest' is unreachable at $URL (content-type=${content_type:-none})."
    fi
    exit 1
    ;;
esac

# --- Download with retry ----------------------------------------------
work="$RUNNER_TEMP/install-welder"
mkdir -p "$work"
tarball="$work/welder.tar.gz"

echo "Downloading welder (${RESOLVED_VERSION}, ${PLATFORM}/${ARCH}) from ${URL}"
for attempt in 1 2 3; do
  if curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 \
       "$URL" -o "$tarball"; then
    break
  fi
  if [ "$attempt" -eq 3 ]; then
    echo "::error::Failed to download welder from $URL after 3 attempts"
    exit 1
  fi
  echo "::warning::welder download attempt $attempt failed, retrying after 5s"
  sleep 5
done

# --- Verify SHA256 (optional) -----------------------------------------
# macOS lacks coreutils' `sha256sum`; fall back to BSD `shasum -a 256`.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_check() { printf '%s  %s\n' "$1" "$2" | sha256sum -c -; }
  sha256_digest() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_check() { printf '%s  %s\n' "$1" "$2" | shasum -a 256 -c -; }
  sha256_digest() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "::error::Neither sha256sum nor shasum is available on PATH."
  exit 1
fi

if [ -n "$WELDER_SHA256" ]; then
  echo 'Verifying SHA256 against caller-supplied digest...'
  sha256_check "$WELDER_SHA256" "$tarball"
fi
ACTUAL_SHA256="$(sha256_digest "$tarball")"
echo "welder tarball SHA256: $ACTUAL_SHA256"

# --- Extract binary ---------------------------------------------------
bindir="$HOME/.local/bin"
mkdir -p "$bindir"
tar -xzf "$tarball" -C "$bindir" welder
chmod +x "$bindir/welder"

echo "$bindir" >> "$GITHUB_PATH"
"$bindir/welder" --version

{
  printf 'version=%s\n' "$RESOLVED_VERSION"
  printf 'binary=%s/welder\n' "$bindir"
} >> "$GITHUB_OUTPUT"
