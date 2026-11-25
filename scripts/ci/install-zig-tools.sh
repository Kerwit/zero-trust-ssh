#!/usr/bin/env bash
# Installs pinned versions of zig and cargo-zigbuild into a self-contained
# directory (default: ~/.local/zig-tools) with SHA-256 verification.
# Idempotent: skips downloading any tool already present (e.g. from CI cache).
set -euo pipefail

ZIG_VERSION="${ZIG_VERSION:-0.14.1}"
ZIG_SHA256="${ZIG_SHA256:-24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c}"
CARGO_ZIGBUILD_VERSION="${CARGO_ZIGBUILD_VERSION:-0.24.1}"

ZIG_TOOLS_DIR="${ZIG_TOOLS_DIR:-$HOME/.local/zig-tools}"
ZIG_DIR="${ZIG_TOOLS_DIR}/zig"
BIN_DIR="${ZIG_TOOLS_DIR}/bin"

OS="$(uname -s)"
ARCH="$(uname -m)"
if [[ "$OS" != "Linux" || "$ARCH" != "x86_64" ]]; then
  echo "Unsupported runner platform: ${OS}/${ARCH} (expected Linux/x86_64)" >&2
  exit 1
fi

mkdir -p "$ZIG_DIR" "$BIN_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# 1. Zig
if [[ ! -x "$ZIG_DIR/zig" ]]; then
  ZIG_ARCHIVE="zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
  ZIG_URL="https://ziglang.org/download/${ZIG_VERSION}/${ZIG_ARCHIVE}"
  echo "Downloading Zig ${ZIG_VERSION}..."
  curl -fsSL --retry 3 --retry-delay 2 -o "$TMP_DIR/$ZIG_ARCHIVE" "$ZIG_URL"
  echo "${ZIG_SHA256}  ${TMP_DIR}/${ZIG_ARCHIVE}" | sha256sum -c -
  rm -rf "$ZIG_DIR"
  mkdir -p "$ZIG_DIR"
  tar -xJf "$TMP_DIR/$ZIG_ARCHIVE" --strip-components=1 -C "$ZIG_DIR"
  test -x "$ZIG_DIR/zig"
else
  echo "Using cached Zig at ${ZIG_DIR}/zig"
fi

# 2. cargo-zigbuild
if [[ ! -x "$BIN_DIR/cargo-zigbuild" ]]; then
  CZB_ARCHIVE="cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"
  CZB_BASE_URL="https://github.com/rust-cross/cargo-zigbuild/releases/download/v${CARGO_ZIGBUILD_VERSION}"
  echo "Downloading cargo-zigbuild v${CARGO_ZIGBUILD_VERSION}..."
  curl -fsSL --retry 3 --retry-delay 2 -o "$TMP_DIR/$CZB_ARCHIVE" "${CZB_BASE_URL}/${CZB_ARCHIVE}"
  curl -fsSL --retry 3 --retry-delay 2 -o "$TMP_DIR/${CZB_ARCHIVE}.sha256" "${CZB_BASE_URL}/${CZB_ARCHIVE}.sha256"
  (
    cd "$TMP_DIR"
    sha256sum -c "${CZB_ARCHIVE}.sha256"
  )
  mkdir -p "$TMP_DIR/czb"
  tar -xJf "$TMP_DIR/$CZB_ARCHIVE" -C "$TMP_DIR/czb"
  CZB_BIN="$(find "$TMP_DIR/czb" -type f -name cargo-zigbuild -print -quit)"
  if [[ -z "$CZB_BIN" ]]; then
    echo "cargo-zigbuild binary not found in archive" >&2
    exit 1
  fi
  install -m 755 "$CZB_BIN" "$BIN_DIR/cargo-zigbuild"
else
  echo "Using cached cargo-zigbuild at ${BIN_DIR}/cargo-zigbuild"
fi

# Export to PATH (GitHub Actions and current shell)
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n%s\n' "$ZIG_DIR" "$BIN_DIR" >> "$GITHUB_PATH"
fi

export PATH="${ZIG_DIR}:${BIN_DIR}:${PATH}"
echo "zig: $(zig version)"
echo "cargo-zigbuild: $(cargo-zigbuild --version)"
