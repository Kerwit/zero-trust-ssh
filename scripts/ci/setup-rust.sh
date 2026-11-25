#!/usr/bin/env bash
# Configures the Rust toolchain via rustup (preinstalled on GitHub-hosted
# runners), adds an optional cross-compilation target, disables incremental
# compilation in CI, and exports a portable rustc version hash for cache keys.
set -euo pipefail

TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGETS+=("${2:-}")
      shift 2
      ;;
    --toolchain)
      TOOLCHAIN="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found in PATH" >&2
  exit 1
fi

rustup toolchain install "$TOOLCHAIN" --profile minimal --no-self-update
rustup default "$TOOLCHAIN"

for target in "${TARGETS[@]}"; do
  if [[ -n "$target" ]]; then
    rustup target add "$target" --toolchain "$TOOLCHAIN"
  fi
done

sha256_short() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  else
    echo "Neither sha256sum nor shasum found" >&2
    exit 1
  fi
}

RUSTC_HASH="$(rustc -vV | tr -d '\r' | sha256_short)"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "rustc_hash=${RUSTC_HASH}" >> "$GITHUB_OUTPUT"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "CARGO_INCREMENTAL=0" >> "$GITHUB_ENV"
fi

echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
echo "rustc_hash: ${RUSTC_HASH}"
