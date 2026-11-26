#!/usr/bin/env bash
# Removes local workspace build artifacts and incremental directories from
# target/ before actions/cache saves it, keeping compiled third-party crates.
set -euo pipefail

RELEASE_FLAG=()
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      RELEASE_FLAG=(--release)
      shift
      ;;
    --target)
      TARGETS+=("${2:-}")
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -d target ]]; then
  exit 0
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  for pkg in ssh-usb-unlock sshd-epoch-auth; do
    cargo clean -p "$pkg" ${RELEASE_FLAG[@]+"${RELEASE_FLAG[@]}"} 2>/dev/null || true
  done
else
  for target in "${TARGETS[@]}"; do
    for pkg in ssh-usb-unlock sshd-epoch-auth; do
      cargo clean -p "$pkg" ${RELEASE_FLAG[@]+"${RELEASE_FLAG[@]}"} --target "$target" 2>/dev/null || true
    done
  done
fi

find target -maxdepth 3 -type d -name incremental -exec rm -rf {} + 2>/dev/null || true
