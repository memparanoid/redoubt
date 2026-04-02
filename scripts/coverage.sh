#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

# Usage:
#   ./scripts/coverage.sh redoubt-aead                   # single crate
#   ./scripts/coverage.sh redoubt-codec zeroize           # crate with features
#   ./scripts/coverage.sh redoubt-aead --no-cache         # clean first

set -euo pipefail

NIGHTLY="nightly-2025-10-15"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COVERAGE_DIR="$REPO_ROOT/coverage"
RUSTC_WRAPPER_PATH="$REPO_ROOT/docker/rustc-nocov-deps.sh"

CRATE=""
FEATURES=""
NO_CACHE=false

for arg in "$@"; do
  case "$arg" in
    --no-cache) NO_CACHE=true ;;
    *)
      if [ -z "$CRATE" ]; then
        CRATE="$arg"
      else
        FEATURES="$arg"
      fi
      ;;
  esac
done

if [ -z "$CRATE" ]; then
  echo "Error: Missing crate name"
  echo "Usage: ./scripts/coverage.sh <crate-name> [features] [--no-cache]"
  exit 1
fi

CRATE_DIR="$COVERAGE_DIR/$CRATE"

echo "=== Coverage: $CRATE ${FEATURES:+[$FEATURES]} ==="
echo "  Output: $CRATE_DIR"
echo ""

mkdir -p "$CRATE_DIR"

if $NO_CACHE; then
  cargo +$NIGHTLY llvm-cov clean
fi

TARGET_DIR="$REPO_ROOT/target/coverage/$CRATE"
mkdir -p "$TARGET_DIR"

COV_CMD=(
  cargo +$NIGHTLY llvm-cov -p "$CRATE"
  --branch
  --html --output-dir "$CRATE_DIR"
)

if [ -n "$FEATURES" ]; then
  COV_CMD+=(--features "$FEATURES")
fi

RUSTC_WRAPPER="$RUSTC_WRAPPER_PATH" \
COVER_CRATES="$CRATE" \
RUSTFLAGS="--cfg=__cover_crates_${CRATE//-/_}" \
CARGO_TARGET_DIR="$TARGET_DIR" \
"${COV_CMD[@]}"
