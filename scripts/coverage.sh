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

# Three passes: doctests, then the tests, then one report over both.
#
# They have to be separate runs. `cargo test --doc` builds and runs one binary
# per doctest and `nextest` does not run doctests at all, so a single
# invocation can only ever measure one of the two. `--no-report` collects the
# profile data without rendering; the last call renders everything together.
#
# Doctests go first: they are the cheapest thing that can be broken and the
# fastest to say so.
#
# `nextest` and not the default runner for the rest, because it gives each test
# a process. `redoubt-forensics` reads the whole process's memory, so two of
# its tests sharing one are two secrets in one process and each is the other's
# needle. And when a test dies on a signal, `nextest` names it instead of
# reporting that the binary went away.
FEATURE_ARGS=()

if [ -n "$FEATURES" ]; then
  FEATURE_ARGS+=(--features "$FEATURES")
fi

run_cov() {
  RUSTC_WRAPPER="$RUSTC_WRAPPER_PATH" \
  COVER_CRATES="$CRATE" \
  RUSTFLAGS="--cfg=__cover_crates_${CRATE//-/_}" \
  CARGO_TARGET_DIR="$TARGET_DIR" \
  "$@"
}

echo "--- doctests ---"
run_cov cargo +$NIGHTLY llvm-cov --no-report --doctests -p "$CRATE" \
  "${FEATURE_ARGS[@]}" test --doc

echo "--- tests ---"
run_cov cargo +$NIGHTLY llvm-cov --no-report nextest -p "$CRATE" "${FEATURE_ARGS[@]}"

echo "--- report ---"
run_cov cargo +$NIGHTLY llvm-cov report --branch --doctests \
  --html --output-dir "$CRATE_DIR"
