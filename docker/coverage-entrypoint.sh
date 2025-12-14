#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Coverage runner (per-crate) for Redoubt workspace with selective instrumentation.
#
# What this script does:
#   - Runs coverage for specific workspace crates using cargo-llvm-cov (nightly).
#   - Uses a rustc wrapper (rustc-nocov-deps) so ONLY the target crate is
#     instrumented; workspace dependencies are compiled without coverage flags.
#   - Supports optional feature sets per crate (comma-separated).
#   - Produces a single aggregated HTML report at /.coverage
#
# Requirements:
#   - rustc-nocov-deps installed at /usr/local/bin/rustc-nocov-deps
#   - nightly toolchain + cargo-llvm-cov installed
#
# Usage examples:
#   docker run redoubt-coverage                                    # All crates
#   docker run redoubt-coverage redoubt-codec-core                 # Single crate
#   docker run redoubt-coverage redoubt-codec-core "test_utils"    # Crate with features
# -----------------------------------------------------------------------------

set -e

REPO_ROOT="$(pwd)"
OUT="/.coverage"

mk() {
  crate_name="$1"       # e.g., redoubt-codec-core
  features_csv="${2:-}" # e.g., "test_utils" (optional; may be empty)

  cd "$REPO_ROOT"
  echo "[DEBUG] PWD: $(pwd)" >&2
  echo "[DEBUG] Repo ROOT: $REPO_ROOT" >&2
  echo "[DEBUG] Crate: $crate_name" >&2

  # Force recompilation of this crate to pick up new COVER_CRATES
  CARGO_TARGET_DIR="target" cargo +nightly clean -p "$crate_name"

  # Clean and set environment for this specific crate
  unset COVER_CRATES
  unset RUSTC_WRAPPER
  unset RUSTFLAGS
  export RUSTC_WRAPPER="/usr/local/bin/rustc-nocov-deps"
  export DEBUG_COVERAGE=1

  # Add COVER_CRATES to RUSTFLAGS so cargo recognizes different instrumentation
  # configs as different build artifacts (forces cache invalidation)
  export RUSTFLAGS="--cfg=__cover_crates_${crate_name//-/_}"

  if [ -n "$features_csv" ]; then
    CARGO_TARGET_DIR="target" \
      COVER_CRATES="$crate_name" \
      cargo +nightly llvm-cov -p "$crate_name" \
      --branch --no-report \
      --features "$features_csv"
  else
    CARGO_TARGET_DIR="target" \
      COVER_CRATES="$crate_name" \
      cargo +nightly llvm-cov -p "$crate_name" \
      --branch --no-report
  fi
}

# ---------------------------------------------------------------------------
# Per-crate mode (only if a crate name was provided)
# ---------------------------------------------------------------------------
if [ $# -ge 1 ]; then
  crate_name="$1"
  features="${2:-}"

  cargo +nightly llvm-cov clean
  mkdir -p "$OUT"

  mk "$crate_name" "$features"

  CARGO_TARGET_DIR="target" \
    cargo +nightly llvm-cov report \
    --branch \
    --html --output-dir "$OUT"

  echo "Coverage report generated at $OUT/index.html"
  exit 0
fi

# ---------------------------------------------------------------------------
# Default behavior: run coverage for all Redoubt crates
# ---------------------------------------------------------------------------

cargo +nightly llvm-cov clean
mkdir -p "$OUT"

# --- Per-crate runs ---
mk redoubt-guard
mk redoubt-alloc
mk redoubt-zero
mk redoubt-zero-core
mk redoubt-test-utils
mk redoubt-zero-derive
mk redoubt-secret
mk redoubt-rand
mk redoubt-util
mk redoubt-vault
mk redoubt-vault-core
mk redoubt-vault-derive
mk redoubt-aead
mk redoubt-buffer
mk redoubt-codec
mk redoubt-codec zeroize
mk redoubt-codec-core
mk redoubt-codec-core zeroize
mk redoubt-codec-derive

# --- Aggregated HTML report (consumes the profraw generated above) ---
CARGO_TARGET_DIR="target" \
  cargo +nightly llvm-cov report \
  --branch \
  --html --output-dir "$OUT"

echo "Coverage report generated at $OUT/index.html"
