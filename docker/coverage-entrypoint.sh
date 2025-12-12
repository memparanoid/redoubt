#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Coverage runner (per-crate) for Memora workspace with selective instrumentation.
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
#   docker run memora-coverage                          # All crates
#   docker run memora-coverage memcodec-core            # Single crate
#   docker run memora-coverage memcrypt "test_utils"    # Crate with features
# -----------------------------------------------------------------------------

set -e

REPO_ROOT="$(pwd)"
OUT="/.coverage"

mk() {
  crate_name="$1"       # e.g., memcrypt
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
# Default behavior: run coverage for all Memora crates
# ---------------------------------------------------------------------------

cargo +nightly llvm-cov clean
mkdir -p "$OUT"

# --- Per-crate runs ---
mk memguard
mk memalloc
mk memzer
mk memzer_core
mk memzer_derive
mk memsecret
mk memrand
mk memutil
mk memvault
mk memvault_core
mk memvault_derive
mk memaead
mk membuffer
mk memcodec
mk memcodec zeroize
mk memcodec_core
mk memcodec_core zeroize
mk memcodec_derive

# --- Aggregated HTML report (consumes the profraw generated above) ---
CARGO_TARGET_DIR="target" \
  cargo +nightly llvm-cov report \
  --branch \
  --html --output-dir "$OUT"

echo "Coverage report generated at $OUT/index.html"
