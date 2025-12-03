#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# -----------------------------------------------------------------------------
# rustc-nocov-deps
#
# Purpose:
#   RUSTC_WRAPPER that disables coverage instrumentation for *dependencies* and
#   instruments only the crates you explicitly allow. This prevents monomorphized
#   code in deps from polluting the coverage of the crate under test.
#
# How it works:
#   - Cargo invokes: <wrapper> <rustc-real> <args...>
#   - We detect the current crate name from `--crate-name`.
#   - If the crate is not in COVER_CRATES, we strip coverage flags from the
#     rustc invocation (`-C instrument-coverage`, `-Clink-dead-code`,
#     `-Z coverage-options=...`).
#   - For rustc query commands (e.g. `--print …`), we pass through unchanged.
#
# Environment:
#   COVER_CRATES   Comma-separated list of crate names to instrument.
#                  Example: COVER_CRATES="memcrypt,memcode-core"
#                  If empty/unset, every crate is instrumented (default behavior).
# -----------------------------------------------------------------------------

set -euo pipefail

# --- Detect the real rustc binary (Cargo calls: wrapper <rustc> <args...>) ---
if [[ $# -gt 0 && -x "${1}" && "${1}" == */rustc ]]; then
  real_rustc="$1"
  shift
else
  real_rustc="${RUSTC_REAL:-rustc}"
fi

# --- Pass-through for rustc query invocations (no filtering needed) ---
for arg in "$@"; do
  if [[ "$arg" == "--print" ]] || [[ "$arg" == "--version" ]] || [[ "$arg" == "-V" ]]; then
    exec "$real_rustc" "$@"
  fi
done

# --- Determine whether this crate should be instrumented ---
covered_crates_csv="${COVER_CRATES:-}"
rustc_args=("$@")
current_crate_name=""
crate_type=""
has_test_flag=false

for i in "${!rustc_args[@]}"; do
  if [[ "${rustc_args[$i]}" == "--crate-name" && $((i + 1)) -lt ${#rustc_args[@]} ]]; then
    current_crate_name="${rustc_args[$((i + 1))]}"
  fi
  if [[ "${rustc_args[$i]}" == "--crate-type" && $((i + 1)) -lt ${#rustc_args[@]} ]]; then
    crate_type="${rustc_args[$((i + 1))]}"
  fi
  if [[ "${rustc_args[$i]}" == "--test" ]]; then
    has_test_flag=true
  fi
done

# DEBUG: Log compilation info
if [[ -n "${DEBUG_COVERAGE:-}" ]]; then
  echo "[rustc-nocov] crate=$current_crate_name type=$crate_type test=$has_test_flag cover=$covered_crates_csv" >&2
fi

instrument_this_crate=true
if [[ -n "$covered_crates_csv" ]]; then
  instrument_this_crate=false
  IFS=, read -ra allowed_list <<<"$covered_crates_csv"

  for allowed in "${allowed_list[@]}"; do
    allowed=$(echo "$allowed" | xargs) # Remove extra spaces

    if [[ "$current_crate_name" == "$allowed" ]]; then
      instrument_this_crate=true
      break
    fi
  done

  # Test binaries need coverage runtime to write profraw, even if not in COVER_CRATES
  if $has_test_flag; then
    instrument_this_crate=true
  fi
fi

# --- If not instrumenting this crate, strip coverage-related flags from args ---
filtered_args=()
skip_next=false
for i in "${!rustc_args[@]}"; do
  $skip_next && {
    skip_next=false
    continue
  }
  arg="${rustc_args[$i]}"

  if ! $instrument_this_crate; then
    # Forms we may see:
    #   -C instrument-coverage
    #   -Cinstrument-coverage
    #   -Clink-dead-code
    #   -Z coverage-options=branch[,condition,...]
    if [[ "$arg" == "-C" && $((i + 1)) -lt ${#rustc_args[@]} ]]; then
      next="${rustc_args[$((i + 1))]}"
      if [[ "$next" == instrument-coverage* || "$next" == link-dead-code* ]]; then
        skip_next=true
        continue
      fi
    fi
    [[ "$arg" == -Cinstrument-coverage* ]] && continue
    [[ "$arg" == -Clink-dead-code* ]] && continue
    [[ "$arg" == -Z*coverage-options* ]] && continue
  fi

  filtered_args+=("$arg")
done

# DEBUG: Print filtered arguments
if [[ -n "${DEBUG_COVERAGE:-}" ]]; then
  echo "[rustc-nocov] filtered_args: ${filtered_args[*]}" >&2
fi

# Execute rustc with the filtered arguments
exec "$real_rustc" "${filtered_args[@]}"
