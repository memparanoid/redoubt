#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Whether the routines that hold a secret branch on it, or index memory by it.
#
# # What decides
#
# Not this script and not an assertion. Memcheck tracks which bytes are
# undefined and reports every conditional jump and every memory index that
# depends on one, so marking a buffer undefined is marking it secret. What
# comes back is the list of places the comparison let its contents decide where
# to go, with a file and a line on each.
#
# # The control comes first, and has to fail
#
# A clean report means one of two things — nothing branches on the secret, or
# nothing is watching — and they read the same. So each package's first case
# is a routine that branches on its secret, and Memcheck has to report it.
# Where it does not, every clean answer after it in that package would be the
# instrument standing somewhere else.
#
# # Release, and only release
#
# The question is about the instructions that run, and those are the
# optimiser's. A branchless loop that the optimiser turns into a short circuit,
# or vectorises into one, is branchless only in the source — and an unoptimised
# build would report it clean while shipping something else.
#
# # One process each
#
# The marking is the process's, so two cases in one run would inherit each
# other's state. The binary is started once per case.
#
# # What it needs
#
# `valgrind` on the PATH, and a build that found Valgrind's headers, because
# `crabgrind` generates its bindings against them. Where they are not on the
# include path, three variables say where to look:
#
#   VALGRIND_INCLUDE          where `valgrind/valgrind.h` is
#   LIBCLANG_PATH             where `libclang.so` is
#   BINDGEN_EXTRA_CLANG_ARGS  `-I` at the clang resource directory, for stddef.h
#
# None of them is checked here, because a build that missed the headers still
# compiles: every client request becomes a no-op and the run reads clean while
# asking nothing. What refuses that is the case itself — marking the memory is
# the first thing each one does, and a no-op leaves it a panic rather than an
# answer, which is a code no case owes.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="tests::constant_time"

# The cases exist only under it, so that an ordinary build never asks the
# machine for libclang.
FEATURE="constant-time"

# What Memcheck answers with when it found something, which is the whole of
# what this reads. A case that panicked leaves 101 and a case that passed
# leaves 0, so the three outcomes are told apart rather than summed.
REPORTED=42

# Each case with its package and the code it owes. Each package's control is
# its first case and owes `$REPORTED`: where it stops reporting, nothing after
# it in that package is a measurement.
CASES=(
  "redoubt-aead-core test_a_short_circuiting_eq_branches_on_the_secret $REPORTED"
  "redoubt-aead-core test_the_rust_eq_branches_on_nothing_but_its_answer 0"
  "redoubt-aead-core test_the_chosen_eq_branches_on_nothing_but_its_answer 0"
  "redoubt-chacha test_a_routine_that_stops_on_the_key_branches_on_the_secret $REPORTED"
  "redoubt-chacha test_the_chosen_subkey_branches_on_nothing 0"
  "redoubt-chacha test_the_chosen_xor_under_a_twelve_byte_nonce_branches_on_nothing 0"
  "redoubt-chacha test_the_chosen_xor_under_an_eight_byte_nonce_branches_on_nothing 0"
  "redoubt-chacha test_the_chosen_xxor_branches_on_nothing 0"
  "redoubt-poly1305 test_a_routine_that_stops_on_the_key_branches_on_the_secret $REPORTED"
  "redoubt-poly1305 test_the_chosen_init_branches_on_nothing 0"
  "redoubt-poly1305 test_the_chosen_update_and_finalize_branch_on_nothing 0"
  "redoubt-hex test_a_routine_that_stops_on_a_non_digit_branches_on_the_secret $REPORTED"
  "redoubt-hex test_the_chosen_bytes_to_hex_branches_on_nothing 0"
  "redoubt-hex test_the_chosen_hex_to_bytes_branches_on_nothing_when_every_digit_is_one 0"
  "redoubt-hex test_the_chosen_hex_to_bytes_branches_on_nothing_when_a_character_is_not_a_digit 0"
)

cd "$ROOT"

command -v valgrind >/dev/null || {
  echo "no valgrind on the PATH" >&2
  exit 1
}

# The test binary of one package, built with the cases on. Asked for rather
# than guessed at: its name carries a hash that changes with the build.
binary_of() {
  cargo test --release --package "$1" --features "$FEATURE" --no-run >/dev/null

  cargo test --release --package "$1" --features "$FEATURE" --no-run --message-format json 2>/dev/null |
    python3 -c '
import json, sys

for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue

    if message.get("executable") and message.get("target", {}).get("kind") == ["lib"]:
        print(message["executable"])
'
}

echo "== building =="

declare -A BINS

for one in "${CASES[@]}"; do
  read -r package _ _ <<<"$one"

  [ -n "${BINS[$package]:-}" ] && continue

  BINS[$package]="$(binary_of "$package")"

  [ -n "${BINS[$package]}" ] || {
    echo "no test binary for $package" >&2
    exit 1
  }
done

echo

FAILED=()

for one in "${CASES[@]}"; do
  read -r package case owed <<<"$one"

  BIN="${BINS[$package]}"

  # Not inside an `if` and not followed by `||`: either is a condition context,
  # where `errexit` would stop applying and a case that died for its own
  # reasons would be read as one that answered.
  set +e

  valgrind -q --error-exitcode="$REPORTED" "$BIN" \
    --exact "$MODULE::$case" --ignored --test-threads=1 >/dev/null 2>&1

  got=$?

  set -e

  if [ "$got" -eq "$owed" ]; then
    answer="$got, as it owes"
  else
    answer="$got, and it owes $owed"
    FAILED+=("$package $case")
  fi

  printf '  %-24s %-64s %s\n' "$package" "$case" "$answer"
done

echo

[ ${#FAILED[@]} -eq 0 ] || {
  printf '## %s\n' "${FAILED[@]}"
  echo
  read -r package case <<<"${FAILED[0]}"
  echo "Run one by hand to read where:"
  echo "  valgrind ${BINS[$package]} --exact $MODULE::$case --ignored --test-threads=1"

  exit 1
}

echo "## no routine branches on a secret, or indexes memory by one"
