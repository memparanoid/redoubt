#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# One crate's forensics, over and over, until a rare failure has to show.
#
# # What this is for
#
# A sweep reads whatever the process happens to hold, and what it holds is not
# only what the code put there: the allocator hands back a block it was given
# earlier, the kernel maps a page that was somebody's, a scheduler decides when
# the analyst forks. A leak that depends on any of those shows once in hundreds
# of runs, and one run that goes green says nothing about it.
#
# Twelve greens in a row is what a flake this rare looks like from close up.
# The number of runs is the whole instrument here: it is what turns "did not
# happen this time" into a rate.
#
# # One process per test, as nextest gives
#
# The binary is run once per test name rather than once for all of them. Two
# of these tests in one process are two secrets in one process, and each is the
# other's needle — which is why `cargo nextest` is what runs them, and why
# running the binary bare would answer a different question.
#
# # And what parallelism costs
#
# Sixteen of these at once is sixteen processes each reading a few megabytes of
# its own memory. They cannot reach each other, so no run is another's needle.
# What they do share is the machine, so the timing of every fork is different
# from what it is alone — which is a reason to run it this way and not an
# objection to it: a failure that only appears under load is still a failure,
# and the load is what a CI machine has.
#
# # Arguments
#
# How many times, and how many at once. `repeat-forensics.sh 3000 16`, which is
# also the default. The crate and its test target come after those:
# `repeat-forensics.sh 500 8 redoubt-mem forensics`.

set -euo pipefail

# Which tests to run, matched as a substring of the name. Empty runs all of
# them; a name runs that one. Hunting a single flake wants the one, because a
# rate is what is being measured and the other twenty runs dilute the machine
# rather than the answer.
FILTER="${FILTER:-}"

RUNS="${1:-3000}"
WORKERS="${2:-16}"
CRATE="${3:-redoubt-alloc}"
TARGET="${4:-forensics}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

OUT="$ROOT/.output/repeat-forensics"

mkdir -p "$OUT"

FAILURES="$OUT/$CRATE-$TARGET.failures"
COUNTED="$OUT/$CRATE-$TARGET.counted"

: >"$FAILURES"
: >"$COUNTED"

echo "building $CRATE --test $TARGET"

# Built once, on purpose. Thirty thousand `cargo` invocations would spend their
# time taking the lock on the target directory, and the runs would serialize on
# it rather than on the machine.
cargo test -p "$CRATE" --release --test "$TARGET" --no-run >/dev/null 2>&1

BIN="$(
  cargo test -p "$CRATE" --release --test "$TARGET" --no-run --message-format=json 2>/dev/null |
    grep -o "\"executable\":\"[^\"]*$TARGET-[^\"]*\"" |
    tail -1 |
    cut -d'"' -f4
)"

[ -n "$BIN" ] && [ -x "$BIN" ] || {
  echo "no test binary for $CRATE --test $TARGET" >&2
  exit 1
}

mapfile -t TESTS < <(
  "$BIN" --list --format terse | grep ': test$' | cut -d: -f1 | grep -F -- "$FILTER"
)

[ ${#TESTS[@]} -gt 0 ] || {
  echo "no test in $BIN matches '$FILTER'" >&2
  exit 1
}

TOTAL=$((${#TESTS[@]} * RUNS))

echo "$BIN"

if [ -n "$FILTER" ]; then
  echo "only: $FILTER"
fi

echo "${#TESTS[@]} tests x $RUNS runs = $TOTAL processes, $WORKERS at a time"
echo

# Run one test in its own process, and keep what it said only if it failed. The
# append is one `printf` per run, which is small enough that the kernel does it
# in one piece and two workers finishing at once do not interleave.
one() {
  local name="$1"
  local said

  if said="$("$BIN" --exact "$name" --nocapture 2>&1)"; then
    printf '.' >>"$COUNTED"
    return 0
  fi

  printf '\n===== %s =====\n%s\n' "$name" "$said" >>"$FAILURES"
  printf 'x' >>"$COUNTED"
}

export -f one
export BIN FAILURES COUNTED

# What has happened so far, read off the same file the workers append to. A run
# of this length with nothing on the screen is one nobody can tell from a hung
# one, and the failure count is the number worth watching go up.
watching() {
  local ran failed

  while :; do
    ran="$(wc -c <"$COUNTED")"
    failed="$(tr -cd x <"$COUNTED" | wc -c)"

    printf '\r  %s/%s run, %s failed   ' "$ran" "$TOTAL" "$failed"

    sleep 1
  done
}

started="$(date +%s)"

watching &
WATCHER=$!

# However this ends — finished, failed, or interrupted — the progress line is
# somebody else's process and would outlive the script without this.
trap 'kill "$WATCHER" 2>/dev/null || true' EXIT

for _ in $(seq 1 "$RUNS"); do
  printf '%s\n' "${TESTS[@]}"
done | xargs -P "$WORKERS" -I{} bash -c 'one "$@"' _ {}

kill "$WATCHER" 2>/dev/null || true

# Counted where it can be counted exactly. The byte-per-run file behind the
# progress line is the workers' and has been seen to disagree with the number
# of runs in both directions; what is known without it is how many were asked
# for, and how many said so themselves by writing down what they said.
ran="$TOTAL"
failed="$(grep -c '^===== ' "$FAILURES" || true)"

echo
echo
echo "################################################################"
echo "## $CRATE --test $TARGET: $failed failed of $ran, in $(($(date +%s) - started))s"
echo "################################################################"

if [ "$failed" -gt 0 ]; then
  echo
  echo "which ones, and how often:"
  grep '^===== ' "$FAILURES" | sort | uniq -c | sort -rn
  echo
  echo "what each said: $FAILURES"
  exit 1
fi

echo
echo "nothing failed. $FAILURES is empty."
