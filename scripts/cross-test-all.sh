#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Every crate that has a cross-test, run one crate at a time.
#
# # Why one at a time, and not one cargo invocation
#
# Because features are unified across whatever cargo is asked to build at once.
# A crate that never enables a feature gets it anyway when some other member of
# the same invocation does, and the test binary that comes out is not the one
# the crate's own `cargo nextest run -p <crate>` produces. That is not a
# hypothetical: `redoubt-guard/guard` reaches `redoubt-vault`'s test binary that
# way, and `prctl(PR_SET_DUMPABLE, 0)` then makes `/proc/<pid>/mem` unreadable,
# so every forensics test in it fails with `NoPhotograph` — green on its own,
# red in the suite, and nothing in the diff to explain it.
#
# Each `cross-test.sh` already runs `-p <its own crate>`. Running them in
# separate invocations is what keeps that true.
#
# It stops at the first failure, which leaves the crate that failed as the last
# thing on the screen.
#
# # Arguments
#
# Crate directory names, to run a subset: `cross-test-all.sh redoubt-mem`.
# With none, everything that has a cross-test.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

mapfile -t FOUND < <(find crates -name cross-test.sh -type f | sort)

if [ ${#FOUND[@]} -eq 0 ]; then
  echo "no cross-test.sh anywhere under crates/" >&2
  exit 1
fi

# What the crate is called, read where each `cross-test.sh` reads it. Not the
# directory: `crates/redoubt-codec/core` is `redoubt-codec-core`, and two of
# those directories are named `core`.
named() {
  sed -n 's/^name *= *"\(.*\)".*/\1/p' "$(dirname "$1")/Cargo.toml" | head -1
}

# A subset, if the caller named one.
WANTED=("$@")

SCRIPTS=()

for script in "${FOUND[@]}"; do
  if [ ${#WANTED[@]} -eq 0 ]; then
    SCRIPTS+=("$script")
    continue
  fi

  crate="$(named "$script")"

  for one in "${WANTED[@]}"; do
    if [ "$one" = "$crate" ]; then
      SCRIPTS+=("$script")
      break
    fi
  done
done

if [ ${#SCRIPTS[@]} -eq 0 ]; then
  echo "nothing matched: ${WANTED[*]}" >&2
  echo "found: $(for s in "${FOUND[@]}"; do named "$s"; done | tr '\n' ' ')" >&2
  exit 1
fi

DONE=()

for script in "${SCRIPTS[@]}"; do
  crate="$(named "$script")"

  echo
  echo "################################################################"
  echo "## $crate"
  echo "################################################################"
  echo

  bash "$script"

  DONE+=("$crate")
done

echo
echo "################################################################"
echo "## read on both architectures: ${DONE[*]}"
echo "################################################################"
echo
