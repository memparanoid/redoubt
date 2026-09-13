#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The lab on both C libraries and both architectures, four runs.
#
# # Why all four, and why the four are the point
#
# What a report says depends on the allocator underneath it. A chunk freed
# under glibc keeps everything past its first few bytes; musl's `mallocng` may
# cover the lot. So the same unzeroized buffer reads as a leak under one and as
# nothing under the other, and a clean report on one library alone has not
# shown that anything is clean. The architecture is the second axis: the copy
# and the cipher take different paths on each.
#
# # Why it does not stop at the first failure
#
# Unlike `scripts/cross-test-all.sh`, where a red means the tree is broken and
# everything after it is read against a tree already known bad. These four are
# independent measurements of the same code, and three of them are worth having
# when the fourth could not run — an architecture Docker cannot emulate here
# does not make the other three say less.
#
# # Arguments
#
# None. Each run lands in `.output/<libc>-<arch>/`, which is gitignored.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RAN=()
FAILED=()

for libc in musl glibc; do
  for arch in x86 arm; do
    echo
    echo "################################################################"
    echo "## $libc / $arch"
    echo "################################################################"
    echo

    if bash "$HERE/run.sh" "--$arch" "--$libc"; then
      RAN+=("$libc-$arch")
    else
      FAILED+=("$libc-$arch")
    fi
  done
done

echo
echo "################################################################"
echo "## summary"
echo "################################################################"
echo

for one in "${RAN[@]}"; do
  echo "  ran   $one"
done

for one in "${FAILED[@]}"; do
  echo "  FAIL  $one"
done

echo
echo "  reports under $(cd "$HERE/.." && pwd)/.output/"
echo

[ ${#FAILED[@]} -eq 0 ]
