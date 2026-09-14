#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The machine, stopped.
#
# Nothing is saved on the way out. What `up.sh` restores is the state
# `build.sh` froze, every time, so a machine that ran tests for an hour and one
# that has just come up are the same machine next time — which is what a test
# bed is for. Anything worth keeping was copied out while it ran.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./common.sh
. "$HERE/common.sh"

if [ ! -S "$MONITOR" ]; then
  echo "not up"
  exit 0
fi

monitor "quit" || true

# It has been told. Whether it went is another matter, and a machine that did
# not go holds the image open against the next restore.
for _ in $(seq 1 20); do
  if [ ! -f "$PIDFILE" ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    rm -f "$MONITOR" "$PIDFILE"
    echo "down"

    exit 0
  fi

  sleep 1
done

echo "it did not go. Its pid is in $PIDFILE." >&2

exit 1
