#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The machine, back the way `build.sh` left it.
#
# Restored and not booted. A first boot under emulation is minutes, and a
# restore is the seconds it takes to read the state out of the image — which is
# the difference between running one test on `aarch64` and not bothering.
#
# Already up is not an error. Something wanting the machine is something that
# wants it running, and it is running.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./common.sh
. "$HERE/common.sh"

[ -f "$DISK" ] || {
  echo "nothing built yet. Run build.sh first." >&2
  exit 1
}

if running; then
  echo "already up on port $SSH_PORT"
  exit 0
fi

# A monitor socket from a machine that is gone. Left behind by a kill, and in
# the way of the one about to start.
rm -f "$MONITOR"

echo "restoring"

boot -loadvm "$SNAPSHOT" -daemonize

for _ in $(seq 1 30); do
  if ssh_in true 2>/dev/null; then
    echo "up on port $SSH_PORT"
    exit 0
  fi

  sleep 1
done

echo "restored, but it never answered. The console log is $VM_HOME/console.log" >&2

exit 1
