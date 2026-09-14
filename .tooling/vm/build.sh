#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# An `aarch64` machine to run the tests on, built once and then frozen.
#
# # Why a whole machine
#
# `qemu-aarch64` — the one every `cross-test.sh` uses — emulates a process. It
# translates the instructions and hands the syscalls to the host kernel, and a
# host kernel cannot be asked to make one emulated process the tracer of
# another. So `ptrace` is refused there, and the analysis falls back to reading
# itself: two processes where there would have been three.
#
# That is a real path and it is the one every `aarch64` run of this workspace
# has ever taken. What none of them took is the other one — and the other one
# is what the `ubuntu-24.04-arm` runner takes, where sixteen tests die on a
# signal that no machine here can produce.
#
# A whole machine has its own kernel, so it has `ptrace`, so it takes the path
# that breaks. That is the entire reason this exists.
#
# # Ubuntu 24.04, and not something smaller
#
# Because the runner is `ubuntu-24.04-arm`. A crash that happens on one kernel
# and one C library is not a thing to reproduce on a different kernel and a
# different C library.
#
# # What it does not have
#
# A compiler. Nothing is built in here — emulating an `aarch64` system on an
# `x86_64` host has no KVM to lean on, so it is `TCG` all the way down and
# compiling a workspace would take an afternoon. The test binaries are built
# on the host, where they always were, and only run in here.
#
# # Frozen
#
# The last thing this does is save the machine's state into the image. After
# that `up.sh` restores it in seconds rather than booting it, which is what
# makes running one test in here a thing anybody will actually do.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./common.sh
. "$HERE/common.sh"

RELEASE="${RELEASE:-noble}"
IMAGE_URL="https://cloud-images.ubuntu.com/$RELEASE/current/$RELEASE-server-cloudimg-$UBUNTU_ARCH.img"

mkdir -p "$VM_HOME"

# Frozen, and not merely present. A disk that exists without a saved state
# inside it is a build that stopped somewhere in the middle, and the machine
# that answers is the one this asks about — `up.sh` restores a state, so a disk
# without one starts nothing.
if [ -f "$DISK" ] && qemu-img snapshot -l "$DISK" 2>/dev/null | grep -q "$SNAPSHOT"; then
  echo "already built: $DISK"
  echo "delete it to build again, or run up.sh to start it."

  exit 0
fi

rm -f "$DISK"

# ----------------------------------------------------------------------------
# The firmware
# ----------------------------------------------------------------------------

# Only where there is one. `x86_64` boots a BIOS that qemu supplies without
# being asked; `aarch64` has none and boots UEFI, which is a pair of files —
# the firmware itself, read only, and a writable store for its variables. Both
# have to be exactly 64 MiB, because the firmware is built for that size and
# refuses another.
#
# One condition each, because they are two files: a single guard over the pair
# makes the second one's absence invisible whenever the first one is there, and
# what qemu then says is that it cannot open a file this script is supposed to
# have made.
if [ -n "$FIRMWARE" ] && [ ! -f "$EFI_CODE" ]; then
  # Beside the qemu that will read it, found from the binary rather than from
  # a list of places distributions put it. Its own installation is the one
  # place it is certain to be.
  beside="$(dirname "$(dirname "$(readlink -f "$(command -v "$QEMU")")")")"

  # `-print -quit` and not a pipe into `head`: under `pipefail` the pipe kills
  # `find` with `SIGPIPE` as soon as the first line is taken, and a pipeline
  # that ends in a signal is a failed one.
  code="$(find "$beside/share" /usr/share/qemu /usr/share/AAVMF \
    -name "$FIRMWARE" -print -quit 2>/dev/null)"

  [ -n "$code" ] || {
    echo "no $FIRMWARE found beside $QEMU or in the usual places." >&2
    echo "It ships with qemu." >&2
    exit 1
  }

  cp "$code" "$EFI_CODE"
  chmod u+w "$EFI_CODE"
fi

if [ -n "$FIRMWARE" ] && [ ! -f "$EFI_VARS" ]; then
  qemu-img create -q -f qcow2 "$EFI_VARS" 64m
fi

# ----------------------------------------------------------------------------
# The disk
# ----------------------------------------------------------------------------

CLOUD="$CACHE/$RELEASE-server-cloudimg-$UBUNTU_ARCH.img"

mkdir -p "$CACHE"

# Only once per release and architecture. Downloaded beside its own name and
# moved into place afterwards, so an interrupted download is never read back as
# a cached image — there is nothing in a truncated one that says it is short.
if [ ! -f "$CLOUD" ]; then
  echo "== fetching $RELEASE for $UBUNTU_ARCH =="

  curl -fL --progress-bar -o "$CLOUD.part" "$IMAGE_URL"
  mv "$CLOUD.part" "$CLOUD"
else
  echo "== $RELEASE for $UBUNTU_ARCH is already here =="
fi

# qcow2 and not raw, because a raw disk cannot hold a saved machine state and
# the saved state is the whole point of building this once.
qemu-img convert -O qcow2 "$CLOUD" "$DISK"
qemu-img resize -q "$DISK" 20G

# ----------------------------------------------------------------------------
# The key and the first boot
# ----------------------------------------------------------------------------

# Its own key, made here and used nowhere else. The machine is local, it is
# reachable on the loopback alone, and it is thrown away and built again
# whenever anybody feels like it — so there is nothing for a passphrase to
# protect and something for one to interrupt, which is the only thing a build
# that wants to run unattended cannot have.
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'redoubt-vm' -f "$KEY"
fi

echo "== first boot, installing =="

cat >"$VM_HOME/user-data" <<EOF
#cloud-config
hostname: redoubt-$ARCH
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
packages:
  - libseccomp2
runcmd:
  # What runs the tests. Nothing else is needed: a nextest archive carries the
  # binaries already linked, so there is no toolchain in here to keep in step
  # with the host's.
  - [sh, -c, "curl -fL https://get.nexte.st/latest/$NEXTEST_BUILD | tar zxf - -C /usr/local/bin"]
  # Written last, and looked for before the machine is frozen: a provisioning
  # that gave up halfway leaves a machine that boots, answers, and has nothing
  # to run the tests with.
  - [sh, -c, "echo READY_FOR_SNAPSHOT > /var/lib/cloud/redoubt-built"]
EOF

cloud-localds "$SEED" "$VM_HOME/user-data"

boot &
BOOTED=$!

trap 'kill "$BOOTED" 2>/dev/null || true' EXIT

echo "-- waiting for it to come up (a first boot under emulation is minutes)"

for _ in $(seq 1 120); do
  if ssh_in true 2>/dev/null; then
    break
  fi

  sleep 10
done

ssh_in true || {
  echo "it never came up. The console log is $VM_HOME/console.log" >&2
  exit 1
}

echo "-- waiting for cloud-init to finish"

ssh_in "cloud-init status --wait" >/dev/null 2>&1 || true
ssh_in "test -f /var/lib/cloud/redoubt-built" || {
  echo "cloud-init did not finish what it was given" >&2
  exit 1
}

# ----------------------------------------------------------------------------
# Frozen
# ----------------------------------------------------------------------------

echo "== freezing =="

# Through the monitor, because the machine has to be running to have a state
# worth saving. `savevm` writes it into the qcow2 beside the disk contents, and
# `up.sh` reads it back instead of booting.
monitor "savevm $SNAPSHOT"
monitor "quit" || true

wait "$BOOTED" 2>/dev/null || true

trap - EXIT

# Asked of the image, because the monitor answers into a socket nobody reads: a
# `savevm` that qemu refused says so there and nowhere else, and what is left
# behind is a machine that builds, boots, answers, and cannot be restored.
qemu-img snapshot -l "$DISK" | grep -q "$SNAPSHOT" || {
  echo "it was never frozen. The console log is $VM_HOME/console.log" >&2
  exit 1
}

echo
echo "built and frozen: $DISK"
echo "start it with up.sh, run something in it with scripts/cross-nextest.sh"
