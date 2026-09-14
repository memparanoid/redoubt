# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Which machine, where it lives, and how to reach it. Sourced, not run.
#
# One of these per architecture, and the one wanted is whichever this host is
# not: a machine of the host's own architecture is the host, and the tests run
# on it already.

ARCH="${ARCH:-aarch64}"

case "$ARCH" in
  aarch64)
    UBUNTU_ARCH="arm64"
    # What `get.nexte.st` calls this. The only thing installed in the machine,
    # because the test binaries arrive already linked.
    NEXTEST_BUILD="linux-arm"
    QEMU="qemu-system-aarch64"
    # `virt` is the only board qemu offers for this that is not a particular
    # phone, and `gic-version=3` is the interrupt controller anything since
    # ARMv8.2 has.
    MACHINE="virt,gic-version=3"
    SSH_PORT="${SSH_PORT:-2222}"
    # No BIOS here. It boots UEFI, which is a pair of files: the firmware
    # itself, read only, and a writable store for its variables.
    FIRMWARE="edk2-aarch64-code.fd"
    # Where the machine keeps its dynamic loader. A glibc binary names the
    # loader it wants by absolute path, and a cross compiler names its own —
    # which on this host is inside the nix store and inside the machine is
    # nowhere. A binary whose loader is missing does not report a missing
    # loader: `exec` answers ENOENT, as if the binary itself were not there.
    LOADER="/lib/ld-linux-aarch64.so.1"
    ;;
  x86_64)
    UBUNTU_ARCH="amd64"
    NEXTEST_BUILD="linux"
    QEMU="qemu-system-x86_64"
    MACHINE="q35"
    SSH_PORT="${SSH_PORT:-2223}"
    # And a BIOS here, which qemu supplies without being asked.
    FIRMWARE=""
    LOADER="/lib64/ld-linux-x86-64.so.2"
    ;;
  *)
    echo "no machine for $ARCH" >&2
    return 1
    ;;
esac

# Beside the scripts that make it, and ignored by the `.gitignore` next to
# them. It is twenty gigabytes and none of it is source.
VM_HOME="${VM_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$ARCH}"

# The images Ubuntu publishes, kept. They are what a build starts from and a
# gigabyte each, so a machine thrown away and built again is a conversion rather
# than a download. Beside the machines and outside them, because the same
# release for the same architecture is the same file however many times a
# machine is rebuilt from it.
CACHE="${CACHE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cache}"

DISK="$VM_HOME/disk.qcow2"
SEED="$VM_HOME/seed.iso"
EFI_CODE="$VM_HOME/efi-code.fd"
# qcow2 and not raw, because it is writable and qemu refuses to snapshot a
# writable device that cannot hold one — which is the freeze this exists for.
EFI_VARS="$VM_HOME/efi-vars.qcow2"
KEY="$VM_HOME/key"

# Where the monitor and the guest's ssh are. The monitor is a socket and not a
# port: it is how the machine is told to freeze itself, and nothing outside
# this directory has any business saying that.
MONITOR="$VM_HOME/monitor.sock"
PIDFILE="$VM_HOME/pid"

# Loopback alone. The machine has no firewall, no updates and a key with no
# passphrase, and all three are fine exactly as long as nothing but this host
# can reach it.
VM_USER="ubuntu"

# What the state saved into the image is called.
SNAPSHOT="frozen"

# How much of this machine it gets. Four cores because the tests are one
# process each and nextest will use them; two gigabytes because nothing in
# here compiles and the tests are small.
VM_CORES="${VM_CORES:-4}"
VM_RAM="${VM_RAM:-2048}"

# Start it, with everything that has to be the same between a build and a
# restore.
#
# `-cpu max` and not a named core: it turns on everything this qemu can
# emulate, the vector extensions included, and what the capture reaches depends
# on which of those a machine has.
#
# `-display none` and not `-nographic`, which qemu refuses alongside
# `-daemonize` — and `up.sh` daemonizes. The console is on a file either way.
#
# Everything writable here is qcow2, and the seed — which is neither — is
# read-only. qemu refuses to save the machine's state while any writable device
# cannot hold one, and it refuses it into a monitor socket nobody is reading, so
# a drive that forgets this leaves a machine that builds and cannot be frozen.
#
# No `-snapshot`. That flag throws away every write when the machine stops,
# which would be sensible for a machine nobody has to freeze and is exactly
# wrong for one whose whole purpose is to be frozen.
boot() {
  local firmware=()

  if [ -n "$FIRMWARE" ]; then
    firmware=(
      -drive "if=pflash,format=raw,readonly=on,file=$EFI_CODE"
      -drive "if=pflash,format=qcow2,file=$EFI_VARS"
    )
  fi

  "$QEMU" \
    -machine "$MACHINE" \
    -cpu max \
    -smp "$VM_CORES" \
    -m "$VM_RAM" \
    -display none \
    -serial "file:$VM_HOME/console.log" \
    -monitor "unix:$MONITOR,server,nowait" \
    -pidfile "$PIDFILE" \
    "${firmware[@]}" \
    -drive "if=virtio,format=qcow2,file=$DISK" \
    -drive "if=virtio,format=raw,file=$SEED,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=net0 \
    "$@"
}

# One line to the monitor, which is how the machine is told things a guest
# cannot tell itself, and whatever it answers.
#
# The answer is the point. A monitor command that qemu refuses says so there and
# nowhere else — it is not an exit status, nothing else reports it, and a
# `savevm` that was refused leaves a machine that looks built.
monitor() {
  printf '%s\n' "$1" | socat - "UNIX-CONNECT:$MONITOR" 2>/dev/null
}

# Something, in there.
#
# The known-hosts file is its own and thrown away with the machine: this is a
# host that is rebuilt whenever anybody feels like it, and warning about a
# changed key every time would train somebody to ignore the warning that
# matters.
ssh_in() {
  ssh \
    -i "$KEY" \
    -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    "$VM_USER@127.0.0.1" \
    "$@"
}

# And something, into there.
copy_in() {
  scp \
    -i "$KEY" \
    -P "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    "$1" \
    "$VM_USER@127.0.0.1:$2"
}

# Whether it is up, asked of the machine rather than of a file somebody may
# have left behind.
running() {
  [ -S "$MONITOR" ] && ssh_in true 2>/dev/null
}
