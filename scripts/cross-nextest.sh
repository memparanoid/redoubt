#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The tests on a machine with a kernel of its own.
#
# # What this reaches that `cross-test.sh` does not
#
# `qemu-aarch64` emulates a process and hands the syscalls to the host kernel,
# and a host kernel cannot be told that one emulated process is the tracer of
# another. So `ptrace` is refused there and the analysis reads itself: two
# processes where there would have been three.
#
# Every `aarch64` run this workspace has ever done took that path, and the
# other one — the one `ubuntu-24.04-arm` takes, where sixteen tests die on a
# signal — took none of them. A machine with its own kernel has `ptrace`, so it
# takes the path that breaks.
#
# `cross-test.sh` is still the one to reach for. It is seconds where this is
# minutes, and it covers the other C library and the architecture in one go.
# This is for the questions it cannot answer.
#
# # Built here, run there
#
# `cargo nextest archive` writes the test binaries, already linked, into one
# file. Nothing is compiled in the machine — emulating a system has no KVM to
# lean on, so a workspace built in there would take an afternoon, and a
# toolchain in there is a second toolchain to keep in step with this one.
#
# # Arguments
#
# Whatever `nextest` takes, which is what this is named for:
# `cross-nextest.sh -p redoubt-forensics`. With none, the whole workspace.
#
# Which machines is `ARCH`. With none, every machine that has been built —
# which on a host that develops away from one architecture is the one, and on
# a host that has built both is both.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VMS="$ROOT/.tooling/vm"

# Debug by default, because that is what the workflow runs and what the
# instrument is sensitive to: what a sweep finds is whatever the compiler left
# on the stack, and release leaves less of it. `RELEASE=1` for the other one.
PROFILE=()

[ -z "${RELEASE:-}" ] || PROFILE=(--release)

cd "$ROOT"

# Which machines there are, asked of the disks rather than of a list: a machine
# exists when it has been built, and `build.sh` is what builds one.
if [ -n "${ARCH:-}" ]; then
  MACHINES=("$ARCH")
else
  MACHINES=()

  for one in "$VMS"/*/; do
    [ -f "$one/disk.qcow2" ] && MACHINES+=("$(basename "$one")")
  done
fi

[ ${#MACHINES[@]} -gt 0 ] || {
  echo "no machine built yet." >&2
  echo "ARCH=aarch64 $VMS/build.sh" >&2
  exit 1
}

DONE=()
FAILED=()

for arch in "${MACHINES[@]}"; do
  echo
  echo "################################################################"
  echo "## $arch"
  echo "################################################################"

  # A subshell each, because every one of these names the same variables for a
  # different machine and nothing of one should reach the next.
  #
  # Not inside an `if`, and not followed by `||`: either of those is a condition
  # context, where `errexit` is suppressed for everything in the subshell and
  # stays suppressed however many times it is set again. A machine that never
  # came up would go on to build an archive and copy it nowhere. So the status
  # is taken afterwards instead, which is also what lets one machine fail
  # without taking the machines after it.
  set +e

  (
    set -e

    export ARCH="$arch"

    # shellcheck source=../.tooling/vm/common.sh
    . "$VMS/common.sh"

    # Both C libraries, for the reason `cross-test.sh` runs both: the C library
    # decides the allocator, and the allocator decides what a freed chunk
    # keeps. glibc leaves everything past a chunk's first bytes where it was;
    # musl's `mallocng` may cover the lot. A sweep reads whatever is left.
    #
    # A musl build links statically and runs on the machine anyway, so one
    # machine serves both.
    TARGETS=(
      "$arch-unknown-linux-gnu:${GNU_CC:-$arch-unknown-linux-gnu-gcc}"
      "$arch-unknown-linux-musl:${MUSL_CC:-$arch-unknown-linux-musl-gcc}"
    )

    HAVE=()

    for one in "${TARGETS[@]}"; do
      if command -v "${one#*:}" >/dev/null; then
        HAVE+=("$one")
      else
        echo "skipping ${one%%:*}: no ${one#*:}. See .tooling/vm/DEPENDENCIES.md"
      fi
    done

    [ ${#HAVE[@]} -gt 0 ] || {
      echo "no cross compiler for either C library on $arch" >&2
      exit 1
    }

    # Up for this machine and down again when the run leaves, however it
    # leaves. What a machine holds is the memory of one run, and the state worth
    # keeping is the one `build.sh` froze into the image — restored whole by the
    # next `up.sh`. A run that died on a failing test and left the machine up
    # would hand the next run a machine that is no longer the frozen one.
    #
    # The trap does not exit, so the status the subshell leaves with is the
    # run's own and not the shutdown's.
    trap '"$VMS/down.sh" >/dev/null 2>&1 || true' EXIT

    "$VMS/up.sh"

    # The source, tracked files alone. An archive carries the test binaries but
    # not the workspace they describe, and nextest reads the manifests to know
    # what it is running — so `--workspace-remap` wants somewhere that is
    # actually the workspace. `git archive` is what settles which files those
    # are: it is a few megabytes, and it leaves `target/` out by construction.
    git archive --format=tar --prefix=redoubt/ HEAD |
      gzip -1 >"$ROOT/target/source.tar.gz"

    copy_in "$ROOT/target/source.tar.gz" "/tmp/source.tar.gz"

    ssh_in "rm -rf /tmp/redoubt && tar xzf /tmp/source.tar.gz -C /tmp"

    for one in "${HAVE[@]}"; do
      target="${one%%:*}"
      cc="${one#*:}"
      archive="$ROOT/target/$target-tests.tar.zst"
      # `cc` looks for its compiler by a name of its own choosing, and cargo
      # for the linker by another, so both are told which one this is.
      named="$(echo "$target" | tr 'a-z-' 'A-Z_')"

      echo
      echo "== $target =="
      echo

      # The glibc half alone: a static musl binary asks for no loader at all,
      # and asking it to want one links nothing.
      loader=()

      if [ "${target##*-}" = "gnu" ]; then
        loader=("CARGO_TARGET_${named}_RUSTFLAGS=-C link-arg=-Wl,-dynamic-linker,$LOADER")
      fi

      env \
        "CC_${target//-/_}=$cc" \
        "CARGO_TARGET_${named}_LINKER=$cc" \
        "${loader[@]}" \
        cargo nextest archive \
        --target "$target" \
        "${PROFILE[@]}" \
        --archive-file "$archive" \
        "$@"

      copy_in "$archive" "/tmp/tests.tar.zst"

      # `--workspace-remap`, because the archive remembers where it was built
      # and the workspace is somewhere else in here.
      #
      # `cargo-nextest nextest`, which is what the binary is called and how it
      # wants to be asked: it is built as a cargo subcommand, so the first word
      # after it is the one cargo would have eaten.
      # `--color always`, because what runs in there has no terminal: the ssh
      # is not on a tty, so nextest reads that as nobody watching and answers
      # in plain text. The one watching is here.
      ssh_in "cd /tmp/redoubt && cargo-nextest nextest run \
        --archive-file /tmp/tests.tar.zst \
        --workspace-remap /tmp/redoubt \
        --color always \
        --no-fail-fast \
        --success-output final"
    done
  )

  status=$?

  set -e

  if [ "$status" -eq 0 ]; then
    DONE+=("$arch")
  else
    FAILED+=("$arch")
  fi
done

echo
echo "################################################################"
echo "## read: ${DONE[*]:-none}"

[ ${#FAILED[@]} -eq 0 ] || echo "## failed: ${FAILED[*]}"

echo "################################################################"
echo

[ ${#FAILED[@]} -eq 0 ]
