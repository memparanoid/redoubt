#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The crate's tests on both architectures, the second one emulated.
#
# Cross-compiling says the code builds; it does not say it answers. An
# implementation written per architecture — assembly above all — is worth
# nothing until it has been read against its oracle on the architecture it was
# written for, and this is what reads it.
#
# The crate is whichever one this file sits in, so it copies from one to the
# next without being edited. Its name comes from the manifest and not from the
# directory: `crates/redoubt-codec/core` is the crate `redoubt-codec-core`, and
# `-p core` matches nothing.
#
# Optimized, on both. An assembler optimizes nothing, so hand-written code is
# the same instructions in either profile, and a debug run spends its time on
# the portable backend instead — under emulation, minutes of it. What release
# gives up is the debug assertions, and those are seconds away on this
# architecture: `cargo nextest run -p <crate>`, as usual.
#
# What it needs: the `aarch64-unknown-linux-musl` target, `qemu-aarch64`, and a
# cross compiler for any assembly or C in the crate and its dependencies. The
# names below are what this machine calls them; a machine that calls them
# something else says so in CROSS_CC and QEMU rather than here.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$(sed -n 's/^name *= *"\(.*\)".*/\1/p' "$HERE/Cargo.toml" | head -1)"

[ -n "$CRATE" ] || {
  echo "no package name in $HERE/Cargo.toml" >&2
  exit 1
}

CROSS_CC="${CROSS_CC:-aarch64-unknown-linux-musl-gcc}"
MUSL_CC="${MUSL_CC:-x86_64-unknown-linux-musl-gcc}"
QEMU="${QEMU:-qemu-aarch64}"

for needed in "$CROSS_CC" "$MUSL_CC" "$QEMU"; do
  command -v "$needed" >/dev/null || {
    echo "missing: $needed" >&2
    echo "set CROSS_CC, MUSL_CC and QEMU if they go by other names here" >&2
    exit 1
  }
done

cd "$HERE"

# A crate that cannot be built whole for the other architecture says here which
# part of it can, in a `cross-test.args` beside this file — data, so that the
# script itself stays the same in every crate.
#
# `redoubt-vault-core` is the one: its lib tests link `libseccomp`, which has no
# static build for this target, and would not mean anything under emulation if
# it had one — a filter built for aarch64 loaded into a process whose real
# syscalls are the host's. `--test forensics` builds the integration target
# alone, which is the part worth reading on both.
EXTRA=()

[ -f "$HERE/cross-test.args" ] && read -ra EXTRA < "$HERE/cross-test.args"

# Three runs, so that the two things that differ are separated. Against the
# first, the second changes the C library and nothing else, and the third
# changes the architecture and nothing else. A difference that showed only in
# one pair would otherwise be unattributable to either.
#
# What the C library decides is the allocator, and the allocator decides what a
# freed chunk keeps: glibc leaves everything past its first bytes where it was,
# musl's `mallocng` may cover the lot. A sweep reads whatever is left.
#
# The fourth corner, aarch64 with glibc, wants a cross compiler this machine
# does not have. `ubuntu-24.04-arm` in CI is that corner.
echo "== $CRATE on x86_64, glibc =="
cargo nextest run -p "$CRATE" --release ${EXTRA[@]+"${EXTRA[@]}"}

echo
echo "== $CRATE on x86_64, musl =="

CC_x86_64_unknown_linux_musl="$MUSL_CC" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_CC" \
  cargo nextest run -p "$CRATE" --release --target x86_64-unknown-linux-musl \
  ${EXTRA[@]+"${EXTRA[@]}"}

echo
echo "== $CRATE on aarch64, musl, under $QEMU =="

# `cc` looks for its compiler by a name of its own choosing, and cargo for the
# linker by another, so both are told which one this is.
CC_aarch64_unknown_linux_musl="$CROSS_CC" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$QEMU" \
  cargo nextest run -p "$CRATE" --release --target aarch64-unknown-linux-musl \
  ${EXTRA[@]+"${EXTRA[@]}"}
