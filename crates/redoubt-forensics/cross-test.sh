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
# next without being edited.
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
CRATE="$(basename "$HERE")"

CROSS_CC="${CROSS_CC:-aarch64-unknown-linux-musl-gcc}"
QEMU="${QEMU:-qemu-aarch64}"

for needed in "$CROSS_CC" "$QEMU"; do
  command -v "$needed" >/dev/null || {
    echo "missing: $needed" >&2
    echo "set CROSS_CC and QEMU if they go by other names here" >&2
    exit 1
  }
done

cd "$HERE"

echo "== $CRATE on x86_64 =="
cargo nextest run -p "$CRATE" --release

echo
echo "== $CRATE on aarch64, under $QEMU =="

# `cc` looks for its compiler by a name of its own choosing, and cargo for the
# linker by another, so both are told which one this is.
CC_aarch64_unknown_linux_musl="$CROSS_CC" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$QEMU" \
  cargo nextest run -p "$CRATE" --release --target aarch64-unknown-linux-musl
