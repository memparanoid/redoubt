#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Every publishable crate, in an order where each one's dependencies are on
# crates.io before it is.
#
# # Why the list is written out
#
# It could be computed from `cargo metadata`, and then a mistake in the
# computation would be a release rather than a failed script. Written out, the
# order is a thing a reader checks against the manifests before anything is
# uploaded, and an upload cannot be taken back.
#
# # What the order is, and what is not in it
#
# Dependencies, and build dependencies. Not dev-dependencies: those form
# genuine cycles here — `redoubt-vault-derive` builds its tests against
# `redoubt-vault`, which depends on it — and they resolve against what is
# already on crates.io rather than against this run.
#
# The crates carrying `publish = false` are absent: the fixtures, the
# examples, the benchmarks and the memory analysis.

set -euo pipefail

# Each line's crates depend on earlier lines and on nothing below.
CRATES=(
  # Nothing in the workspace
  redoubt-asm
  redoubt-codec-derive
  redoubt-forensics
  redoubt-mem
  redoubt-test-utils
  redoubt-util
  redoubt-vault-derive

  redoubt-aead-core
  redoubt-zero-core
  redoubt-zero-derive
  redoubt-zero

  redoubt-aead-aegis128l
  redoubt-alloc
  redoubt-buffer
  redoubt-chacha
  redoubt-hkdf
  redoubt-poly1305

  redoubt-aead-xchachapoly1305
  redoubt-codec-core
  redoubt-rand
  redoubt-codec
  redoubt-aead
  redoubt-secret

  redoubt-vault-core
  redoubt-vault
  redoubt
)

# `--no-verify` skips the rebuild each publish would otherwise do, which CI has
# already done for every target this ships to.
for crate in "${CRATES[@]}"; do
  echo "Publishing $crate..."

  if ! cargo publish -p "$crate" --no-verify 2>&1 | tee /tmp/publish_output; then
    if grep -q "already uploaded" /tmp/publish_output; then
      echo "  (already published, skipping)"
    else
      echo "  FAILED"
      exit 1
    fi
  fi

  echo ""

  # The index is what the next crate resolves its dependencies against, and it
  # is written after the upload answers.
  sleep 5
done

echo "Done! All crates published."
