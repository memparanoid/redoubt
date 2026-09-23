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
# # Dev-dependencies count
#
# A dev-dependency that names a version is kept in the published manifest and
# has to resolve. A prerelease requirement asks for that prerelease or a later
# one, so the release being cut is never satisfied by the one before it. That
# is why `redoubt-codec-derive` waits for `redoubt-codec-core` although it only
# builds its tests against it.
#
# A dev-dependency given a path and no version is dropped when the package is
# packed, so it constrains nothing. `redoubt-util` depending on itself that way
# is the reason its own tests see its `test-utils` feature.
#
# The crates carrying `publish = false` are absent: the fixtures, the
# examples, the benchmarks and the memory analysis.

set -euo pipefail

# Each crate depends on ones above it and on none below.
CRATES=(
  redoubt-asm
  redoubt-forensics
  redoubt-test-utils
  redoubt-util

  redoubt-aead-core
  redoubt-mem
  redoubt-zero-core
  redoubt-zero-derive
  redoubt-zero

  redoubt-aead-aegis128l
  redoubt-alloc
  redoubt-chacha
  redoubt-hkdf
  redoubt-poly1305

  redoubt-aead-xchachapoly1305
  redoubt-codec-core
  redoubt-rand
  redoubt-buffer
  redoubt-codec-derive
  redoubt-codec
  redoubt-aead
  redoubt-secret

  redoubt-vault-core
  redoubt-vault-derive
  redoubt-vault
  redoubt
)

# `--no-verify` skips the rebuild each publish would otherwise do, which CI has
# already done for every target this ships to.
for crate in "${CRATES[@]}"; do
  echo "Publishing $crate..."

  if ! cargo publish -p "$crate" --no-verify 2>&1 | tee /tmp/publish_output; then
    # Two refusals, because a version that is already there is refused twice
    # over: by the index, which cargo reads before it uploads anything, and by
    # the registry, which answers the upload itself. Which one comes back
    # depends on how fresh the local index is.
    if grep -qE "already exists on crates.io index|already uploaded" /tmp/publish_output; then
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
