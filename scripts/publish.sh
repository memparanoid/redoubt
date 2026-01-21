#!/bin/bash
set -e

# Publish order based on dependency graph
CRATES=(
  # No dependencies
  redoubt-util
  redoubt-test-utils
  redoubt-guard

  # redoubt-zero stack
  redoubt-zero-core    # deps: redoubt-util
  redoubt-zero-derive  # deps: redoubt-zero-core
  redoubt-zero         # deps: redoubt-zero-core, redoubt-zero-derive

  # Core utilities
  redoubt-hkdf         # deps: redoubt-util, redoubt-zero
  redoubt-rand         # deps: redoubt-hkdf, redoubt-zero
  redoubt-alloc        # deps: redoubt-util, redoubt-zero
  redoubt-aead         # deps: redoubt-rand, redoubt-util, redoubt-zero
  redoubt-buffer       # deps: redoubt-util, redoubt-zero, redoubt-rand

  # redoubt-codec stack
  redoubt-codec-core   # deps: redoubt-alloc, redoubt-util, redoubt-zero, redoubt-test-utils
  redoubt-codec-derive # deps: redoubt-codec-core, redoubt-zero
  redoubt-codec        # deps: redoubt-codec-core, redoubt-codec-derive

  # Higher level
  redoubt-secret       # deps: redoubt-alloc, redoubt-codec, redoubt-util, redoubt-zero

  # redoubt-vault stack
  redoubt-vault-core   # deps: redoubt-aead, redoubt-alloc, redoubt-buffer, redoubt-codec, redoubt-guard, redoubt-rand, redoubt-secret, redoubt-zero
  redoubt-vault-derive # deps: redoubt-aead, redoubt-alloc, redoubt-codec, redoubt-secret, redoubt-vault-core, redoubt-zero
  redoubt-vault        # deps: redoubt-vault-core, redoubt-vault-derive

  # Main crate
  redoubt              # deps: everything
)

for crate in "${CRATES[@]}"; do
  echo "Publishing $crate..."
  cargo publish -p "$crate"
  echo ""
done

echo "Done! All crates published."
