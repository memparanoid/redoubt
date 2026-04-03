#!/usr/bin/env bash
set -e

# Publish order based on dependency graph
# Uses --no-verify to skip local rebuild (already tested in CI)
CRATES=(
  # No dependencies
  redoubt-util
  redoubt-test-utils
  redoubt-guard

  # redoubt-zero stack
  redoubt-zero-core    # deps: redoubt-util
  redoubt-zero-derive  # deps: redoubt-zero-core
  redoubt-zero         # deps: redoubt-zero-core, redoubt-zero-derive

  # redoubt-hkdf stack
  redoubt-hkdf-core       # deps: thiserror
  redoubt-hkdf-wycheproof # deps: redoubt-hkdf-core, redoubt-util
  redoubt-hkdf-rust       # deps: redoubt-hkdf-core, redoubt-zero, redoubt-util (dev: redoubt-hkdf-wycheproof)
  redoubt-hkdf-x86        # deps: redoubt-hkdf-core, cc (dev: redoubt-hkdf-wycheproof)
  redoubt-hkdf-arm        # deps: redoubt-hkdf-core, cc (dev: redoubt-hkdf-wycheproof)
  redoubt-hkdf            # deps: redoubt-hkdf-core, redoubt-hkdf-rust, redoubt-hkdf-x86, redoubt-hkdf-arm

  # Core utilities
  redoubt-rand         # deps: redoubt-hkdf, redoubt-zero
  redoubt-alloc        # deps: redoubt-util, redoubt-zero

  # redoubt-aead stack
  redoubt-aead-core          # deps: redoubt-rand, thiserror
  redoubt-aead-aegis-wycheproof # deps: redoubt-aead-core, redoubt-util
  redoubt-aead-xchacha       # deps: redoubt-aead-core, redoubt-rand, redoubt-util, redoubt-zero
  redoubt-aead-aegis-x86     # deps: redoubt-aead-core, redoubt-rand, redoubt-util, cc (dev: redoubt-aead-aegis-wycheproof)
  redoubt-aead-aegis-arm     # deps: redoubt-aead-core, redoubt-rand, redoubt-util, cc (dev: redoubt-aead-aegis-wycheproof)
  redoubt-aead               # deps: redoubt-aead-core, redoubt-aead-xchacha, redoubt-aead-aegis-x86, redoubt-aead-aegis-arm

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
  if ! cargo publish -p "$crate" --no-verify 2>&1 | tee /tmp/publish_output; then
    if grep -q "already uploaded" /tmp/publish_output; then
      echo "  (already published, skipping)"
    else
      echo "  FAILED"
      exit 1
    fi
  fi
  echo ""
  sleep 5  # Wait for crates.io index to update
done

echo "Done! All crates published."
