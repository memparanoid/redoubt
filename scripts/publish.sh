#!/bin/bash
set -e

CRATES=(
  redoubt-test-utils
  redoubt-codec-core
  redoubt-codec-derive
  redoubt-codec
  redoubt-secret
  redoubt-vault-core
  redoubt-vault-derive
  redoubt-vault
  redoubt
)

for crate in "${CRATES[@]}"; do
  echo "Publishing $crate..."
  cargo publish -p "$crate"
  echo "Waiting for crates.io to index..."
  sleep 15
done

echo "Done!"
