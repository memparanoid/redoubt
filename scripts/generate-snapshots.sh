#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo run --quiet --manifest-path scripts/Cargo.toml --bin generate-snapshots
