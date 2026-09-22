#!/usr/bin/env bash
# Generate clean dependency graph for the workspace
# Excludes top-level application crates to show core architecture

set -e

cd "$(dirname "$0")/.."

cargo depgraph \
    --workspace-only \
    --exclude wasm-example \
    --exclude benchmarks \
    --exclude dummy-codec \
    --exclude dummy-vault \
    --exclude dummy-zero \
    --exclude test-a \
    --exclude test-b \
    --exclude wallet-example \
    | dot -Tpng > deps_graph.png

echo "✓ Dependency graph generated: deps_graph.png"
