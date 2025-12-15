#!/usr/bin/env bash
# Generate clean dependency graph for the workspace
# Excludes top-level application crates to show core architecture

set -e

cd "$(dirname "$0")/.."

cargo depgraph \
    --workspace-only \
    --exclude wasm-demo \
    --exclude benchmarks \
    | dot -Tpng > deps_graph.png

echo "✓ Dependency graph generated: deps_graph.png"
