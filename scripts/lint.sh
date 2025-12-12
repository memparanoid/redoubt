#!/usr/bin/env bash
# Run linting in Docker (captures Linux-specific warnings)
#
# Usage:
#   ./scripts/lint.sh                    # Lint entire workspace
#   ./scripts/lint.sh -p <crate>         # Lint specific crate

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building lint Docker image..."
DOCKER_BUILDKIT=1 docker build -f "$PROJECT_ROOT/docker/Dockerfile.test" -t memora-lint "$PROJECT_ROOT"

echo "Running cargo make lint..."
docker run --rm \
  -v memora-cargo-cache:/usr/local/cargo/registry \
  -v memora-target-cache:/workspace/target \
  memora-lint cargo make lint "$@"
