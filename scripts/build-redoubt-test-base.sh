#!/usr/bin/env bash
# Build redoubt-test-base image for native architecture
#
# Usage:
#   ./scripts/build-redoubt-test-base.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building redoubt-test-base for native architecture..."
DOCKER_BUILDKIT=1 docker buildx build \
    -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-test-base" \
    -t redoubt-test-base:latest \
    --load \
    "$PROJECT_ROOT"

echo "✓ redoubt-test-base:latest built successfully"
