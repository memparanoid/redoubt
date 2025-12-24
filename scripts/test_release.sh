#!/usr/bin/env bash
# Run release tests locally and in Docker for both architectures
#
# Usage:
#   ./scripts/test_release.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Build base image for both architectures
echo "Building base image..."
"$SCRIPT_DIR/build-redoubt-test-base.sh"

# Run tests locally
echo ""
echo "Running release tests locally..."
cargo test --release --workspace --all-features

# Build test-release image for both architectures
echo ""
echo "Building test-release image..."
DOCKER_BUILDKIT=1 docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -f "$PROJECT_ROOT/docker/Dockerfile.test-release" \
    -t redoubt-test-release \
    --load \
    "$PROJECT_ROOT"

# Run on linux/amd64
echo ""
echo "Running release tests on linux/amd64..."
docker run --rm --platform linux/amd64 redoubt-test-release

# Run on linux/arm64
echo ""
echo "Running release tests on linux/arm64..."
docker run --rm --platform linux/arm64 redoubt-test-release

echo ""
echo "✓ All release tests passed"
