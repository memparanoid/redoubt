#!/usr/bin/env bash
# Run release tests locally and in Docker for native architecture
#
# Usage:
#   ./scripts/test_release.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Build base image for native architecture
echo "Building base image..."
"$SCRIPT_DIR/build-redoubt-test-base.sh"

# Run tests locally
echo ""
echo "Running release tests locally with all features..."
cargo test --release --workspace --all-features -- --nocapture

echo ""
echo "Running release tests locally without features..."
cargo test --release --workspace -- --nocapture

# Build test-release image for native architecture
echo ""
echo "Building test-release image for native architecture..."
DOCKER_BUILDKIT=1 docker buildx build \
    -f "$PROJECT_ROOT/docker/Dockerfile.test-release" \
    -t redoubt-test-release \
    --load \
    "$PROJECT_ROOT"

# Run on native architecture
echo ""
echo "Running release tests in Docker..."
docker run --rm redoubt-test-release

echo ""
echo "✓ All release tests passed"
