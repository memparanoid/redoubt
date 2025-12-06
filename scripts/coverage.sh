#!/usr/bin/env bash
# Run coverage in Docker with required capabilities
#
# Usage:
#   ./scripts/coverage.sh                    # All crates (aggregated report)
#   ./scripts/coverage.sh memcode-core       # Single crate only
#   ./scripts/coverage.sh memzer-core        # Another crate
#   ./scripts/coverage.sh memcrypt test_utils # Crate with features
#
# Note: Single-crate mode uses selective instrumentation to avoid
# monomorphization pollution from workspace dependencies.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

# Create coverage directory if it doesn't exist
mkdir -p "$COVERAGE_DIR"

echo "Building coverage Docker image..."
DOCKER_BUILDKIT=1 docker build -f "$PROJECT_ROOT/docker/Dockerfile.coverage" -t memora-coverage "$PROJECT_ROOT"

echo "Running coverage with capabilities..."
docker run --rm \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_ADMIN \
  --ulimit memlock=67108864:67108864 \
  -v "$COVERAGE_DIR:/.coverage" \
  -v memora-cargo-cache:/usr/local/cargo/registry \
  -v memora-coverage-target-cache:/workspace/target \
  memora-coverage "$@"

echo ""
echo "Coverage report generated in: $COVERAGE_DIR"
echo "Open coverage/index.html to view the HTML report"
