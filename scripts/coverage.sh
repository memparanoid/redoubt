#!/usr/bin/env bash
# Run coverage in Docker with required capabilities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

# Create coverage directory if it doesn't exist
mkdir -p "$COVERAGE_DIR"

echo "Building coverage Docker image..."
docker build -f "$PROJECT_ROOT/docker/Dockerfile.coverage" -t memora-coverage "$PROJECT_ROOT"

echo "Running coverage with capabilities..."
docker run --rm \
  --cap-add=IPC_LOCK \
  --cap-add=SYS_RESOURCE \
  -v "$COVERAGE_DIR:/workspace/coverage" \
  memora-coverage

echo "Coverage report generated in: $COVERAGE_DIR"
echo "Open coverage/index.html to view the HTML report"
