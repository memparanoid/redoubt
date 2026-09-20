#!/usr/bin/env bash
# Run coverage in Docker with required capabilities
#
# Usage:
#   ./scripts/coverage-docker.sh                    # All crates
#   ./scripts/coverage-docker.sh redoubt-codec-core # Single crate only
#
# Each crate is built on its own behind the `rustc-nocov-deps` wrapper, which
# strips instrumentation from every other crate.
#
# That build emits no branch counters, so the report over it reads `0 0 -` for
# branches instead of failing — a column that looks measured and is not.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

# Create coverage directory if it doesn't exist
mkdir -p "$COVERAGE_DIR"

echo "Building coverage Docker image..."
DOCKER_BUILDKIT=1 docker build -f "$PROJECT_ROOT/docker/Dockerfile.coverage" -t redoubt-coverage "$PROJECT_ROOT"

echo "Running coverage with capabilities..."
docker run --rm \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_ADMIN \
  --ulimit memlock=67108864:67108864 \
  -v "$COVERAGE_DIR:/.coverage" \
  -v redoubt-cargo-cache:/usr/local/cargo/registry \
  -v redoubt-coverage-target-cache:/workspace/target \
  redoubt-coverage "$@"

echo ""
echo "Coverage report generated in: $COVERAGE_DIR"
echo "Open coverage/index.html to view the HTML report"
