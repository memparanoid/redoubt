#!/usr/bin/env bash
# Run tests in Docker with required capabilities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building test Docker image..."
docker build -f "$PROJECT_ROOT/docker/Dockerfile.test" -t memora-test "$PROJECT_ROOT"

echo "Running tests with capabilities (mlock, mprotect, madvise, prctl)..."
docker run --rm \
  --cap-add=IPC_LOCK \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_ADMIN \
  memora-test "$@"
