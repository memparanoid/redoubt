#!/usr/bin/env bash
# Run tests in Docker with required capabilities
#
# Usage:
#   ./scripts/test.sh                              # All tests
#   ./scripts/test.sh -p memcode-core              # Specific crate
#   ./scripts/test.sh -p memcode-core test_name    # Specific test
#   ./scripts/test.sh --lib                        # Only lib tests
#   ./scripts/test.sh -p memcrypt --features test_utils test_encrypt

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
