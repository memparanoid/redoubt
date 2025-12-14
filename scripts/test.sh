#!/usr/bin/env bash
# Run tests in Docker with required capabilities
#
# Usage:
#   ./scripts/test.sh                                          # All tests
#   ./scripts/test.sh -p <crate>                               # Specific crate
#   ./scripts/test.sh -p <crate> <test_name>                   # Specific test
#   ./scripts/test.sh -p <crate> --features <f1,f2>            # With features (comma-separated)
#   ./scripts/test.sh -p <crate> --features <f1,f2> <test>     # Features + specific test
#   ./scripts/test.sh --lib                                    # Only lib tests
#
# Examples:
#   ./scripts/test.sh -p redoubt-buffer
#   ./scripts/test.sh -p redoubt-vault-core --features no_std
#   ./scripts/test.sh -p redoubt-aead --features test_utils test_encrypt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building test Docker image..."
DOCKER_BUILDKIT=1 docker build -f "$PROJECT_ROOT/docker/Dockerfile.test" -t redoubt-test "$PROJECT_ROOT"

echo "Running tests with capabilities (mprotect, madvise, prctl)..."
docker run --rm \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_ADMIN \
  --ulimit memlock=67108864:67108864 \
  -v redoubt-cargo-cache:/usr/local/cargo/registry \
  -v redoubt-target-cache:/workspace/target \
  redoubt-test "$@"
