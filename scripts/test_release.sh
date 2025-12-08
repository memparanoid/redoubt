#!/usr/bin/env bash
# Run tests in release mode via test.sh
#
# Usage: same as test.sh but with --release prepended

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/test.sh" --release "$@"
