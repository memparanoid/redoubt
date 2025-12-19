#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Parse architecture flag (default: native)
PLATFORM=""
if [ "${1:-}" = "--x86" ]; then
    PLATFORM="--platform linux/amd64"
    echo "[*] Forcing x86_64 architecture"
elif [ "${1:-}" = "--arm" ]; then
    PLATFORM="--platform linux/arm64"
    echo "[*] Forcing ARM64 architecture"
fi

echo "[*] Redoubt Leak Detection Test"
echo "[*] Host Architecture: $(uname -m)"
echo "[*] Docker PLATFORM: $PLATFORM"
echo "[*] Testing Redoubt for sensitive data patterns recognition"
echo ""

# Build the Docker image
echo "[*] Building Docker image..."
docker build \
    $PLATFORM \
    -f "${PROJECT_ROOT}/gdb/dockerfiles/test_redoubt_leaks.Dockerfile" \
    -t redoubt-test-leaks \
    "${PROJECT_ROOT}"

echo ""
echo "[*] Running test with gdb..."
echo "[*] This will take ~60 seconds (test sleeps for memory scanning)"
echo ""

# Create output directory for core dumps
CORE_OUTPUT="${PROJECT_ROOT}/gdb/core_dumps"
mkdir -p "${CORE_OUTPUT}"

# Run the container with volume mount
docker run --rm $PLATFORM -v "${CORE_OUTPUT}:/workspace/core_dumps" redoubt-test-leaks

echo ""
echo "[+] Test complete"
echo "[*] Core dumps (if any) saved to: ${CORE_OUTPUT}"
