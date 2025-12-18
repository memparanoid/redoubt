#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "[*] Redoubt Leak Detection Test"
echo "[*] Architecture: $(uname -m)"
echo "[*] Testing AEGIS-128L assembly implementation for key leaks"
echo ""

# Build the Docker image
echo "[*] Building Docker image..."
docker build \
    -f "${PROJECT_ROOT}/gdb/dockerfiles/test_redoubt_leaks.Dockerfile" \
    -t redoubt-test-leaks \
    "${PROJECT_ROOT}"

echo ""
echo "[*] Running test with gdb..."
echo "[*] This will take ~60 seconds (test sleeps for memory scanning)"
echo ""

# Run the container
docker run --rm redoubt-test-leaks

echo ""
echo "[+] Test complete"
