#!/bin/bash
# Test redoubt-util, memcodec_core, redoubt-aead on multiple architectures
# Requires: docker with QEMU binfmt support
#   docker run --privileged --rm tonistiigi/binfmt --install all

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "=== Testing s390x (Big Endian) ==="
DOCKER_BUILDKIT=1 docker build --platform linux/s390x -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t redoubt-test-be "$PROJECT_ROOT"
docker run --rm --platform linux/s390x \
  -v redoubt-cargo-cache-s390x:/usr/local/cargo/registry \
  -v redoubt-target-cache-s390x:/workspace/target \
  redoubt-test-be

echo "=== Testing x86_64 ==="
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t redoubt-test-x86 "$PROJECT_ROOT"
docker run --rm --platform linux/amd64 \
  -v redoubt-cargo-cache-x86:/usr/local/cargo/registry \
  -v redoubt-target-cache-x86:/workspace/target \
  redoubt-test-x86

echo ""
echo "=== Testing aarch64 ==="
DOCKER_BUILDKIT=1 docker build --platform linux/arm64 -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t redoubt-test-arm "$PROJECT_ROOT"
docker run --rm --platform linux/arm64 \
  -v redoubt-cargo-cache-arm:/usr/local/cargo/registry \
  -v redoubt-target-cache-arm:/workspace/target \
  redoubt-test-arm

echo ""
echo "=== Testing riscv64 ==="
DOCKER_BUILDKIT=1 docker build --platform linux/riscv64 -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t redoubt-test-riscv "$PROJECT_ROOT"
docker run --rm --platform linux/riscv64 \
  -v redoubt-cargo-cache-riscv:/usr/local/cargo/registry \
  -v redoubt-target-cache-riscv:/workspace/target \
  redoubt-test-riscv

echo ""
echo "=== ALL ARCHITECTURES PASSED ==="
