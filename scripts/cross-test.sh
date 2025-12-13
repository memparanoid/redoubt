#!/bin/bash
# Test redoubt-util, memcodec_core, memaead on multiple architectures
# Requires: docker with QEMU binfmt support
#   docker run --privileged --rm tonistiigi/binfmt --install all

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "=== Testing s390x (Big Endian) ==="
DOCKER_BUILDKIT=1 docker build --platform linux/s390x -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t memora-test-be "$PROJECT_ROOT"
docker run --rm --platform linux/s390x \
  -v memora-cargo-cache-s390x:/usr/local/cargo/registry \
  -v memora-target-cache-s390x:/workspace/target \
  memora-test-be

echo "=== Testing x86_64 ==="
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t memora-test-x86 "$PROJECT_ROOT"
docker run --rm --platform linux/amd64 \
  -v memora-cargo-cache-x86:/usr/local/cargo/registry \
  -v memora-target-cache-x86:/workspace/target \
  memora-test-x86

echo ""
echo "=== Testing aarch64 ==="
DOCKER_BUILDKIT=1 docker build --platform linux/arm64 -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" -t memora-test-arm "$PROJECT_ROOT"
docker run --rm --platform linux/arm64 \
  -v memora-cargo-cache-arm:/usr/local/cargo/registry \
  -v memora-target-cache-arm:/workspace/target \
  memora-test-arm

echo ""
echo "=== ALL ARCHITECTURES PASSED ==="
