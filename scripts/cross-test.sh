#!/bin/bash
# Test memutil, memcodec_core, memaead on multiple architectures
# Requires: docker with QEMU binfmt support
#   docker run --privileged --rm tonistiigi/binfmt --install all

set -e

echo "=== Testing x86_64 ==="
docker build --platform linux/amd64 -f docker/Dockerfile.arch-test -t memora-test-x86 .
docker run --rm --platform linux/amd64 memora-test-x86

echo ""
echo "=== Testing aarch64 ==="
docker build --platform linux/arm64 -f docker/Dockerfile.arch-test -t memora-test-arm .
docker run --rm --platform linux/arm64 memora-test-arm

echo ""
echo "=== Testing s390x (Big Endian) ==="
docker build --platform linux/s390x -f docker/Dockerfile.arch-test -t memora-test-be .
docker run --rm --platform linux/s390x memora-test-be

echo ""
echo "=== ALL ARCHITECTURES PASSED ==="
