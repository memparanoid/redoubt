#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Run linting locally and in Docker for cross-platform coverage
#
# Usage:
#   ./scripts/lint.sh              # Run all
#   ./scripts/lint.sh --no-cache   # Force rebuild Docker images

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

NO_CACHE=""
[[ "${1:-}" == "--no-cache" ]] && NO_CACHE="--no-cache"

echo "=========================================="
echo "Building base images"
echo "=========================================="

echo "Building redoubt-base-arm..."
DOCKER_BUILDKIT=1 docker buildx build \
    $NO_CACHE \
    --platform linux/arm64 \
    -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-base" \
    -t redoubt-base-arm:latest \
    --load \
    "$PROJECT_ROOT"

echo "Building redoubt-base-x86..."
DOCKER_BUILDKIT=1 docker buildx build \
    $NO_CACHE \
    --platform linux/amd64 \
    -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-base" \
    -t redoubt-base-x86:latest \
    --load \
    "$PROJECT_ROOT"

echo ""
echo "=========================================="
echo "Running local lint"
echo "=========================================="
cargo make lint

echo ""
echo "=========================================="
echo "Running Docker lint (arm)"
echo "=========================================="

DOCKER_BUILDKIT=1 docker buildx build \
    $NO_CACHE \
    --platform linux/arm64 \
    --build-arg BASE_IMAGE=redoubt-base-arm:latest \
    -f "$PROJECT_ROOT/docker/Dockerfile.lint" \
    -t redoubt-lint-arm:latest \
    --load \
    "$PROJECT_ROOT"

docker run --rm \
    --platform linux/arm64 \
    -v redoubt-cargo-cache-arm:/usr/local/cargo/registry \
    -v redoubt-target-cache-arm:/workspace/target \
    redoubt-lint-arm:latest

echo ""
echo "=========================================="
echo "Running Docker lint (x86)"
echo "=========================================="

DOCKER_BUILDKIT=1 docker buildx build \
    $NO_CACHE \
    --platform linux/amd64 \
    --build-arg BASE_IMAGE=redoubt-base-x86:latest \
    -f "$PROJECT_ROOT/docker/Dockerfile.lint" \
    -t redoubt-lint-x86:latest \
    --load \
    "$PROJECT_ROOT"

docker run --rm \
    --platform linux/amd64 \
    -v redoubt-cargo-cache-x86:/usr/local/cargo/registry \
    -v redoubt-target-cache-x86:/workspace/target \
    redoubt-lint-x86:latest

echo ""
echo "=========================================="
echo "Lint complete!"
echo "=========================================="
