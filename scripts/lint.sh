#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Run linting locally and in Docker for cross-platform coverage
#
# Usage:
#   ./scripts/lint.sh              # Run all: local + arm + x86
#   ./scripts/lint.sh local        # Run only local
#   ./scripts/lint.sh arm          # Run only arm Docker
#   ./scripts/lint.sh x86          # Run only x86 Docker
#   ./scripts/lint.sh --no-cache   # Force rebuild Docker images

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse args
TARGET=""
NO_CACHE=""
for arg in "$@"; do
    case "$arg" in
        local|arm|x86) TARGET="$arg" ;;
        --no-cache) NO_CACHE="--no-cache" ;;
    esac
done

run_local() {
    echo ""
    echo "=========================================="
    echo "Running local lint"
    echo "=========================================="
    cargo make lint
}

run_arm() {
    echo ""
    echo "=========================================="
    echo "Building base image (arm)"
    echo "=========================================="
    DOCKER_BUILDKIT=1 docker buildx build \
        $NO_CACHE \
        --platform linux/arm64 \
        -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-base" \
        -t redoubt-base-arm:latest \
        --load \
        "$PROJECT_ROOT"

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
}

run_x86() {
    echo ""
    echo "=========================================="
    echo "Building base image (x86)"
    echo "=========================================="
    DOCKER_BUILDKIT=1 docker buildx build \
        $NO_CACHE \
        --platform linux/amd64 \
        -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-base" \
        -t redoubt-base-x86:latest \
        --load \
        "$PROJECT_ROOT"

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
}

case "$TARGET" in
    local) run_local ;;
    arm) run_arm ;;
    x86) run_x86 ;;
    *)
        run_local
        run_arm
        run_x86
        ;;
esac

echo ""
echo "=========================================="
echo "Lint complete!"
echo "=========================================="
