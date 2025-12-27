#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# Build redoubt-base image for native architecture
#
# Usage:
#   ./scripts/build-redoubt-base.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building redoubt-base for native architecture..."
DOCKER_BUILDKIT=1 docker buildx build \
    -f "$PROJECT_ROOT/docker/Dockerfile.redoubt-base" \
    -t redoubt-base:latest \
    --load \
    "$PROJECT_ROOT"

echo "✓ redoubt-base:latest built successfully"
