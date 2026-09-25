#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

# Builds the libaegis image and writes aegis128l_digests.txt from inside it.
#
# Run: ./vectors/generate_aegis128l_digests.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="localhost/redoubt-aegis128l-oracle"

podman build --tag "${image}" --file "${here}/Containerfile" "${here}"

podman run --rm \
    --volume "${here}:/vectors:Z" \
    --workdir /vectors \
    "${image}" \
    python3 /vectors/generate_aegis128l_digests.py
