// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

FROM rust:alpine

RUN apk add --no-cache \
  musl-dev \
  linux-headers \
  build-base \
  bash \
  coreutils \
  grep \
  python3

WORKDIR /workspace

# Copy entire workspace
COPY . .

# Build the binary (build.rs handles architecture-specific crypto flags)
RUN cargo build --bin test_redoubt_leaks -p gdb-tests

# Make scripts executable
RUN chmod +x gdb/entrypoints/analyze_core_dump.sh && \
    chmod +x gdb/scripts/search_patterns_in_core_dump.py

# Enable core dumps (disabled by default in containers)
RUN echo 'ulimit -c unlimited' >> /root/.bashrc

# Default command: run core dump analysis
CMD ["sh", "-c", "ulimit -c unlimited && ./gdb/entrypoints/analyze_core_dump.sh"]
