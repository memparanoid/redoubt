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

# Build the binary in release mode (build.rs handles architecture-specific crypto flags)
RUN cargo build --release --bin test_redoubt_leaks -p redoubt-forensics

# Make scripts executable
RUN chmod +x forensics/memory_analysis/entrypoints/analyze_core_dump.sh && \
    chmod +x forensics/memory_analysis/scripts/analyze_key.py && \
    chmod +x forensics/memory_analysis/scripts/analyze_blocks.py

# Enable core dumps (disabled by default in containers)
RUN echo 'ulimit -c unlimited' >> /root/.bashrc

# Default command: run core dump analysis
CMD ["sh", "-c", "ulimit -c unlimited && ./forensics/memory_analysis/entrypoints/analyze_core_dump.sh"]
