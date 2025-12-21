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

# Build the binary in release mode with forensics feature enabled
# This disables memory protections (prctl, rlimit) to allow core dump analysis
RUN cargo build --release --features __internal__forensics --bin test_redoubt_leaks -p redoubt-forensics

# Make scripts executable
RUN chmod +x forensics/memory_analysis/entrypoints/analyze_core_dump.sh && \
    chmod +x forensics/memory_analysis/scripts/analyze_key.py && \
    chmod +x forensics/memory_analysis/scripts/analyze_blocks.py

# Enable core dumps (disabled by default in containers)
RUN echo 'ulimit -c unlimited' >> /root/.bashrc

# Default command: run core dump analysis
CMD ["sh", "-c", "ulimit -c unlimited && ./forensics/memory_analysis/entrypoints/analyze_core_dump.sh"]
