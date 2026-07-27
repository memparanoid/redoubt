FROM rust:alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900

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

# Build the binary in release mode.
#
# `internal-forensics` exposes `reset_master_key` and prints a warning. It does
# NOT relax any memory protection: `prctl(PR_SET_DUMPABLE)` and
# `setrlimit(RLIMIT_CORE)` are applied by the `guard` feature, which is off by
# default and not enabled here.
RUN cargo build --release --features internal-forensics --bin redoubt_trace_report -p redoubt-forensics

# Make scripts executable
RUN chmod +x forensics/memory_analysis/entrypoints/analyze_core_dump.sh && \
    chmod +x forensics/memory_analysis/scripts/analyze_value.py && \
    chmod +x forensics/memory_analysis/scripts/analyze_pattern.py && \
    chmod +x forensics/memory_analysis/scripts/analyze_regions.py

# No `ulimit -c` and no `--cap-add` are needed. The binary dumps its own memory
# and registers, so nothing here depends on `kernel.core_pattern` — a global
# sysctl that containers inherit from the host, which is why a lab built on
# kernel-written core dumps behaves one way under Docker Desktop's Linux VM and
# another way on a Linux host routing cores to systemd-coredump.
CMD ["sh", "-c", "./forensics/memory_analysis/entrypoints/analyze_core_dump.sh"]
