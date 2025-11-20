// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

# Docker Infrastructure for Memora

This directory contains optimized Docker configurations for testing and coverage analysis of the Memora framework.

## Key Features

### 1. Dependency Caching
Both Dockerfiles use a **two-stage copy** pattern to maximize Docker layer caching:

1. **First stage**: Copy only `Cargo.toml` files + create stub `lib.rs` files
2. **Build dependencies**: Run `cargo build --workspace` (this layer is cached)
3. **Second stage**: Copy actual source code

**Result**: Rebuilds only recompile changed crates, not all dependencies.

### 2. Per-Crate Coverage
The coverage system uses `rustc-nocov-deps.sh` as a `RUSTC_WRAPPER` to ensure:

- **Only the target crate is instrumented** for coverage
- **Workspace dependencies are compiled without coverage flags**
- **Prevents monomorphized code pollution**: Coverage for `memcode-core` won't include lines from `memzer-core` that are instantiated in `memcode-core` tests

**How it works**:
- `COVER_CRATES` environment variable specifies which crates to instrument
- `rustc-nocov-deps.sh` strips `-C instrument-coverage` flags for non-target crates
- Each crate runs with `cargo llvm-cov -p <crate> --no-report`
- Final report aggregates all `.profraw` files

## Files

### Dockerfiles

- **`Dockerfile.test`**: Fast test runner with dependency caching
- **`Dockerfile.coverage`**: Coverage analysis with `cargo-llvm-cov` (nightly)

### Entrypoints

- **`test-entrypoint.sh`**: Simple wrapper that passes args to `cargo test`
- **`coverage-entrypoint.sh`**: Per-crate coverage runner with selective instrumentation
- **`rustc-nocov-deps.sh`**: RUSTC_WRAPPER for filtering coverage flags

## Usage

### Running Tests

```bash
# All tests
./scripts/test.sh

# Specific crate
./scripts/test.sh -p memcode-core

# Specific test in a crate
./scripts/test.sh -p memcode-core test_roundtrip

# With flags
./scripts/test.sh --lib
./scripts/test.sh -p memcrypt --features test_utils

# Specific test with features
./scripts/test.sh -p memcrypt --features test_utils test_encrypt_decrypt
```

### Running Coverage

```bash
# All crates (aggregated report)
./scripts/coverage.sh

# Single crate only
./scripts/coverage.sh memcode-core

# Crate with features
./scripts/coverage.sh memcrypt test_utils
```

**Output**: `coverage/index.html` (HTML report)

## Coverage Methodology

### Problem: Monomorphization Pollution

Without selective instrumentation:
```
memcode-core uses memzer-core::Secret<T>
↓
memzer-core code is monomorphized in memcode-core binary
↓
Coverage report shows memzer-core lines as "covered" by memcode-core tests
↓
memzer-core appears to have higher coverage than it actually does
```

### Solution: Per-Crate Instrumentation

```bash
# Step 1: Clean previous runs
cargo +nightly llvm-cov clean

# Step 2: Run coverage for memcode-core only
COVER_CRATES="memcode-core" \
RUSTC_WRAPPER="/usr/local/bin/rustc-nocov-deps" \
cargo +nightly llvm-cov -p memcode-core --branch --no-report

# Step 3: Run coverage for memzer-core only
COVER_CRATES="memzer-core" \
RUSTC_WRAPPER="/usr/local/bin/rustc-nocov-deps" \
cargo +nightly llvm-cov -p memzer-core --branch --no-report

# Step 4: Generate aggregated report
cargo +nightly llvm-cov report --branch --html --output-dir /.coverage
```

**Result**: Each crate's coverage is accurate and isolated.

## Capabilities

Both containers require Linux capabilities for memory-locking syscalls:

- `IPC_LOCK`: For `mlock()`, `mlock2()`
- `SYS_RESOURCE`: For `setrlimit()` (increase `RLIMIT_MEMLOCK`)
- `SYS_ADMIN`: For `mprotect()`, `madvise()`, `prctl()`

These are automatically added by `scripts/test.sh` and `scripts/coverage.sh`.

## Docker Layer Structure

### Test Image

```
Layer 1: rust:1.83-alpine + system deps (musl, build-base)
Layer 2: Workspace structure (mkdir crates/**)
Layer 3: Cargo.toml files copied
Layer 4: Stub lib.rs files created
Layer 5: cargo build --workspace (CACHED IF NO Cargo.toml CHANGES)
Layer 6: Real source code copied (INVALIDATES FROM HERE)
Layer 7: Entrypoint + scripts
```

### Coverage Image

Same as test image, plus:
```
Layer 1b: cargo-llvm-cov + nightly toolchain + llvm-tools
Layer 7b: rustc-nocov-deps wrapper
```

## Performance

**First build**: ~5-10 minutes (compiles all dependencies + tooling)

**Rebuild after code change**: ~30 seconds (only recompiles changed crates)

**Why?**: Layer 5 (dependency compilation) is cached and reused.

## Alpine vs Debian

**Choice**: `rust:1.83-alpine` (not `rust:1.83-slim`)

**Reasons**:
- Smaller image size (~1GB vs ~2GB)
- musl libc (static linking, simpler deployment)
- Aligns with Memora's minimalist security model

**Trade-off**: Some C libraries may need manual compilation (e.g., libseccomp if needed later).

## Maintenance

When adding a new crate to workspace:

1. Update `Dockerfile.test` and `Dockerfile.coverage`:
   - Add `RUN mkdir -p crates/<new-crate>/src`
   - Add `COPY crates/<new-crate>/Cargo.toml ./crates/<new-crate>/`
   - Add `RUN echo "// stub" > crates/<new-crate>/src/lib.rs`

2. Update `coverage-entrypoint.sh`:
   - Add `mk <new-crate>` to default run list

3. Rebuild images to cache new dependencies:
   ```bash
   docker build -f docker/Dockerfile.test -t memora-test .
   docker build -f docker/Dockerfile.coverage -t memora-coverage .
   ```

## Debugging

### View coverage wrapper logs

The `rustc-nocov-deps.sh` wrapper doesn't log by default. To enable debugging:

```bash
# Add to rustc-nocov-deps.sh (after shebang):
LOG_FILE="/tmp/coverage_debug.txt"
log_info() {
  echo "$(date) - $1" >> "$LOG_FILE"
}

# Run coverage, then inspect:
docker run --rm memora-coverage memcode-core
docker cp <container-id>:/tmp/coverage_debug.txt .
```

### Test dependency caching

```bash
# First build (slow)
time docker build -f docker/Dockerfile.test -t memora-test .

# Change a single file
echo "// comment" >> crates/memcode/core/src/lib.rs

# Second build (fast - should skip Layer 5)
time docker build -f docker/Dockerfile.test -t memora-test .
```

Expected: Second build completes in <1 minute (only recompiles memcode-core).
