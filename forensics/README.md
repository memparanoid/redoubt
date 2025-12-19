# Redoubt Forensic Analysis

Internal tooling for forensic analysis of sensitive data in memory dumps.

## Overview

This directory contains tools for detecting residual sensitive data patterns in process core dumps. The forensic analysis validates that Redoubt's zeroization guarantees hold under real-world conditions by examining actual memory artifacts.

## Structure

```
./forensics/
 ├── memory_analysis/    # Analysis implementation
 │   ├── src/            # Test binaries
 │   ├── scripts/        # Analysis scripts & runner
 │   ├── entrypoints/    # Core dump generation & analysis
 │   └── Dockerfile      # Isolated test environment
 └── core_dumps/         # Generated dumps (gitignored)
```

## Quick Start

```bash
# Run forensic analysis (ARM64 default)
./forensics/memory_analysis/scripts/run.sh

# Run on x86_64
./forensics/memory_analysis/scripts/run.sh --x86

# Run on ARM64 (explicit)
./forensics/memory_analysis/scripts/run.sh --arm
```

## What It Tests

The forensic analysis creates a test process that:

1. Generates a random 32-byte master key (stored in Redoubt vault)
2. Performs 50 iterations of operations on sensitive patterns:
   - **Vec pattern**: 0xAA (1024 bytes)
   - **String pattern**: 0x41 'A' (1024 bytes, valid UTF-8)
   - **Array pattern**: 0xCC (1024 bytes)
3. Zeroizes all sensitive data using Redoubt's guarantees
4. Generates core dump via SIGABRT
5. Analyzes dump for residual artifacts:
   - **Master key**: Progressive prefix search (1-32 bytes)
   - **Hardcoded patterns**: Contiguous block detection (≥64 bytes)

## Expected Results

**Clean run (0 leaks):**
```
[*] Analyzing master key (progressive prefix search)...
  [01/32] prefix=05  occurrences=118
  [02/32] prefix=05ae  occurrences=0
      -> Dropped to 0 at prefix length 2 (16 bits)
  ...
  [32/32] prefix=05ae...abca74  occurrences=0

[+] No full pattern found in core dump (pattern protected)

[*] Analyzing Pattern #1: 0xaa (contiguous block search)...
============================================================
Pattern: 0xAA
============================================================
Total blocks found: 0

[*] Analyzing Pattern #2: 0x41 (contiguous block search)...
============================================================
Pattern: 0x41
============================================================
Total blocks found: 0

[*] Analyzing Pattern #3: 0xcc (contiguous block search)...
============================================================
Pattern: 0xCC
============================================================
Total blocks found: 0

[+] Analysis complete - no leaks detected
```

**Leak detected example:**
```
============================================================
Pattern: 0xAA
============================================================
Total blocks found: 2
Total bytes: 1952

Block details:
  Block 1: offset=0x00035338, size=1024 bytes
  Block 2: offset=0x000363a0, size= 928 bytes

[!] LEAK CONFIRMED: Sensitive data found in core dump
```

## Analysis Tools

### Block Analysis (Hardcoded Patterns)

Detects contiguous blocks of repeated bytes (>=64 bytes):

```bash
# Analyze Vec pattern (0xAA)
python3 forensics/memory_analysis/scripts/analyze_blocks.py core.dump aa

# Analyze String pattern (0x41)
python3 forensics/memory_analysis/scripts/analyze_blocks.py core.dump 41

# Analyze Array pattern (0xCC)
python3 forensics/memory_analysis/scripts/analyze_blocks.py core.dump cc
```

### Key Analysis (Master Key)

Searches for progressively longer prefixes (1-32 bytes) to detect partial key leaks. This catches scenarios where only a portion of the key material remains in memory:

```bash
python3 forensics/memory_analysis/scripts/analyze_key.py core.dump master_key.hex
```

The analysis starts with 1-byte prefixes and progressively increases length. Random keys typically show many single-byte matches (e.g., 118 occurrences for `05`) but drop to zero at 2-byte prefixes (16-bit collision space). Any matches beyond 3-4 bytes indicate a likely leak.

## Supported Architectures

- **ARM64** (linux/arm64) - default
- **x86_64** (linux/amd64)

Cross-architecture validation ensures zeroization works correctly across different CPU architectures and memory layouts.

## Requirements

- Docker (for isolated test environment)
- Python 3 (for analysis scripts)
- ~300MB disk space (ARM64 core dumps ~220KB, x86_64 ~300MB)

## Internal Use Only

This module uses the `__internal__forensics` feature flag to disable memory protections and enable core dump generation. **Not intended for production use.**

The `__internal__` prefix indicates this is internal testing infrastructure, not a public API.
