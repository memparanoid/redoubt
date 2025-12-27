# Redoubt Forensic Analysis

Validates that Redoubt's memory-safe types leave no traces in memory after zeroization.

## Purpose

This forensic analysis demonstrates that:

1. **Redoubt types** (`RedoubtString`, `RedoubtVec`, `RedoubtArray`, `RedoubtSecret`) can be updated while the cipherbox is open without leaving traces in memory
2. **Cipherbox master keys** are properly zeroized and don't persist in process memory

The analysis generates a core dump after sensitive operations and searches for any remaining traces of secret data.

## Quick Start

```bash
# Run forensic analysis (native architecture)
./forensics/memory_analysis/scripts/run.sh

# Run on x86_64
./forensics/memory_analysis/scripts/run.sh --x86

# Run on ARM64
./forensics/memory_analysis/scripts/run.sh --arm
```

## How It Works

### Test Binary (`redoubt_trace_report`)

The test binary:

1. Creates a `Cipherbox` with a random 32-byte master key
2. Populates Redoubt types with recognizable patterns:
   - `RedoubtVec<u8>` - 1024 bytes of `0xAA`
   - `RedoubtString` - 1024 bytes of `0x42` ('B')
   - `RedoubtArray<u8, 1024>` - 1024 bytes of `0xCC`
   - `RedoubtOption<RedoubtVec>` - 1024 bytes of `0xDD`
   - `RedoubtOption<RedoubtString>` - 1024 bytes of `0x45` ('E')
   - `RedoubtOption<RedoubtArray>` - 1024 bytes of `0xFF`
   - `RedoubtOption<RedoubtOption<RedoubtString>>` - 1024 bytes of `0x47` ('G')
3. Populates `RedoubtSecret<u64>` values:
   - Value 1: `0xDEADBEEFCAFEBABE`
   - Value 2: `0xCAFEBABEDEADBEEF`
   - Value 3: `0xABCDEF0123456789`
4. Runs 50 iterations of open/modify/close cycles
5. Zeroizes all data and drops the cipherbox
6. Generates a core dump via `SIGABRT`

### Analysis Scripts

Two Python scripts analyze the core dump:

#### `analyze_value.py` - Progressive Prefix Search

For values (master key, u64 secrets), searches progressively longer prefixes to detect partial traces. Automatically detects value type (u8, u16, u32, u64) and searches **both endiannesses**.

> **Note:** While x86 and ARM64 are little-endian, we search both byte orders to prepare for future big-endian architecture support.

```
[*] Detected type: u64 (8 bytes)
[*] Big-endian:    deadbeefcafebabe
[*] Little-endian: bebafecaefbeadde
```

A clean result shows occurrences dropping to 0 within 2-3 bytes:

```
[*] Searching big-endian: deadbeefcafebabe

  [01/8] prefix=de  occurrences=902
  [02/8] prefix=dead  occurrences=0
      -> Dropped to 0 at prefix length 2 (16 bits)
  ...
  [08/8] prefix=deadbeefcafebabe  occurrences=0

[+] No full value found in core dump (value protected)
```

#### `analyze_pattern.py` - Contiguous Block Search

For repeated byte patterns, searches for contiguous blocks of 64+ bytes:

```
============================================================
Pattern: 0xAA
============================================================
Total blocks found: 0
```

## Expected Output

A successful run shows no traces for any tested data:

```
[+] Analysis complete - no traces detected
```

If a trace is found:

```
[!] TRACE DETECTED!
[!] Full 8-byte value found (little-endian)
```

## Structure

```
forensics/
├── memory_analysis/
│   ├── src/bin/
│   │   └── redoubt_trace_report.rs   # Test binary
│   ├── scripts/
│   │   ├── run.sh                    # Main runner
│   │   ├── analyze_value.py          # Progressive prefix search
│   │   └── analyze_pattern.py        # Block search
│   ├── entrypoints/
│   │   └── analyze_core_dump.sh      # Core dump orchestration
│   └── Dockerfile
└── core_dumps/                       # Generated dumps (gitignored)
```

## Supported Architectures

- **ARM64** (linux/arm64)
- **x86_64** (linux/amd64)

Cross-architecture validation ensures Redoubt types can be updated without leaving traces across different CPU architectures and memory layouts.

## Requirements

- Docker
- ~300MB disk space

## Internal Use Only

This module uses the `internal-forensics` feature flag to disable memory protections (prctl, rlimit) and enable core dump generation. **Not intended for production use.**
