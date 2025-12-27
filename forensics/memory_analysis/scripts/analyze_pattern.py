#!/usr/bin/env python3
"""Analyze contiguous blocks of repeated bytes in core dump."""

import sys


def find_blocks(dump_path, byte_value, min_length=16):
    """Find contiguous blocks of a specific byte value."""
    blocks = []

    with open(dump_path, "rb") as f:
        data = f.read()

    start = None
    length = 0

    for i, b in enumerate(data):
        if b == byte_value:
            if start is None:
                start = i
            length += 1
        else:
            if start is not None and length >= min_length:
                blocks.append((start, length))
            start = None
            length = 0

    # Handle block at end
    if start is not None and length >= min_length:
        blocks.append((start, length))

    return blocks


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <core_dump_path> <pattern_hex>")
        print(f"Example: {sys.argv[0]} core.dump aa")
        sys.exit(1)

    dump_path = sys.argv[1]
    pattern_hex = sys.argv[2]

    # Parse hex pattern (e.g., "aa", "41", "cc")
    try:
        byte_value = int(pattern_hex, 16)
    except ValueError:
        print(f"Error: Invalid hex pattern '{pattern_hex}'")
        sys.exit(1)

    # Find contiguous blocks (minimum 64 bytes)
    blocks = find_blocks(dump_path, byte_value, min_length=64)

    print(f"\n{'=' * 60}")
    print(f"Pattern: 0x{pattern_hex.upper()}")
    print(f"{'=' * 60}")
    print(f"Total blocks found: {len(blocks)}")

    if blocks:
        total_bytes = sum(length for _, length in blocks)
        print(f"Total bytes: {total_bytes}")
        print(f"\nBlock details:")
        for i, (offset, length) in enumerate(blocks, 1):
            print(f"  Block {i}: offset=0x{offset:08x}, size={length:4d} bytes")

    # Exit code: 0 if no traces, 1 if traces found
    sys.exit(1 if blocks else 0)


if __name__ == "__main__":
    main()
