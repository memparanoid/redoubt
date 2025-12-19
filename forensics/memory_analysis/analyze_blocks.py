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
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <core_dump_path>")
        sys.exit(1)

    dump_path = sys.argv[1]

    # Analyze each pattern
    for byte_val, name in [(0xAA, "0xAA"), (0x41, "0x41 'A'"), (0xCC, "0xCC")]:
        blocks = find_blocks(dump_path, byte_val, min_length=64)

        print(f"\n{'=' * 60}")
        print(f"Pattern: {name}")
        print(f"{'=' * 60}")
        print(f"Total blocks found: {len(blocks)}")

        if blocks:
            total_bytes = sum(length for _, length in blocks)
            print(f"Total bytes: {total_bytes}")
            print(f"\nBlock details:")
            for i, (offset, length) in enumerate(blocks, 1):
                print(f"  Block {i}: offset=0x{offset:08x}, size={length:4d} bytes")


if __name__ == "__main__":
    main()
