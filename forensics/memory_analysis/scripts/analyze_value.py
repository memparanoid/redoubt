#!/usr/bin/env python3
"""
Progressive pattern detection in core dumps.

Searches for progressively longer prefixes of sensitive data patterns to determine
at what point the pattern is no longer present in memory.

For multi-byte values (u16, u32, u64), searches both big-endian and little-endian
byte orders since the value may be stored differently depending on architecture.
"""

import sys
import re

CHUNK = 1024 * 1024 * 16  # 16 MiB
MAX_LINES = 200           # avoid spam; adjust if needed
REPORT_EVERY = 1          # 1 = report every prefix; can increase (e.g., 2, 4, 8)

# Standard integer sizes in bytes
INT_SIZES = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

def read_pattern_hex(path: str) -> bytes:
    """Read hex pattern from file and convert to bytes."""
    with open(path, "rt", encoding="utf-8") as f:
        s = f.read().strip()  # trim whitespace

    # Allow optional "0x..." prefix and spaces
    s = s.lower()
    if s.startswith("0x"):
        s = s[2:]
    s = re.sub(r"\s+", "", s)

    if len(s) == 0 or (len(s) % 2) != 0:
        raise SystemExit(f"Invalid hex length in {path}: {len(s)}")

    if not re.fullmatch(r"[0-9a-f]+", s):
        raise SystemExit(f"Invalid hex characters in {path}")

    return bytes.fromhex(s)

def detect_type(size: int) -> str:
    """Detect integer type from byte size."""
    return INT_SIZES.get(size, f"{size}-byte value")

def count_occurrences(path: str, needle: bytes, chunk: int) -> int:
    """Count occurrences of needle in file, handling chunk overlaps."""
    if not needle:
        return 0

    overlap = len(needle) - 1
    tail = b""
    count = 0

    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break

            data = tail + b

            start = 0
            while True:
                i = data.find(needle, start)
                if i == -1:
                    break
                count += 1
                start = i + 1

            tail = data[-overlap:] if overlap > 0 else b""

    return count

def search_pattern(core_path: str, pattern: bytes, label: str) -> bool:
    """Search for pattern with progressive prefix detection. Returns True if trace found."""
    print(f"[*] Searching {label}: {pattern.hex()}")
    print()

    lines = 0
    prev = None
    trace_found = False

    for n in range(1, len(pattern) + 1):
        if (n % REPORT_EVERY) != 0 and n != len(pattern):
            continue

        pref = pattern[:n]
        c = count_occurrences(core_path, pref, CHUNK)

        pref_hex = pref.hex()
        print(f"  [{n:02d}/{len(pattern)}] prefix={pref_hex}  occurrences={c}")

        # Detect when occurrences drop to 0
        if prev is not None and prev != 0 and c == 0:
            print(f"      -> Dropped to 0 at prefix length {n} ({n*8} bits)")

        # Check if full pattern is found
        if n == len(pattern) and c > 0:
            trace_found = True

        prev = c

        lines += 1
        if lines >= MAX_LINES and n != len(pattern):
            print(f"Reached MAX_LINES={MAX_LINES}. Stopping early.")
            print(f"Increase MAX_LINES or REPORT_EVERY to continue.")
            break

    print()
    return trace_found

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <core_dump_path> <pattern_hex_path>", file=sys.stderr)
        sys.exit(1)

    core_path = sys.argv[1]
    pattern_hex_path = sys.argv[2]

    print(f"[*] Reading pattern from: {pattern_hex_path}")
    pattern_be = read_pattern_hex(pattern_hex_path)  # big-endian (as written)
    pattern_le = pattern_be[::-1]  # little-endian (reversed)

    value_type = detect_type(len(pattern_be))
    print(f"[*] Detected type: {value_type} ({len(pattern_be)} bytes)")
    print(f"[*] Big-endian:    {pattern_be.hex()}")
    print(f"[*] Little-endian: {pattern_le.hex()}")
    print(f"[*] Searching core dump: {core_path}")
    print()

    trace_be = False
    trace_le = False

    # Search big-endian
    trace_be = search_pattern(core_path, pattern_be, "big-endian")

    # Search little-endian (skip if same as big-endian, e.g., single byte)
    if pattern_be != pattern_le:
        trace_le = search_pattern(core_path, pattern_le, "little-endian")

    # Report results
    if trace_be or trace_le:
        print("[!] ============================================")
        print("[!] TRACE DETECTED!")
        if trace_be:
            print(f"[!] Full {len(pattern_be)}-byte value found (big-endian)")
        if trace_le:
            print(f"[!] Full {len(pattern_le)}-byte value found (little-endian)")
        print("[!] ============================================")
        sys.exit(1)
    else:
        print("[+] No full value found in core dump (value protected)")
        sys.exit(0)

if __name__ == "__main__":
    main()
