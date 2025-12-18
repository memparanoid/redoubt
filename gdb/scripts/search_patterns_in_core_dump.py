#!/usr/bin/env python3
"""
Progressive key leak detection in core dumps.

Searches for progressively longer prefixes of the master key to determine
at what point the key material is no longer present in memory.
"""

import sys
import re

CHUNK = 1024 * 1024 * 16  # 16 MiB
MAX_LINES = 200           # avoid spam; adjust if needed
REPORT_EVERY = 1          # 1 = report every prefix; can increase (e.g., 2, 4, 8)

def read_key_hex(path: str) -> bytes:
    """Read hex key from file and convert to bytes."""
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

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <core_dump_path> <key_hex_path>", file=sys.stderr)
        sys.exit(1)

    core_path = sys.argv[1]
    key_hex_path = sys.argv[2]

    print(f"[*] Reading key from: {key_hex_path}")
    key = read_key_hex(key_hex_path)

    print(f"[*] Key size: {len(key)} bytes")
    print(f"[*] Key hex:  {key.hex()}")
    print(f"[*] Searching core dump: {core_path}")
    print()

    lines = 0
    prev = None
    leak_detected = False

    for n in range(1, len(key) + 1):
        if (n % REPORT_EVERY) != 0 and n != len(key):
            continue

        pref = key[:n]
        c = count_occurrences(core_path, pref, CHUNK)

        pref_hex = pref.hex()
        print(f"  [{n:02d}/{len(key)}] prefix={pref_hex}  occurrences={c}")

        # Detect when occurrences drop to 0
        if prev is not None and prev != 0 and c == 0:
            print(f"      -> Dropped to 0 at prefix length {n} ({n*8} bits)")

        # Check if full key is found
        if n == len(key) and c > 0:
            leak_detected = True

        prev = c

        lines += 1
        if lines >= MAX_LINES and n != len(key):
            print(f"Reached MAX_LINES={MAX_LINES}. Stopping early.")
            print(f"Increase MAX_LINES or REPORT_EVERY to continue.")
            break

    print()
    if leak_detected:
        print("[!] ============================================")
        print("[!] KEY LEAK DETECTED!")
        print(f"[!] Full {len(key)}-byte key found {prev} time(s) in core dump")
        print("[!] ============================================")
        sys.exit(1)
    else:
        print("[+] No full key found in core dump (key protected)")
        sys.exit(0)

if __name__ == "__main__":
    main()
