#!/usr/bin/env python3
"""Locate a secret inside a dump produced by `dumper.rs`, and name where it is.

The other two scripts answer "is it there". This one answers "where", which is
the part that decides what to do about it:

  REGISTERS/xsave -> ZMM17   a value left in a vector register. Zeroizing
                             memory cannot reach it; on glibc this is what
                             `memcpy` leaves behind on an AVX-512 host.
  [heap]                     a buffer that was dropped without being wiped.
  [stack]                    a frame that was never overwritten, or vector
                             state spilled there by a signal frame.
  DUMPER_SELF                the dumper's own copy of what it just read.
                             Not a finding; reported and discarded.

Usage:
    analyze_regions.py <dump.bin> <pattern.hex | hex-string> [more.hex ...]
    analyze_regions.py --expect <dump.bin> <canary.hex | hex-string>

Exit status is 1 if anything was found outside DUMPER_SELF, so it can gate CI.

`--expect` inverts that for the positive control: the pattern *must* be present,
and a run that cannot find it exits non-zero. Without this check a broken dumper
— wrong `maps` filter, `pread` returning nothing, `XSAVE` never called — reports
exactly what a genuinely clean process reports, and the whole lab silently
becomes a machine for printing good news.
"""

import os
import re
import sys

# XSAVE standard-format layout. Offsets are fixed when XCOMP_BV is 0; the
# dumper always requests the standard format.
XSAVE_COMPONENTS = [
    ("x87/MXCSR", 0x000, 0xA0, 0xA0),
    ("XMM", 0x0A0, 0x100, 16),
    ("YMM_Hi128", 0x240, 0x100, 16),
    ("opmask K", 0x340, 0x40, 8),
    ("ZMM_Hi256", 0x380, 0x200, 32),
    ("Hi16_ZMM", 0x580, 0x400, 64),
]


def load_index(path):
    """Returns (regions, self_ranges).

    regions:     [(file_offset, length, vaddr, label)] sorted by file_offset
    self_ranges: [(vaddr, length, name)] for the dumper's own buffers
    """
    regions, self_ranges = [], []
    with open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("# DUMPER_SELF"):
                _, _, addr, length, name = line.split()
                self_ranges.append((int(addr, 16), int(length, 16), name))
                continue
            if not line or line.startswith("#"):
                if "WARNING" in line:
                    print(f"[!] {line.lstrip('# ')}")
                continue
            off, length, vaddr, label = line.split(maxsplit=3)
            regions.append((int(off, 16), int(length, 16), int(vaddr, 16), label))
    regions.sort()
    return regions, self_ranges


def resolve(offset, regions):
    """Maps a file offset back to (label, offset_in_region, vaddr)."""
    for off, length, vaddr, label in regions:
        if off <= offset < off + length:
            rel = offset - off
            return label, rel, (vaddr + rel if vaddr else 0)
    return "<unmapped>", offset, 0


def name_register(rel):
    """Turns an offset inside the XSAVE area into a register name."""
    for name, start, size, per in XSAVE_COMPONENTS:
        if start <= rel < start + size:
            if name == "x87/MXCSR":
                return "x87/MXCSR area"
            index = (rel - start) // per
            if name == "Hi16_ZMM":
                return f"ZMM{16 + index}"
            if name == "ZMM_Hi256":
                return f"ZMM{index} (bits 256-511)"
            if name == "YMM_Hi128":
                return f"YMM{index} (bits 128-255)"
            if name == "opmask K":
                return f"K{index}"
            return f"{name}{index}"
    return f"XSAVE +{rel:#x}"


def read_pattern(arg):
    """Accepts either a path to a hex file or a hex string directly."""
    text = arg
    if os.path.exists(arg):
        with open(arg, "rt", encoding="utf-8") as f:
            text = f.read()
    text = re.sub(r"\s+", "", text.strip().lower())
    if text.startswith("0x"):
        text = text[2:]
    if not text or len(text) % 2 or not re.fullmatch(r"[0-9a-f]+", text):
        raise SystemExit(f"[!] Not a hex pattern: {arg}")
    return bytes.fromhex(text)


def find_all(data, needle):
    at, out = data.find(needle), []
    while at != -1:
        out.append(at)
        at = data.find(needle, at + 1)
    return out


BOX_WIDTH = 76


def box(title):
    print("╔" + "═" * BOX_WIDTH + "╗")
    print("║ " + title.ljust(BOX_WIDTH - 1) + "║")
    print("╚" + "═" * BOX_WIDTH + "╝")


def abbreviate(hexstr, keep=12):
    if len(hexstr) <= keep * 2 + 3:
        return hexstr
    return f"{hexstr[:keep]} … {hexstr[-keep:]}"


def describe(offset, regions, self_ranges):
    """Renders one hit as a single line, or None if it is self-contamination."""
    label, rel, vaddr = resolve(offset, regions)
    if next((n for a, l, n in self_ranges if vaddr and a <= vaddr < a + l), None):
        return None
    if label == "REGISTERS/xsave":
        return f"{name_register(rel):<22} XSAVE +{rel:#x}"
    suffix = f"vaddr {vaddr:#x}" if vaddr else ""
    return f"{label:<22} +{rel:#x}  {suffix}".rstrip()


def positive_control(dump_path, idx_path, needle_arg):
    """The canary check. Present is pass; absent is a void run."""
    regions, self_ranges = load_index(idx_path)
    with open(dump_path, "rb") as f:
        data = f.read()

    needle = read_pattern(needle_arg)
    hits = [h for h in find_all(data, needle) if describe(h, regions, self_ranges)]

    print()
    box("POSITIVE CONTROL — canary")
    print()
    print(f"  {len(needle)} bytes, never zeroized, random per run.")
    print("  A dump that cannot find this has not been shown to look anywhere.")
    print()
    print(f"  {'needle':<10}{abbreviate(needle.hex())}")
    print(f"  {'dump':<10}{len(data):,} bytes across {len(regions)} regions")

    has_regs = any(r[3] == "REGISTERS/xsave" for r in regions)
    print(f"  {'registers':<10}{'captured' if has_regs else 'ABSENT — no XSAVE in this dump'}")
    print(f"  {'found':<10}{len(hits)} occurrence(s)")
    print()

    for hit in hits:
        print(f"      {describe(hit, regions, self_ranges)}")

    print()
    if not hits:
        print("  ✘ CONTROL FAILED — the canary is not in the dump.")
        print("    The dumper is not capturing what it claims to.")
        print("    Every clean result from this run is void.")
        print()
        return 2

    print("  ✔ CONTROL PASSED — the dump covers the memory the analysis relies on.")
    if not has_regs:
        print("    Note: no register area. Vector-register findings are out of reach")
        print("    on this target, and their absence proves nothing.")
    print()
    return 0


def main():
    argv = sys.argv[1:]

    if argv and argv[0] == "--expect":
        if len(argv) != 3:
            raise SystemExit(__doc__)
        dump_path = argv[1]
        idx = dump_path[:-4] + ".idx" if dump_path.endswith(".bin") else dump_path + ".idx"
        return positive_control(dump_path, idx, argv[2])

    if len(sys.argv) < 3:
        raise SystemExit(__doc__)

    dump_path = sys.argv[1]
    idx_path = dump_path[:-4] + ".idx" if dump_path.endswith(".bin") else dump_path + ".idx"

    regions, self_ranges = load_index(idx_path)
    with open(dump_path, "rb") as f:
        data = f.read()

    print(f"[*] Dump:  {dump_path} ({len(data):,} bytes, {len(regions)} regions)")
    print(f"[*] Index: {idx_path}")
    print()

    real_hits = 0

    for arg in sys.argv[2:]:
        needle = read_pattern(arg)
        hits = find_all(data, needle)
        head = needle.hex()[:16]
        print(f"[*] {head}... ({len(needle)} bytes) -> {len(hits)} occurrence(s)")

        for offset in hits:
            label, rel, vaddr = resolve(offset, regions)

            # The dumper's own buffers hold a copy of the last region it read.
            contaminated = next(
                (n for a, l, n in self_ranges if vaddr and a <= vaddr < a + l), None
            )
            if contaminated:
                print(f"      - {label} +{rel:#x}  [DUMPER_SELF/{contaminated}] ignored")
                continue

            if label == "REGISTERS/xsave":
                where = name_register(rel)
                print(f"      ! REGISTERS -> {where}  (XSAVE +{rel:#x})")
            else:
                print(f"      ! {label} +{rel:#x}  (vaddr {vaddr:#x})")
            real_hits += 1

        if not hits:
            print("      clean")
        print()

    if real_hits:
        print(f"[!] TRACE DETECTED: {real_hits} occurrence(s) outside the dumper's own buffers")
        return 1

    print("[+] No traces found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
