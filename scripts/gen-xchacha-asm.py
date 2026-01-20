#!/usr/bin/env python3
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

"""Generate assembly for redoubt-aead xchacha20poly1305.

Usage:
    ./scripts/gen-xchacha-asm.py           # Generate for both x86 and ARM
    ./scripts/gen-xchacha-asm.py x86       # Generate for x86 only
    ./scripts/gen-xchacha-asm.py arm       # Generate for ARM only

Output goes to: scripts/asm/xchacha20poly1305/{x86,arm}/

Requires: cargo-asm (cargo install cargo-asm)
"""

import subprocess
import sys
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
ASM_DIR = SCRIPT_DIR / "asm" / "xchacha20poly1305"

# Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

X86_TARGET = "x86_64-unknown-linux-gnu"
ARM_TARGET = "aarch64-unknown-linux-gnu"


def extract_body(asm_content: str, arch: str) -> str:
    """Extract function body, excluding prologue and epilogue."""
    lines = asm_content.split('\n')

    prologue_end = 0
    epilogue_start = len(lines)

    if arch == "x86":
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not any(p in stripped for p in [
                'push', 'sub rsp', 'mov rbp', 'mov rsp', '.cfi_', '.p2align',
                '.section', '.globl', '.type', ':',
            ]):
                prologue_end = i
                break

        for i in range(len(lines) - 1, prologue_end, -1):
            stripped = lines[i].strip()
            if stripped and not any(p in stripped for p in [
                'pop', 'add rsp', 'ret', 'jmp', '.cfi_', '#NO_APP',
            ]):
                epilogue_start = i + 1
                break
    else:
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not any(p in stripped for p in [
                'stp', 'sub sp', 'mov x29', 'mov fp', '.cfi_', '.p2align',
                '.section', '.globl', '.type', ':', 'str x', 'str w',
            ]) and '[sp' not in stripped:
                prologue_end = i
                break

        for i in range(len(lines) - 1, prologue_end, -1):
            stripped = lines[i].strip()
            if stripped and not any(p in stripped for p in [
                'ldp', 'add sp', 'ret', '.cfi_', 'ldr x', 'ldr w',
            ]) and '[sp' not in stripped and not stripped.startswith('b '):
                epilogue_start = i + 1
                break

    return '\n'.join(lines[prologue_end:epilogue_start])


def analyze_stack_ops(body: str, arch: str) -> tuple[set, list, list]:
    """Analyze stack operations, returning (slots, stores, loads)."""
    if arch == "x86":
        pattern = re.compile(
            r"\b(mov(?:aps|dqa|dqu|ups)?|lea)\b\s+([^,]+),\s*([^\n]+)",
            re.IGNORECASE
        )
        stack_ref = re.compile(r"\[\s*(rsp|rbp)(?:\s*\+\s*(\d+))?\s*\]", re.IGNORECASE)
    else:
        pattern = re.compile(
            r"\b(str|ldr|stp|ldp|stur|ldur)\b\s+([^,]+),\s*([^\n]+)",
            re.IGNORECASE
        )
        stack_ref = re.compile(r"\[\s*(sp|x29)(?:,\s*#?(\d+))?\s*\]", re.IGNORECASE)

    stores = []
    loads = []

    for line in body.splitlines():
        s = line.strip()
        m = pattern.search(s)
        if not m:
            continue

        dst = m.group(2)
        src = m.group(3)

        dst_match = stack_ref.search(dst)
        src_match = stack_ref.search(src)

        if dst_match:
            base, off = dst_match.group(1), int(dst_match.group(2) or 0)
            stores.append((base, off))
        elif src_match:
            base, off = src_match.group(1), int(src_match.group(2) or 0)
            loads.append((base, off))

    slots = set(stores + loads)
    return slots, stores, loads


def count_spills(asm_content: str, arch: str) -> tuple[int, int, int]:
    """Count stack spill slots in function body (excluding prologue/epilogue).

    Returns (slots, stores, loads) where slots is the number of unique
    stack locations used.
    """
    body = extract_body(asm_content, arch)
    slots, stores, loads = analyze_stack_ops(body, arch)
    return len(slots), len(stores), len(loads)


def sanitize_filename(func_path: str) -> str:
    """Convert function path to safe filename."""
    # Remove < and >
    name = func_path.replace("<", "").replace(">", "")
    # Replace :: with _
    name = name.replace("::", "_")
    # Replace spaces
    name = name.replace(" ", "_")
    # Remove any other problematic chars
    name = re.sub(r'[^\w_.-]', '_', name)
    return name


def get_xchacha_functions(target: str) -> list[tuple[int, str]]:
    """Get list of xchacha20poly1305 functions from cargo-asm."""
    result = subprocess.run(
        ["cargo", "asm", "--lib", "-p", "redoubt-aead", "--target", target],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    functions = []
    for line in result.stdout.split("\n"):
        # Match lines like: 36 "redoubt_aead::xchacha20poly1305::..." [135]
        match = re.match(r'\s*(\d+)\s+"([^"]+)"', line)
        if match and "xchacha20poly1305" in match.group(2):
            idx = int(match.group(1))
            func_path = match.group(2)
            functions.append((idx, func_path))

    return functions


def gen_func_asm(idx: int, func_path: str, target: str, arch: str, out_dir: Path) -> None:
    """Generate assembly for a single function."""
    filename = sanitize_filename(func_path) + ".s"
    out_file = out_dir / filename

    # Short display name
    short_name = func_path.split("::")[-1][:40]
    print(f"  [{idx}] {short_name}: ", end="", flush=True)

    result = subprocess.run(
        ["cargo", "asm", "--lib", "-p", "redoubt-aead", "--target", target, str(idx)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    if result.returncode != 0:
        print(f"{YELLOW}failed{NC}")
        return

    asm_content = result.stdout
    out_file.write_text(asm_content)

    slots, stores, loads = count_spills(asm_content, arch)

    if slots == 0:
        print(f"{GREEN}0 slots{NC} -> {out_file.name}")
    elif slots < 5:
        print(f"{YELLOW}{slots} slots ({stores}W/{loads}R){NC} -> {out_file.name}")
    else:
        print(f"{RED}{slots} slots ({stores}W/{loads}R){NC} -> {out_file.name}")


def gen_arch(arch: str, target: str) -> None:
    """Generate assembly for all xchacha functions for a given architecture."""
    print(f"Fetching xchacha20poly1305 functions for {arch.upper()}...")

    functions = get_xchacha_functions(target)
    print(f"Found {len(functions)} functions\n")

    if not functions:
        print(f"{YELLOW}No xchacha20poly1305 functions found{NC}")
        return

    out_dir = ASM_DIR / arch
    out_dir.mkdir(parents=True, exist_ok=True)

    for idx, func_path in functions:
        gen_func_asm(idx, func_path, target, arch, out_dir)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "both"

    if target == "x86":
        gen_arch("x86", X86_TARGET)
    elif target == "arm":
        gen_arch("arm", ARM_TARGET)
    elif target in ("both", ""):
        gen_arch("x86", X86_TARGET)
        print()
        gen_arch("arm", ARM_TARGET)
    else:
        print(f"Usage: {sys.argv[0]} [x86|arm|both]")
        sys.exit(1)

    print(f"\nAssembly files in: {ASM_DIR}/")


if __name__ == "__main__":
    main()
