#!/usr/bin/env python3
"""
Idempotent license header manager.

Removes existing license headers and adds standardized GPL-3.0-only headers.
Running this script multiple times produces the same result.
"""

import re
from pathlib import Path

# License header template (GPL-3.0-only)
HEADER_TEMPLATE = """// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.
"""

# Patterns to detect existing license headers
LICENSE_PATTERNS = [
    re.compile(
        r"^// Copyright.*?\n(?:// .*?(?:License|MIT|Apache|BUSL|Business Source).*?\n)+",
        re.MULTILINE | re.IGNORECASE,
    ),
    re.compile(
        r"^/\*\*?\s*Copyright.*?\*/\s*\n", re.MULTILINE | re.DOTALL | re.IGNORECASE
    ),
]


def remove_existing_headers(content: str) -> str:
    """Remove any existing license headers from content."""
    for pattern in LICENSE_PATTERNS:
        content = pattern.sub("", content)
    return content


def add_header(content: str, file_ext: str) -> str:
    """Add license header to content if not present."""
    # Remove existing headers first (idempotent)
    content = remove_existing_headers(content)

    if file_ext == ".rs":
        # For Rust files, add header before any content
        # But after shebang if present
        lines = content.split("\n")
        insert_pos = 0

        # Skip shebang
        if lines and lines[0].startswith("#!"):
            insert_pos = 1

        # Remove leading empty lines after insert position
        while insert_pos < len(lines) and lines[insert_pos] == "":
            lines.pop(insert_pos)

        # Insert header
        header_lines = HEADER_TEMPLATE.strip().split("\n")
        result_lines = lines[:insert_pos] + header_lines + [""] + lines[insert_pos:]
        return "\n".join(result_lines)

    return content


def process_file(filepath: Path) -> bool:
    """Process a single file. Returns True if modified."""
    try:
        content = filepath.read_text(encoding="utf-8")
        original = content

        new_content = add_header(content, filepath.suffix)

        if new_content != original:
            filepath.write_text(new_content, encoding="utf-8")
            return True
        return False
    except Exception as e:
        print(f"✗ Error processing {filepath}: {e}")
        return False


def main():
    """Process all Rust source files in the project."""
    project_root = Path(__file__).parent.parent

    # Find all .rs files in crates/
    rust_files = list(project_root.glob("crates/**/*.rs"))

    modified_count = 0
    skipped_count = 0

    for filepath in rust_files:
        if process_file(filepath):
            print(f"✓ Updated {filepath.relative_to(project_root)}")
            modified_count += 1
        else:
            skipped_count += 1

    print(f"\n{'=' * 60}")
    print(f"Modified: {modified_count} files")
    print(f"Unchanged: {skipped_count} files")
    print(f"Total: {modified_count + skipped_count} files")


if __name__ == "__main__":
    main()
