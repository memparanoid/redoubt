#!/usr/bin/env python3
"""
Rename a crate following Redoubt naming conventions.

Usage: python scripts/rename_crate.py <old_name> <new_name>
Example: python scripts/rename_crate.py memrand redoubt-rand
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


def rename_crate(old_name: str, new_name: str):
    """Rename a crate with proper handling of hyphens vs underscores."""

    project_root = Path(__file__).parent.parent
    old_name_underscore = old_name.replace("-", "_")
    new_name_underscore = new_name.replace("-", "_")
    new_name_hyphen = new_name.replace("_", "-")

    print(f"🔄 Renaming {old_name} → {new_name}")
    print(f"   Directory: crates/{old_name} → crates/{new_name_hyphen}")
    print(f"   Imports:   {old_name_underscore}:: → {new_name_underscore}::")

    # 1. Rename directory
    old_dir = project_root / "crates" / old_name
    new_dir = project_root / "crates" / new_name_hyphen

    if old_dir.exists():
        old_dir.rename(new_dir)
        print(f"✓ Renamed directory")
    else:
        print(f"✗ Directory not found: {old_dir}")
        return False

    # 2. Update crate's own Cargo.toml
    crate_toml = new_dir / "Cargo.toml"
    if crate_toml.exists():
        content = crate_toml.read_text()
        content = re.sub(
            rf'name\s*=\s*"{old_name}"',
            f'name = "{new_name_hyphen}"',
            content
        )
        crate_toml.write_text(content)
        print(f"✓ Updated crate Cargo.toml")

    # 3. Update workspace Cargo.toml
    workspace_toml = project_root / "Cargo.toml"
    content = workspace_toml.read_text()

    # Update members list
    content = re.sub(
        rf'"crates/{old_name}"',
        f'"crates/{new_name_hyphen}"',
        content
    )

    # Update workspace.dependencies
    content = re.sub(
        rf'{old_name_underscore}\s*=\s*{{\s*path\s*=\s*"crates/{old_name}"\s*}}',
        f'{new_name_underscore:15} = {{ path = "crates/{new_name_hyphen}" }}',
        content
    )

    workspace_toml.write_text(content)
    print(f"✓ Updated workspace Cargo.toml")

    # 4. Update all Cargo.toml files (dependencies)
    for toml_file in project_root.rglob("Cargo.toml"):
        if "target" in toml_file.parts or toml_file == workspace_toml:
            continue

        content = toml_file.read_text()
        original = content

        # Fix workspace dependencies: old_name.workspace → new-name.workspace
        content = re.sub(
            rf'{old_name_underscore}\.workspace',
            f'{new_name_hyphen}.workspace',
            content
        )

        # Fix path dependencies
        content = re.sub(
            rf'{old_name_underscore}\s*=\s*{{\s*path\s*=\s*"[^"]*/{old_name}"',
            f'{new_name_underscore} = {{ path = "../{new_name_hyphen}"',
            content
        )

        if content != original:
            toml_file.write_text(content)

    print(f"✓ Updated all Cargo.toml dependencies")

    # 5. Update Rust source files (.rs)
    for rs_file in project_root.rglob("*.rs"):
        if "target" in rs_file.parts:
            continue

        content = rs_file.read_text()
        original = content

        # Replace use statements: use old_name:: → use new_name::
        content = re.sub(
            rf'\buse {old_name_underscore}::',
            f'use {new_name_underscore}::',
            content
        )

        # Replace extern crate
        content = re.sub(
            rf'\bextern crate {old_name_underscore}\b',
            f'extern crate {new_name_underscore}',
            content
        )

        if content != original:
            rs_file.write_text(content)

    print(f"✓ Updated Rust source files")

    # 6. Update snapshots (.snap)
    for snap_file in project_root.rglob("*.snap"):
        if "target" in snap_file.parts:
            continue

        content = snap_file.read_text()
        original = content

        # Snapshots use underscores
        content = content.replace(old_name_underscore, new_name_underscore)

        if content != original:
            snap_file.write_text(content)

    print(f"✓ Updated snapshot files")

    # 7. Update Docker and shell scripts
    for pattern in ["*.sh", "Dockerfile*"]:
        for script_file in project_root.rglob(pattern):
            if "target" in script_file.parts or ".git" in script_file.parts:
                continue

            try:
                content = script_file.read_text()
                original = content

                # cargo -p uses hyphens
                content = re.sub(
                    rf'\bcargo\s+([a-z-]+\s+)*-p\s+{old_name}\b',
                    lambda m: m.group(0).replace(old_name, new_name_hyphen),
                    content
                )

                # Directory references use hyphens
                content = re.sub(
                    rf'crates/{old_name}',
                    f'crates/{new_name_hyphen}',
                    content
                )

                # Generic references (be conservative)
                content = content.replace(old_name, new_name_hyphen)

                if content != original:
                    script_file.write_text(content)
            except UnicodeDecodeError:
                # Skip binary files
                pass

    print(f"✓ Updated Docker and shell scripts")

    print(f"\n✅ Rename complete: {old_name} → {new_name_hyphen}")
    print(f"   Run: cargo test -p {new_name_hyphen}")

    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/rename_crate.py <old_name> <new_name>")
        print("Example: python scripts/rename_crate.py memrand redoubt-rand")
        sys.exit(1)

    old_name = sys.argv[1]
    new_name = sys.argv[2]

    success = rename_crate(old_name, new_name)
    sys.exit(0 if success else 1)
