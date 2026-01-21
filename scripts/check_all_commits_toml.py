#!/usr/bin/env python3
"""Check for license consistency in Cargo.toml across all commits."""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re


def get_all_commits():
    """Get all commit hashes."""
    cmd = ["git", "rev-list", "--all"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout.splitlines()


def get_file_content(commit, filepath):
    """Get file content at specific commit."""
    cmd = ["git", "show", f"{commit}:{filepath}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout


def get_crate_cargo_tomls(commit):
    """Get all Cargo.toml files in crates/*/ for a commit."""
    cmd = ["git", "ls-tree", "-r", "--name-only", commit]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    files = []
    for line in result.stdout.splitlines():
        if line.startswith("crates/") and line.endswith("Cargo.toml"):
            files.append(line)
    return files


def process_commit(commit):
    """Process a single commit and return violations."""
    violations = []

    # Check root Cargo.toml has GPL-3.0-only
    root_content = get_file_content(commit, "Cargo.toml")
    if root_content:
        if 'license' in root_content:
            if 'GPL-3.0-only' not in root_content:
                violations.append(("Cargo.toml", "missing GPL-3.0-only", commit[:7]))

    # Check crates/*/Cargo.toml have license.workspace = true
    crate_tomls = get_crate_cargo_tomls(commit)
    for filepath in crate_tomls:
        content = get_file_content(commit, filepath)
        if content:
            has_license_workspace = re.search(r'license\.workspace\s*=\s*true', content)
            has_any_license = 'license' in content.lower()

            if has_any_license and not has_license_workspace:
                violations.append((filepath, "missing license.workspace = true", commit[:7]))

    return violations


if __name__ == "__main__":
    print("Getting all commits...")
    commits = get_all_commits()
    total = len(commits)
    print(f"Found {total} commits")

    violations = {}
    completed = 0
    lock = threading.Lock()

    print("\nChecking license consistency in all commits (parallel)...")

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(process_commit, c): c for c in commits}

        for future in as_completed(futures):
            with lock:
                completed += 1
                if completed % 5 == 0:
                    print(f"  Progress: {completed}/{total} commits")

            for filepath, reason, short_hash in future.result():
                key = (filepath, reason)
                if key not in violations:
                    violations[key] = []
                violations[key].append(short_hash)

    if violations:
        print(f"\n❌ Found {len(violations)} license issues in some commits:\n")
        for (filepath, reason), commits_list in sorted(violations.items()):
            print(f"  {filepath}: {reason}")
            print(f"    In {len(commits_list)} commit(s): {', '.join(commits_list[:5])}")
            if len(commits_list) > 5:
                print(f"    ... and {len(commits_list) - 5} more")
            print()
    else:
        print("\n✅ All Cargo.toml files have consistent licenses in all commits!")
