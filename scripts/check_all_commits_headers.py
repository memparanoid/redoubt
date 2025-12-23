#!/usr/bin/env python3
"""Check for missing license headers in all commits."""

import subprocess
import sys


def get_all_commits():
    """Get all commit hashes."""
    cmd = ["git", "rev-list", "--all"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout.splitlines()


def get_files_in_commit(commit, extensions):
    """Get all .rs and .S files in a specific commit."""
    cmd = ["git", "ls-tree", "-r", "--name-only", commit]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    files = []
    for line in result.stdout.splitlines():
        if any(line.endswith(ext) for ext in extensions):
            # Skip .private, .git, target
            if any(
                x in line
                for x in [
                    "/.private/",
                    "/.git/",
                    "/target/",
                    ".private/",
                    ".git/",
                    "target/",
                ]
            ):
                continue
            files.append(line)
    return files


def check_file_header(commit, filepath):
    """Check if file has Copyright header in specific commit."""
    cmd = ["git", "show", f"{commit}:{filepath}"]
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )

    if result.returncode != 0:
        return None

    first_line = result.stdout.split("\n")[0] if result.stdout else ""
    return "Copyright" in first_line


if __name__ == "__main__":
    extensions = [".rs", ".S"]

    print("Getting all commits...")
    commits = get_all_commits()
    print(f"Found {len(commits)} commits")

    # Track violations: {filepath: [(commit, short_hash), ...]}
    violations = {}

    print("\nChecking all files in all commits...")
    for i, commit in enumerate(commits):
        if i % 100 == 0:
            print(f"  Progress: {i}/{len(commits)} commits")

        files = get_files_in_commit(commit, extensions)

        for filepath in files:
            has_header = check_file_header(commit, filepath)

            if has_header is False:  # Explicitly False, not None
                if filepath not in violations:
                    violations[filepath] = []
                violations[filepath].append(commit[:7])

    if violations:
        print(
            f"\n❌ Found {len(violations)} files missing Copyright header in some commits:\n"
        )
        for filepath, commits_list in sorted(violations.items()):
            print(f"  {filepath}")
            print(
                f"    Missing in {len(commits_list)} commit(s): {', '.join(commits_list[:5])}"
            )
            if len(commits_list) > 5:
                print(f"    ... and {len(commits_list) - 5} more")
            print()
    else:
        print("\n✅ All files have Copyright headers in all commits!")
