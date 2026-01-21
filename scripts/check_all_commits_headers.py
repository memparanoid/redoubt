#!/usr/bin/env python3
"""Check for missing license headers in all commits."""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

EXTENSIONS = [".rs", ".S"]
SKIP_PATTERNS = ["/.private/", "/.git/", "/target/", ".private/", ".git/", "target/"]


def get_all_commits():
    """Get all commit hashes."""
    cmd = ["git", "rev-list", "--all"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout.splitlines()


def get_files_in_commit(commit):
    """Get all .rs and .S files in a specific commit."""
    cmd = ["git", "ls-tree", "-r", "--name-only", commit]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    files = []
    for line in result.stdout.splitlines():
        if any(line.endswith(ext) for ext in EXTENSIONS):
            if not any(x in line for x in SKIP_PATTERNS):
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


def process_commit(commit):
    """Process a single commit and return violations."""
    violations = []
    files = get_files_in_commit(commit)

    for filepath in files:
        has_header = check_file_header(commit, filepath)
        if has_header is False:
            violations.append((filepath, commit[:7]))

    return violations


if __name__ == "__main__":
    print("Getting all commits...")
    commits = get_all_commits()
    total = len(commits)
    print(f"Found {total} commits")

    violations = {}
    completed = 0
    lock = threading.Lock()

    print("\nChecking all files in all commits (parallel)...")

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(process_commit, c): c for c in commits}

        for future in as_completed(futures):
            with lock:
                completed += 1
                if completed % 5 == 0:
                    print(f"  Progress: {completed}/{total} commits")

            for filepath, short_hash in future.result():
                if filepath not in violations:
                    violations[filepath] = []
                violations[filepath].append(short_hash)

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
