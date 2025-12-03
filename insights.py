#!/usr/bin/env python3
"""
Project insights: code metrics, test coverage, and assertion counts.
No external dependencies - stdlib only.
"""

import subprocess
import re
import os
from pathlib import Path

def run_cmd(cmd, cwd=None):
    """Run command and return output."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        cwd=cwd
    )
    return result.stdout

def parse_tokei_rust(output):
    """Parse tokei output and extract Rust stats."""
    for line in output.split('\n'):
        if line.strip().startswith('Rust'):
            # Format: Rust  Files  Lines  Code  Comments  Blanks
            parts = line.split()
            if len(parts) >= 6:
                try:
                    return {
                        'files': int(parts[1].replace(',', '')),
                        'lines': int(parts[2].replace(',', '')),
                        'code': int(parts[3].replace(',', '')),
                        'comments': int(parts[4].replace(',', '')),
                        'blanks': int(parts[5].replace(',', ''))
                    }
                except (ValueError, IndexError):
                    continue
    return None

def find_crates():
    """Find all crates in workspace."""
    crates = []
    crates_dir = Path('crates')
    if crates_dir.exists():
        for item in crates_dir.iterdir():
            if item.is_dir() and (item / 'Cargo.toml').exists():
                crates.append(item)
            # Check for nested crates (e.g., memcodec/core)
            for subitem in item.iterdir():
                if subitem.is_dir() and (subitem / 'Cargo.toml').exists():
                    crates.append(subitem)
    return sorted(set(crates))

def count_assertions(path):
    """Count assertion macros in Rust files."""
    counts = {
        'assert_eq!': 0,
        'assert!': 0,
        'debug_assert_eq!': 0,
        'debug_assert!': 0
    }

    for rust_file in Path(path).rglob('*.rs'):
        try:
            content = rust_file.read_text()
            for macro in counts.keys():
                counts[macro] += content.count(macro)
        except:
            pass

    return counts

def main():
    print("=" * 80)
    print("MEMORA PROJECT INSIGHTS")
    print("=" * 80)

    # 1. Full project stats
    print("\n📊 FULL PROJECT STATS (including tests)")
    print("-" * 80)
    full_output = run_cmd("tokei crates --sort code")
    print(full_output)
    full_stats = parse_tokei_rust(full_output)

    # 2. Production code only (exclude tests/benches)
    print("\n🔧 PRODUCTION CODE (excluding tests/benches)")
    print("-" * 80)
    prod_output = run_cmd("tokei crates --sort code --exclude '**/tests/**' --exclude '**/benches/**'")
    print(prod_output)
    prod_stats = parse_tokei_rust(prod_output)

    # 3. Calculate test code
    if full_stats and prod_stats:
        test_code = full_stats['code'] - prod_stats['code']
        test_lines = full_stats['lines'] - prod_stats['lines']

        print("\n📝 TEST CODE DIFFERENCE")
        print("-" * 80)
        print(f"{'Metric':<20} {'Production':<15} {'Tests':<15} {'Total':<15}")
        print("-" * 80)
        print(f"{'Code lines':<20} {prod_stats['code']:<15,} {test_code:<15,} {full_stats['code']:<15,}")
        print(f"{'Total lines':<20} {prod_stats['lines']:<15,} {test_lines:<15,} {full_stats['lines']:<15,}")
        print(f"{'Files':<20} {prod_stats['files']:<15,} {full_stats['files'] - prod_stats['files']:<15,} {full_stats['files']:<15,}")

        if prod_stats['code'] > 0:
            ratio = test_code / prod_stats['code']
            print(f"\n📈 Test/Code Ratio: {ratio:.2f}x ({test_code:,} test lines / {prod_stats['code']:,} prod lines)")

    # 4. Run tests and count
    print("\n🧪 RUNNING TESTS")
    print("-" * 80)
    test_output = run_cmd("cargo test --workspace --lib 2>&1")

    # Parse test results
    test_counts = []
    for line in test_output.split('\n'):
        if 'test result:' in line and 'passed' in line:
            match = re.search(r'(\d+) passed', line)
            if match:
                test_counts.append(int(match.group(1)))

    total_tests = sum(test_counts)
    print(f"Total tests: {total_tests}")

    if prod_stats and total_tests > 0:
        lines_per_test = prod_stats['code'] / total_tests
        print(f"Lines per test: {lines_per_test:.1f}")

    # 5. Count assertions
    print("\n✅ ASSERTION COUNTS")
    print("-" * 80)
    assertions = count_assertions('.')
    total_assertions = sum(assertions.values())

    for macro, count in sorted(assertions.items(), key=lambda x: x[1], reverse=True):
        print(f"{macro:<25} {count:>10,}")
    print("-" * 80)
    print(f"{'TOTAL':<25} {total_assertions:>10,}")

    if total_tests > 0:
        assertions_per_test = total_assertions / total_tests
        print(f"\nAssertions per test: {assertions_per_test:.1f}")

    # 6. Per-crate breakdown
    print("\n📦 PER-CRATE BREAKDOWN (production code only)")
    print("-" * 80)
    print(f"{'Crate':<30} {'Code':<12} {'Tests':<10}")
    print("-" * 80)

    crates = find_crates()
    crate_stats = []

    for crate_path in crates:
        crate_name = str(crate_path).replace('crates/', '')

        # Get production code
        prod_out = run_cmd(
            "tokei --exclude '**/tests/**' --exclude '**/benches/**'",
            cwd=str(crate_path)
        )
        prod = parse_tokei_rust(prod_out)

        # Get test count
        test_out = run_cmd("cargo test --lib 2>&1", cwd=str(crate_path))
        # Find last occurrence of "N passed"
        matches = re.findall(r'(\d+) passed', test_out)
        tests = int(matches[-1]) if matches else 0

        if prod:
            crate_stats.append((crate_name, prod['code'], tests))
            print(f"{crate_name:<30} {prod['code']:>12,} {tests:>10}")

    print("-" * 80)
    if crate_stats:
        total_prod = sum(c[1] for c in crate_stats)
        total_tests = sum(c[2] for c in crate_stats)
        print(f"{'TOTAL':<30} {total_prod:>12,} {total_tests:>10}")

    print("=" * 80)

if __name__ == '__main__':
    main()
