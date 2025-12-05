#!/usr/bin/env python3
"""
Project insights: generates INSIGHTS.md with code metrics and coverage.
No external dependencies - stdlib only.
"""

import subprocess
import re
from pathlib import Path
from datetime import datetime

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

def parse_coverage_html():
    """Parse coverage/html/index.html and extract coverage percentages."""
    coverage_path = Path('coverage/html/index.html')
    if not coverage_path.exists():
        return None

    content = coverage_path.read_text()

    pattern = r"<tr class='light-row-bold'><td><pre>Totals</pre></td>" \
              r"<td[^>]*><pre>\s*([\d.]+)%\s*\((\d+)/(\d+)\)</pre></td>" \
              r"<td[^>]*><pre>\s*([\d.]+)%\s*\((\d+)/(\d+)\)</pre></td>" \
              r"<td[^>]*><pre>\s*([\d.]+)%\s*\((\d+)/(\d+)\)</pre></td>" \
              r"<td[^>]*><pre>\s*([\d.]+)%\s*\((\d+)/(\d+)\)</pre></td>"

    match = re.search(pattern, content)
    if not match:
        return None

    return {
        'function': {
            'percent': float(match.group(1)),
            'covered': int(match.group(2)),
            'total': int(match.group(3))
        },
        'line': {
            'percent': float(match.group(4)),
            'covered': int(match.group(5)),
            'total': int(match.group(6))
        },
        'region': {
            'percent': float(match.group(7)),
            'covered': int(match.group(8)),
            'total': int(match.group(9))
        },
        'branch': {
            'percent': float(match.group(10)),
            'covered': int(match.group(11)),
            'total': int(match.group(12))
        }
    }

def parse_tokei_rust(output):
    """Parse tokei output and extract Rust stats."""
    for line in output.split('\n'):
        if line.strip().startswith('Rust'):
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
            for subitem in item.iterdir():
                if subitem.is_dir() and (subitem / 'Cargo.toml').exists():
                    crates.append(subitem)
    return sorted(set(crates))

def count_assertions(path):
    """Count assertion macros in Rust files."""
    counts = {
        'assert!': 0,
        'assert_eq!': 0,
        'debug_assert!': 0,
        'debug_assert_eq!': 0
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
    lines = []

    # Header with logo
    lines.append("""<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>
""")

    lines.append(f"<p align=\"center\"><em>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}</em></p>\n")
    lines.append("---\n")

    # Coverage Section
    coverage = parse_coverage_html()
    if coverage:
        lines.append("## 📊 Test Coverage\n")
        lines.append("| Metric | Coverage | Covered | Total |")
        lines.append("|--------|----------|---------|-------|")
        lines.append(f"| **Function** | **{coverage['function']['percent']:.2f}%** | {coverage['function']['covered']:,} | {coverage['function']['total']:,} |")
        lines.append(f"| **Line** | **{coverage['line']['percent']:.2f}%** | {coverage['line']['covered']:,} | {coverage['line']['total']:,} |")
        lines.append(f"| **Region** | **{coverage['region']['percent']:.2f}%** | {coverage['region']['covered']:,} | {coverage['region']['total']:,} |")
        lines.append(f"| **Branch** | **{coverage['branch']['percent']:.2f}%** | {coverage['branch']['covered']:,} | {coverage['branch']['total']:,} |")
        lines.append("")
    else:
        lines.append("## 📊 Test Coverage\n")
        lines.append("> ⚠️ Coverage data not available. Run `./coverage.sh` to generate.\n")

    # Code Stats Section
    lines.append("## 📈 Code Statistics\n")

    full_output = run_cmd("tokei crates --sort code")
    full_stats = parse_tokei_rust(full_output)

    prod_output = run_cmd("tokei crates --sort code --exclude '**/tests/**' --exclude '**/benches/**'")
    prod_stats = parse_tokei_rust(prod_output)

    if full_stats and prod_stats:
        test_code = full_stats['code'] - prod_stats['code']
        test_lines = full_stats['lines'] - prod_stats['lines']
        test_files = full_stats['files'] - prod_stats['files']

        lines.append("| Metric | Production | Tests | Total |")
        lines.append("|--------|------------|-------|-------|")
        lines.append(f"| **Code Lines** | {prod_stats['code']:,} | {test_code:,} | {full_stats['code']:,} |")
        lines.append(f"| **Total Lines** | {prod_stats['lines']:,} | {test_lines:,} | {full_stats['lines']:,} |")
        lines.append(f"| **Files** | {prod_stats['files']:,} | {test_files:,} | {full_stats['files']:,} |")
        lines.append(f"| **Comments** | {prod_stats['comments']:,} | - | {full_stats['comments']:,} |")
        lines.append("")

        if prod_stats['code'] > 0:
            ratio = test_code / prod_stats['code']
            lines.append(f"> **Test/Code Ratio:** `{ratio:.2f}x` — {test_code:,} test lines / {prod_stats['code']:,} production lines\n")

    # Test Count Section
    lines.append("## 🧪 Tests\n")

    test_output = run_cmd("cargo test --workspace --lib 2>&1")
    test_counts = []
    for line in test_output.split('\n'):
        if 'test result:' in line and 'passed' in line:
            match = re.search(r'(\d+) passed', line)
            if match:
                test_counts.append(int(match.group(1)))

    total_tests = sum(test_counts)

    # Assertions
    assertions = count_assertions('crates')
    total_assertions = sum(assertions.values())

    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| **Total Tests** | {total_tests:,} |")
    lines.append(f"| **Total Assertions** | {total_assertions:,} |")
    if total_tests > 0:
        lines.append(f"| **Assertions/Test** | {total_assertions / total_tests:.1f} |")
    if prod_stats and prod_stats['code'] > 0:
        lines.append(f"| **Lines/Test** | {prod_stats['code'] / total_tests:.1f} |")
    lines.append("")

    # Assertion breakdown
    lines.append("<details>")
    lines.append("<summary>Assertion Breakdown</summary>\n")
    lines.append("| Macro | Count |")
    lines.append("|-------|-------|")
    for macro, count in sorted(assertions.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"| `{macro}` | {count:,} |")
    lines.append("")
    lines.append("</details>\n")

    # Per-crate breakdown
    lines.append("## 📦 Per-Crate Breakdown\n")
    lines.append("| Crate | Production Code | Tests |")
    lines.append("|-------|-----------------|-------|")

    crates = find_crates()
    crate_stats = []

    for crate_path in crates:
        crate_name = str(crate_path).replace('crates/', '')

        prod_out = run_cmd(
            "tokei --exclude '**/tests/**' --exclude '**/benches/**'",
            cwd=str(crate_path)
        )
        prod = parse_tokei_rust(prod_out)

        test_out = run_cmd("cargo test --lib 2>&1", cwd=str(crate_path))
        matches = re.findall(r'(\d+) passed', test_out)
        tests = int(matches[-1]) if matches else 0

        if prod and prod['code'] > 0:
            crate_stats.append((crate_name, prod['code'], tests))
            lines.append(f"| `{crate_name}` | {prod['code']:,} | {tests} |")

    if crate_stats:
        total_prod = sum(c[1] for c in crate_stats)
        total_crate_tests = sum(c[2] for c in crate_stats)
        lines.append(f"| **Total** | **{total_prod:,}** | **{total_crate_tests}** |")

    lines.append("")

    # Footer
    lines.append("---\n")
    lines.append("<p align=\"center\"><sub>Generated with <code>python insights.py</code></sub></p>")

    # Write to file
    output = '\n'.join(lines)
    Path('INSIGHTS.md').write_text(output)
    print(f"✅ Generated INSIGHTS.md")
    print(f"   Coverage: {coverage['line']['percent']:.2f}% lines" if coverage else "   Coverage: N/A")
    print(f"   Tests: {total_tests}")
    print(f"   Assertions: {total_assertions}")

if __name__ == '__main__':
    main()
