#!/usr/bin/env python3
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

"""
Coverage report generator for Redoubt.

Usage:
    ./scripts/coverage.py                             # run all crates and generate report
    ./scripts/coverage.py redoubt-aead                # run single crate only
    ./scripts/coverage.py --report-only               # just parse existing coverage dirs

Reads crate list from .cov_crates.
Format: one crate per line, optional features after space.
  redoubt-codec
  redoubt-codec zeroize
"""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
COVERAGE_DIR = REPO_ROOT / "coverage"
COV_CRATES_FILE = REPO_ROOT / ".cov_crates"


@dataclass
class CrateStats:
    name: str
    functions: int = 0
    functions_total: int = 0
    lines: int = 0
    lines_total: int = 0
    regions: int = 0
    regions_total: int = 0
    branches: int = 0
    branches_total: int = 0

    @property
    def functions_pct(self):
        return self._pct(self.functions, self.functions_total)

    @property
    def lines_pct(self):
        return self._pct(self.lines, self.lines_total)

    @property
    def regions_pct(self):
        return self._pct(self.regions, self.regions_total)

    @property
    def branches_pct(self):
        return self._pct(self.branches, self.branches_total)

    def _pct(self, covered, total):
        if total == 0:
            return 100.0
        return (covered / total) * 100.0


def read_crates() -> list[tuple[str, str]]:
    """Read crate list from .cov_crates. Returns list of (crate_name, features)."""
    lines = COV_CRATES_FILE.read_text().splitlines()
    result = []
    for l in lines:
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        parts = l.split(None, 1)
        crate = parts[0]
        features = parts[1] if len(parts) > 1 else ""
        result.append((crate, features))
    return result


def crate_display_name(crate: str, features: str) -> str:
    """Display name for a crate, including features if any."""
    if features:
        return f"{crate} [{features}]"
    return crate


def run_cov(crate_name: str, features: str = "") -> bool:
    """Run coverage.sh for a crate."""
    cmd = [str(REPO_ROOT / "scripts" / "coverage.sh"), crate_name]
    if features:
        cmd.append(features)

    print(f"  Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=REPO_ROOT, timeout=600)

    if result.returncode != 0:
        print(f"  {crate_display_name(crate_name, features)}: FAILED (exit {result.returncode})")
        return False

    return True


def parse_html_totals(crate_name: str) -> CrateStats | None:
    """Parse the Totals row from a crate's coverage index.html."""
    index = COVERAGE_DIR / crate_name / "html" / "index.html"
    if not index.exists():
        index = COVERAGE_DIR / crate_name / "index.html"
    if not index.exists():
        return None

    html = index.read_text()

    stats = CrateStats(name=crate_name)

    totals_match = re.search(r'Totals.*?</tr>', html, re.DOTALL)
    if not totals_match:
        return None

    totals_html = totals_match.group(0)

    pairs = re.findall(r'(\d+)/(\d+)', totals_html)
    if len(pairs) >= 4:
        stats.functions, stats.functions_total = int(pairs[0][0]), int(pairs[0][1])
        stats.lines, stats.lines_total = int(pairs[1][0]), int(pairs[1][1])
        stats.regions, stats.regions_total = int(pairs[2][0]), int(pairs[2][1])
        stats.branches, stats.branches_total = int(pairs[3][0]), int(pairs[3][1])
        return stats

    return None


def pct_class(pct: float) -> str:
    if pct >= 99.0:
        return "excellent"
    elif pct >= 90.0:
        return "good"
    elif pct >= 75.0:
        return "fair"
    else:
        return "poor"


def fmt_pct(pct: float) -> str:
    return f"{pct:.2f}%"


def generate_html(all_stats: list[CrateStats], totals: CrateStats, with_links: bool = True) -> str:
    rows = ""
    for s in all_stats:
        name_cell = f'<a href="{s.name}/html/index.html">{s.name}</a>' if with_links else s.name
        rows += f"""        <tr>
            <td class="crate-name">{name_cell}</td>
            <td class="{pct_class(s.functions_pct)}">{fmt_pct(s.functions_pct)} <span class="detail">({s.functions}/{s.functions_total})</span></td>
            <td class="{pct_class(s.lines_pct)}">{fmt_pct(s.lines_pct)} <span class="detail">({s.lines}/{s.lines_total})</span></td>
            <td class="{pct_class(s.regions_pct)}">{fmt_pct(s.regions_pct)} <span class="detail">({s.regions}/{s.regions_total})</span></td>
            <td class="{pct_class(s.branches_pct)}">{fmt_pct(s.branches_pct)} <span class="detail">({s.branches}/{s.branches_total})</span></td>
        </tr>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Redoubt Coverage Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }}
        h1 {{ color: #58a6ff; margin-bottom: 8px; font-size: 24px; }}
        .subtitle {{ color: #8b949e; margin-bottom: 24px; font-size: 14px; }}
        .totals {{ display: flex; gap: 24px; margin-bottom: 32px; }}
        .total-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 160px; }}
        .total-card .label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
        .total-card .value {{ font-size: 28px; font-weight: bold; margin-top: 4px; }}
        .total-card .detail {{ color: #8b949e; font-size: 12px; margin-top: 2px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
        th {{ background: #21262d; color: #8b949e; text-align: left; padding: 12px 16px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 10px 16px; border-top: 1px solid #21262d; font-size: 14px; }}
        td .detail {{ color: #8b949e; font-size: 12px; }}
        .crate-name a {{ color: #58a6ff; text-decoration: none; font-weight: 500; }}
        .crate-name a:hover {{ text-decoration: underline; }}
        .excellent {{ color: #3fb950; }}
        .good {{ color: #d29922; }}
        .fair {{ color: #db6d28; }}
        .poor {{ color: #f85149; }}
        tr:hover {{ background: #1c2128; }}
    </style>
</head>
<body>
    <h1>Redoubt Coverage Report</h1>
    <p class="subtitle">{len(all_stats)} crates</p>

    <div class="totals">
        <div class="total-card">
            <div class="label">Functions</div>
            <div class="value {pct_class(totals.functions_pct)}">{fmt_pct(totals.functions_pct)}</div>
            <div class="detail">{totals.functions}/{totals.functions_total}</div>
        </div>
        <div class="total-card">
            <div class="label">Lines</div>
            <div class="value {pct_class(totals.lines_pct)}">{fmt_pct(totals.lines_pct)}</div>
            <div class="detail">{totals.lines}/{totals.lines_total}</div>
        </div>
        <div class="total-card">
            <div class="label">Regions</div>
            <div class="value {pct_class(totals.regions_pct)}">{fmt_pct(totals.regions_pct)}</div>
            <div class="detail">{totals.regions}/{totals.regions_total}</div>
        </div>
        <div class="total-card">
            <div class="label">Branches</div>
            <div class="value {pct_class(totals.branches_pct)}">{fmt_pct(totals.branches_pct)}</div>
            <div class="detail">{totals.branches}/{totals.branches_total}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Crate</th>
                <th>Functions</th>
                <th>Lines</th>
                <th>Regions</th>
                <th>Branches</th>
            </tr>
        </thead>
        <tbody>
{rows}        </tbody>
    </table>
</body>
</html>"""


def main():
    report_only = "--report-only" in sys.argv
    open_report = "--open" in sys.argv
    no_cache = "--no-cache" in sys.argv
    flags = ("--report-only", "--open", "--no-cache")
    args = [a for a in sys.argv[1:] if a not in flags]
    single_crate = args[0] if args else None

    crates = read_crates()
    crate_names = [c for c, _ in crates]

    if no_cache:
        if single_crate:
            target = REPO_ROOT / "target" / "coverage" / single_crate
            if target.exists():
                shutil.rmtree(target)
                print(f"Cleaned cache: {target}")
        else:
            target = REPO_ROOT / "target" / "coverage"
            if target.exists():
                shutil.rmtree(target)
                print(f"Cleaned cache: {target}")
        print()

    if single_crate:
        # Find features for the single crate
        features = ""
        for c, f in crates:
            if c == single_crate:
                features = f
                break
        print(f"Running coverage for: {crate_display_name(single_crate, features)}")
        run_cov(single_crate, features)
        print()
    elif not report_only:
        print(f"Redoubt Coverage Report")
        print(f"  Crates: {len(crates)}")
        print()
        for crate, features in crates:
            run_cov(crate, features)
            print()

    # Parse results
    all_stats: list[CrateStats] = []
    for crate in crate_names:
        stats = parse_html_totals(crate)
        if stats:
            print(f"  {crate}: functions={fmt_pct(stats.functions_pct)} lines={fmt_pct(stats.lines_pct)} branches={fmt_pct(stats.branches_pct)}")
            all_stats.append(stats)
        else:
            print(f"  {crate}: SKIPPED (no report found)")

    # Compute totals
    totals = CrateStats(name="TOTAL")
    for s in all_stats:
        totals.functions += s.functions
        totals.functions_total += s.functions_total
        totals.lines += s.lines
        totals.lines_total += s.lines_total
        totals.regions += s.regions
        totals.regions_total += s.regions_total
        totals.branches += s.branches
        totals.branches_total += s.branches_total

    print()
    print(f"  TOTAL: functions={fmt_pct(totals.functions_pct)} lines={fmt_pct(totals.lines_pct)} regions={fmt_pct(totals.regions_pct)} branches={fmt_pct(totals.branches_pct)}")

    # Generate HTML reports
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    (COVERAGE_DIR / "index.html").write_text(generate_html(all_stats, totals, with_links=True))
    (COVERAGE_DIR / "report.html").write_text(generate_html(all_stats, totals, with_links=False))

    print()
    print(f"Local report:  {COVERAGE_DIR / 'index.html'}")
    print(f"Public report: {COVERAGE_DIR / 'report.html'}")

    if open_report:
        import webbrowser
        if single_crate:
            target = COVERAGE_DIR / single_crate / "html" / "index.html"
        else:
            target = COVERAGE_DIR / "index.html"
        webbrowser.open(f"file://{target}")


if __name__ == "__main__":
    main()
