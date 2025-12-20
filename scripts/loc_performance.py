#!/usr/bin/env python3
"""
LOC Performance Chart Generator

Usage: python3 loc_performance.py <days>
Example: python3 loc_performance.py 7

Generates a bar chart showing lines added (green) and removed (red) per day.
"""

import subprocess
import sys
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
import os

def get_loc_for_hours(hours):
    """Get cumulative LOC stats for the last N hours using LOC.sh."""
    repo_root = Path(__file__).parent.parent
    loc_script = repo_root / 'LOC.sh'

    result = subprocess.run(
        ['bash', str(loc_script), str(hours)],
        capture_output=True,
        text=True,
        cwd=repo_root
    )

    # Parse output: "+ <insertions> - <deletions> = <net>"
    parts = result.stdout.strip().split()
    if len(parts) >= 4:
        insertions = int(parts[1]) if parts[1].isdigit() else 0
        deletions = int(parts[3]) if parts[3].isdigit() else 0
        return insertions, deletions

    return 0, 0

def get_loc_for_day(day_num):
    """Get LOC stats for a specific day (day_num days ago)."""
    # LOC for day D = LOC.sh(D * 24) - LOC.sh((D-1) * 24)
    hours_start = day_num * 24
    hours_end = (day_num - 1) * 24

    ins_start, del_start = get_loc_for_hours(hours_start)
    ins_end, del_end = get_loc_for_hours(hours_end)

    # Delta gives us the changes for that specific day
    insertions = ins_start - ins_end
    deletions = del_start - del_end

    return insertions, deletions

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 loc_performance.py <days>")
        print("Example: python3 loc_performance.py 7")
        sys.exit(1)

    try:
        days = int(sys.argv[1])
    except ValueError:
        print(f"Error: '{sys.argv[1]}' is not a valid number")
        sys.exit(1)

    if days < 1:
        print("Error: days must be >= 1")
        sys.exit(1)

    # Collect data for each day
    day_labels = []
    additions = []
    removals = []

    for day in range(days, 0, -1):
        adds, dels = get_loc_for_day(day)
        day_labels.append(f"D-{day}")
        additions.append(adds)
        removals.append(dels)

    # Create the chart
    fig, ax = plt.subplots(figsize=(max(10, days * 1.2), 6))

    x = range(len(day_labels))
    width = 0.35

    # Plot bars
    bars_add = ax.bar([i - width/2 for i in x], additions, width, label='Added', color='green', alpha=0.7)
    bars_del = ax.bar([i + width/2 for i in x], removals, width, label='Removed', color='red', alpha=0.7)

    # Customize chart
    ax.set_xlabel('Day', fontsize=12, fontweight='bold')
    ax.set_ylabel('Lines of Code', fontsize=12, fontweight='bold')
    ax.set_title(f'LOC Performance - Last {days} Days', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(day_labels, rotation=45 if days > 10 else 0)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    # Add value labels on bars
    for bars in [bars_add, bars_del]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=8)

    plt.tight_layout()

    # Save to file
    output_path = Path(__file__).parent / 'loc_performance.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')

    print(f"\n✓ Chart generated successfully!")
    print(f"\nAbsolute path:")
    print(f"file://{output_path.absolute()}")
    print(f"\nStats summary:")
    total_add = sum(additions)
    total_del = sum(removals)
    net = total_add - total_del
    print(f"  Total added:   +{total_add:,}")
    print(f"  Total removed: -{total_del:,}")
    print(f"  Net change:     {net:+,}")
    print(f"  Avg/day:        {net/days:+.1f}")

if __name__ == '__main__':
    main()
