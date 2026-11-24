#!/usr/bin/env bash

# Usage: loc [hours]
# Shows lines added, removed, and net change for the last N hours (default: 6)

HOURS="${1:-6}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"

if [ -z "$REPO_ROOT" ]; then
    echo "Not a git repository."
    exit 1
fi

cd "$REPO_ROOT" || exit 1

STATS=$(git log --since="${HOURS} hours ago" --numstat --pretty="" | awk '
    { added += $1; removed += $2 }
    END { print added, removed, added - removed }
')

ADDED=$(echo "$STATS" | awk '{print $1}')
REMOVED=$(echo "$STATS" | awk '{print $2}')
NET=$(echo "$STATS" | awk '{print $3}')

if [ "$NET" -ge 0 ] 2>/dev/null; then
    NET_COLOR="\033[32m+${NET}\033[0m"
else
    NET_COLOR="\033[31m${NET}\033[0m"
fi

COMMITS=$(git log --since="${HOURS} hours ago" --oneline | wc -l)

echo -e "Last ${HOURS}h — ${COMMITS} commits"
echo -e "\033[32m+${ADDED}\033[0m added"
echo -e "\033[31m-${REMOVED}\033[0m removed"
echo -e "${NET_COLOR} net"
