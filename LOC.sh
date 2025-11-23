#!/bin/bash
# Usage: ./loc.sh <hours>
# Example: ./loc.sh 8
# This script shows net lines of code changed in the last N hours

HOURS=$1

git log --since="$HOURS hours ago" --shortstat --oneline |
  grep -E "files? changed" |
  awk '{ins+=$4; del+=$6} END {print "+",ins,"-",del,"=", (ins-del)}'
