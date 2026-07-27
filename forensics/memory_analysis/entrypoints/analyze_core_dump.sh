#!/usr/bin/env bash
# Runs the trace report and analyzes the memory dump it writes.
#
# The binary dumps its own memory and vector registers (see `src/dumper.rs`) and
# prints the path. Nothing here depends on `kernel.core_pattern`, on ptrace
# capabilities, or on root — that sysctl is global rather than per-container, so
# a lab built on kernel-written core dumps behaves differently depending on
# whose kernel the container is running under, which is not a difference this
# analysis should be sensitive to.
set -euo pipefail

OUT_DIR="${FORENSICS_OUT_DIR:-/workspace/core_dumps}"
mkdir -p "$OUT_DIR"

SCRIPTS="forensics/memory_analysis/scripts"
LOG=$(mktemp)
trap 'rm -f "$LOG" /tmp/needle_*.hex' EXIT

echo "[*] Running trace report..."
FORENSICS_DUMP_STEM="${OUT_DIR}/memdump" \
    ./target/release/redoubt_trace_report | tee "$LOG"

DUMP=$(grep '^DUMP_WRITTEN: ' "$LOG" | sed 's/DUMP_WRITTEN: //')
[ -f "$DUMP" ] || { echo "[!] ERROR: dump not written"; exit 1; }

SIZE=$(stat -c%s "$DUMP" 2>/dev/null || stat -f%z "$DUMP")
echo ""
echo "[+] Dump: $DUMP ($((SIZE / 1024)) KB)"
echo ""

# ── Positive control ─────────────────────────────────────────────────────────
#
# The canary is never zeroized, so it has to be in the dump. If it is missing,
# the dumper looked somewhere other than where the data is, and every "clean"
# result below means nothing — so this runs first and is fatal.
CANARY=$(grep '^Canary: ' "$LOG" | sed 's/Canary: //')
python3 "$SCRIPTS/analyze_regions.py" --expect "$DUMP" "$CANARY" || exit 2

# ── The analysis ─────────────────────────────────────────────────────────────
TRACE=0

analyze() {  # analyze <label> <hex>
    echo "[*] $1"
    echo "$2" > /tmp/needle_current.hex
    python3 "$SCRIPTS/analyze_value.py"   "$DUMP" /tmp/needle_current.hex || TRACE=1
    python3 "$SCRIPTS/analyze_regions.py" "$DUMP" /tmp/needle_current.hex || TRACE=1
    echo ""
}

MASTER_KEY=$(grep '^Master Key: ' "$LOG" | sed 's/Master Key: //' || true)
[ -n "$MASTER_KEY" ] && analyze "Master key" "$MASTER_KEY"

while read -r value; do
    [ -n "$value" ] && analyze "Value 0x$value" "$value"
done < <(grep '^Value #' "$LOG" | sed 's/^Value #[0-9]*: //' || true)

# Repeated byte patterns need a block search rather than a value search: a
# single byte occurs constantly by chance, a contiguous run of it does not.
while read -r pattern; do
    [ -z "$pattern" ] && continue
    echo "[*] Pattern 0x$pattern (contiguous block search)"
    python3 "$SCRIPTS/analyze_pattern.py" "$DUMP" "$pattern" || TRACE=1
    echo ""
done < <(grep '^Pattern #' "$LOG" | sed 's/^Pattern #[0-9]*: //' || true)

# The dump holds every secret the run was hunting for. It is created 0600 and
# removed here; keep it only when explicitly asked for.
if [ "${FORENSICS_KEEP_DUMP:-0}" != "1" ]; then
    rm -f "$DUMP" "${DUMP%.bin}.idx"
    echo "[*] Dump removed (set FORENSICS_KEEP_DUMP=1 to retain it)"
fi

if [ "$TRACE" -eq 1 ]; then
    echo "[!] TRACE CONFIRMED: sensitive data found in the dump"
    exit 1
fi
echo "[+] Analysis complete - no traces detected"
