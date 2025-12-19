#!/usr/bin/env bash
set -euo pipefail

echo "[*] Core Dump Analysis - Progressive Key Search"
echo ""

# Launch the test binary in background, capturing stdout to file
echo "[*] Launching test binary..."
./target/release/test_redoubt_leaks > /tmp/rust_output.txt 2>&1 &
RUST_PID=$!
echo "[+] Process started with PID: $RUST_PID"

# Show output in real-time
tail -f /tmp/rust_output.txt &
TAIL_PID=$!
echo ""

# Wait for DUMP_NOW signal
echo "[*] Waiting for patterns generation..."
for i in {1..3000}; do
    if grep -q "DUMP_NOW" /tmp/rust_output.txt 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# Extract all patterns from Rust output
echo "[*] Extracting patterns..."
PATTERN_COUNT=0
while IFS= read -r line; do
    PATTERN_NUM=$(echo "$line" | sed -n 's/Pattern #\([0-9]*\):.*/\1/p')
    PATTERN_HEX=$(echo "$line" | sed 's/Pattern #[0-9]*: //')

    if [ -n "$PATTERN_NUM" ] && [ -n "$PATTERN_HEX" ]; then
        echo "$PATTERN_HEX" > "/tmp/pattern_${PATTERN_NUM}.hex"
        echo "[+] Pattern #${PATTERN_NUM} captured: ${PATTERN_HEX:0:16}...${PATTERN_HEX: -16}"
        PATTERN_COUNT=$((PATTERN_COUNT + 1))
    fi
done < <(grep "Pattern #" /tmp/rust_output.txt)

if [ $PATTERN_COUNT -eq 0 ]; then
    echo "[!] ERROR: No patterns found in Rust output"
    exit 1
fi
echo "[+] Total patterns captured: $PATTERN_COUNT"
echo ""

echo ""
echo "[*] Test binary output:"
echo ""
cat /tmp/rust_output.txt
echo ""

# Give it a moment to settle
sleep 1

# Generate core dump
echo "[*] Generating core dump..."
kill -ABRT $RUST_PID || true
wait $RUST_PID 2>/dev/null || true

# Find the core dump
CORE_FILE=""
if [ -f "core.$RUST_PID" ]; then
    CORE_FILE="core.$RUST_PID"
elif [ -f "core" ]; then
    CORE_FILE="core"
else
    echo "[!] ERROR: Core dump not found"
    exit 1
fi

echo "[+] Core dump generated: $CORE_FILE"
CORE_SIZE=$(stat -c%s "$CORE_FILE" 2>/dev/null || stat -f%z "$CORE_FILE")
if [ $CORE_SIZE -lt 1048576 ]; then
    echo "[*] Core dump size: $((CORE_SIZE / 1024)) KB"
else
    echo "[*] Core dump size: $((CORE_SIZE / 1024 / 1024)) MB"
fi
echo ""

# Copy core dump to mounted volume for manual inspection
if [ -d "/workspace/core_dumps" ]; then
    cp "$CORE_FILE" "/workspace/core_dumps/core_dump_$(date +%Y%m%d_%H%M%S)"
    echo "[+] Core dump copied to /workspace/core_dumps/"
    echo ""
fi

# Manual inspection: search for AAAA pattern (0xAA repeated)
echo "[*] Manual check: searching for 0xAA pattern in core dump..."
AAAA_COUNT=$(xxd -p "$CORE_FILE" | tr -d '\n' | grep -o 'aaaa' | wc -l)
echo "[+] Found 0xAAAA (2 bytes): $AAAA_COUNT times"
echo ""

# Run Python analysis for each pattern
echo "[*] Starting progressive pattern search..."
echo ""

LEAK_DETECTED=0
for i in $(seq 1 $PATTERN_COUNT); do
    PATTERN_FILE="/tmp/pattern_${i}.hex"

    echo "[*] Analyzing Pattern #${i}..."
    python3 forensics/memory_analysis/scripts/search_patterns_in_core_dump.py "$CORE_FILE" "$PATTERN_FILE"
    RESULT=$?

    if [ $RESULT -eq 1 ]; then
        LEAK_DETECTED=1
        echo "[!] LEAK DETECTED in Pattern #${i}"
    fi
    echo ""
done

# Cleanup
for i in $(seq 1 $PATTERN_COUNT); do
    rm -f "/tmp/pattern_${i}.hex"
done
rm -f "$CORE_FILE"

if [ $LEAK_DETECTED -eq 1 ]; then
    echo "[!] LEAK CONFIRMED: Pattern found in core dump"
    exit 1
else
    echo "[+] Analysis complete - no patterns leaked"
    exit 0
fi
