#!/usr/bin/env bash
set -euo pipefail

echo "[*] Core Dump Analysis - Progressive Key Search"
echo ""

# Launch the report binary in background, capturing stdout to file
echo "[*] Launching forensics report binary..."
./target/release/redoubt_leaks_report > /tmp/rust_output.txt 2>&1 &
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

# Extract master key and patterns from Rust output
echo "[*] Extracting master key and patterns..."

# Extract master key
MASTER_KEY=$(grep "^Master Key: " /tmp/rust_output.txt | sed 's/Master Key: //')
if [ -n "$MASTER_KEY" ]; then
    echo "$MASTER_KEY" > /tmp/master_key.hex
    echo "[+] Master key captured: ${MASTER_KEY:0:16}...${MASTER_KEY: -16}"
else
    echo "[!] WARNING: Master key not found in output"
fi

# Extract hardcoded patterns
PATTERN_COUNT=0
declare -a PATTERNS
while IFS= read -r line; do
    if [[ $line =~ ^Pattern\ #[0-9]+:\ ([a-fA-F0-9]+)$ ]]; then
        PATTERN_HEX="${BASH_REMATCH[1]}"
        PATTERNS[$PATTERN_COUNT]="$PATTERN_HEX"
        echo "[+] Pattern #$((PATTERN_COUNT + 1)) captured: 0x${PATTERN_HEX}"
        PATTERN_COUNT=$((PATTERN_COUNT + 1))
    fi
done < <(grep "^Pattern #" /tmp/rust_output.txt)

# Extract secret values
VALUE_COUNT=0
declare -a VALUES
while IFS= read -r line; do
    if [[ $line =~ ^Value\ #[0-9]+:\ ([a-fA-F0-9]+)$ ]]; then
        VALUE_HEX="${BASH_REMATCH[1]}"
        VALUES[$VALUE_COUNT]="$VALUE_HEX"
        echo "[+] Value #$((VALUE_COUNT + 1)) captured: 0x${VALUE_HEX}"
        VALUE_COUNT=$((VALUE_COUNT + 1))
    fi
done < <(grep "^Value #" /tmp/rust_output.txt)

echo "[+] Total: $PATTERN_COUNT patterns + $VALUE_COUNT values + 1 master key"
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

# Run forensic analysis
echo "[*] Starting forensic analysis..."
echo ""

LEAK_DETECTED=0

# Analyze master key (progressive search)
if [ -f /tmp/master_key.hex ]; then
    echo "[*] Analyzing master key (progressive prefix search)..."
    python3 forensics/memory_analysis/scripts/analyze_value.py "$CORE_FILE" /tmp/master_key.hex
    RESULT=$?
    if [ $RESULT -eq 1 ]; then
        LEAK_DETECTED=1
        echo "[!] LEAK DETECTED in master key"
    fi
    echo ""
fi

# Analyze secret values (progressive search)
for i in $(seq 0 $((VALUE_COUNT - 1))); do
    VALUE_HEX="${VALUES[$i]}"
    echo "$VALUE_HEX" > /tmp/value_${i}.hex
    echo "[*] Analyzing Value #$((i + 1)): 0x${VALUE_HEX} (progressive prefix search)..."
    python3 forensics/memory_analysis/scripts/analyze_value.py "$CORE_FILE" /tmp/value_${i}.hex
    RESULT=$?
    if [ $RESULT -eq 1 ]; then
        LEAK_DETECTED=1
        echo "[!] LEAK DETECTED in Value #$((i + 1))"
    fi
    rm -f /tmp/value_${i}.hex
    echo ""
done

# Analyze hardcoded patterns (block search)
for i in $(seq 0 $((PATTERN_COUNT - 1))); do
    PATTERN_HEX="${PATTERNS[$i]}"
    echo "[*] Analyzing Pattern #$((i + 1)): 0x${PATTERN_HEX} (contiguous block search)..."
    python3 forensics/memory_analysis/scripts/analyze_pattern.py "$CORE_FILE" "$PATTERN_HEX"
    RESULT=$?
    if [ $RESULT -eq 1 ]; then
        LEAK_DETECTED=1
        echo "[!] LEAK DETECTED in Pattern #$((i + 1))"
    fi
    echo ""
done

# Cleanup
rm -f /tmp/master_key.hex
rm -f "$CORE_FILE"

if [ $LEAK_DETECTED -eq 1 ]; then
    echo "[!] LEAK CONFIRMED: Sensitive data found in core dump"
    exit 1
else
    echo "[+] Analysis complete - no leaks detected"
    exit 0
fi
