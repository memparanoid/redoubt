#!/usr/bin/env bash
set -euo pipefail

echo "[*] Core Dump Analysis - Progressive Key Search"
echo ""

# Launch the test binary in background, capturing stdout
echo "[*] Launching test binary..."
./target/debug/test_redoubt_leaks > /tmp/rust_output.txt 2>&1 &
RUST_PID=$!
echo "[+] Process started with PID: $RUST_PID"
echo ""

# Wait for KEY_READY:DEADBEEF signal
echo "[*] Waiting for key generation..."
for i in {1..3000}; do
    if grep -q "KEY_READY:DEADBEEF" /tmp/rust_output.txt 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# Extract key from Rust output
KEY_HEX=$(grep "KEY_HEX:" /tmp/rust_output.txt | cut -d: -f2)
if [ -z "$KEY_HEX" ]; then
    echo "[!] ERROR: Failed to extract key from Rust output"
    exit 1
fi
echo "$KEY_HEX" > /tmp/key.hex
echo "[+] Generated key captured: ${KEY_HEX:0:16}...${KEY_HEX: -16}"
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

# Run Python analysis
echo "[*] Starting progressive pattern search..."
echo ""

python3 gdb/scripts/search_patterns_in_core_dump.py "$CORE_FILE" /tmp/key.hex
RESULT=$?

# Cleanup
rm -f /tmp/key.hex
rm -f "$CORE_FILE"

if [ $RESULT -eq 1 ]; then
    echo "[!] LEAK CONFIRMED: getrandom left key material in memory"
    exit 1
else
    echo "[+] Analysis complete - no leak detected"
    exit 0
fi
