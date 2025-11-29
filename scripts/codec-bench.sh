#!/bin/bash
# Codec benchmark script
# Usage:
#   ./scripts/codec-bench.sh          # Run without zeroize
#   ./scripts/codec-bench.sh zeroize  # Run with zeroize

FEATURES="benchmark"

if [ "$1" = "zeroize" ]; then
    FEATURES="benchmark,zeroize"
    echo "=== Running codec benchmark WITH zeroize ==="
else
    echo "=== Running codec benchmark WITHOUT zeroize ==="
fi

cargo test -p memcodec_core --features "$FEATURES" benchmark_codec_roundtrip --release -- --nocapture
