#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# One lab per C library, because the allocator is what differs and not the
# copy. A chunk freed under glibc keeps everything past its first few bytes;
# musl's `mallocng` may cover the lot. The same unzeroized buffer reads as a
# leak under one and as nothing under the other, so a clean report names which
# one it came from or it says nothing.
DOCKERFILE_MUSL="Dockerfile.musl"
DOCKERFILE_GLIBC="Dockerfile.glibc"

# Parse flags in any order: architecture, and which C library.
PLATFORM=""
DOCKERFILE="$DOCKERFILE_MUSL"
LIBC="musl"
IMAGE="redoubt-memory-analysis"

ARCH="$(uname -m)"

for arg in "$@"; do
    case "$arg" in
        --x86)
            PLATFORM="--platform linux/amd64"
            ARCH="x86_64"
            echo "[*] Forcing x86_64 architecture"
            ;;
        --arm)
            PLATFORM="--platform linux/arm64"
            ARCH="aarch64"
            echo "[*] Forcing ARM64 architecture"
            ;;
        --glibc)
            DOCKERFILE="$DOCKERFILE_GLIBC"
            LIBC="glibc"
            IMAGE="redoubt-memory-analysis-glibc"
            ;;
        --musl)
            DOCKERFILE="$DOCKERFILE_MUSL"
            LIBC="musl"
            IMAGE="redoubt-memory-analysis"
            ;;
        *)
            echo "[!] Unknown flag: $arg" >&2
            echo "    usage: run.sh [--x86|--arm] [--musl|--glibc]" >&2
            exit 1
            ;;
    esac
done

# Which C library, said loudly and at both ends. The same code reports a leak
# under one and nothing under the other, so a report read without knowing which
# one produced it says nothing at all — and these are usually read one after the
# other, scrolled back to.
banner() {
    echo ""
    echo "================================================================"
    echo "  REDOUBT MEMORY ANALYSIS — C LIBRARY: $(echo "$LIBC" | tr '[:lower:]' '[:upper:]')"
    echo "  $DOCKERFILE${PLATFORM:+  |  $PLATFORM}"
    echo "================================================================"
    echo ""
}

# One directory per combination, so that four runs are four readable things
# rather than the last one. Gitignored: what lands here is a report about this
# machine's C library and this run's addresses.
OUT="${PROJECT_ROOT}/forensics/memory_analysis/.output/${LIBC}-${ARCH}"

rm -rf "${OUT}"
mkdir -p "${OUT}/core_dumps"

REPORT="${OUT}/report.txt"
BUILD_LOG="${OUT}/build.log"

banner | tee "${REPORT}"

echo "[*] Host Architecture: $(uname -m)"
echo "[*] Output: ${OUT}"
echo ""

# The build says nothing about memory and is a thousand lines of cargo, so it
# goes to a file of its own. The report is the analysis and the banner that
# names which of the four runs it is — the whole of what there is to read.
echo "[*] Building the image, into ${BUILD_LOG}"

if ! docker build \
    $PLATFORM \
    -f "${PROJECT_ROOT}/forensics/memory_analysis/${DOCKERFILE}" \
    -t "${IMAGE}" \
    "${PROJECT_ROOT}" > "${BUILD_LOG}" 2>&1; then

    echo "[!] The image would not build. The last of ${BUILD_LOG}:" >&2
    echo "" >&2
    tail -40 "${BUILD_LOG}" >&2

    exit 1
fi

echo ""
echo "[*] Running forensic analysis..."
echo "[*] This will take ~60 seconds (test sleeps for memory scanning)"
echo ""

docker run --rm $PLATFORM -v "${OUT}/core_dumps:/workspace/core_dumps" "${IMAGE}" 2>&1 \
    | tee -a "${REPORT}"

banner | tee -a "${REPORT}"

echo "[+] Test complete"
echo "[*] Core dumps (if any) saved to: ${OUT}/core_dumps"
echo "[*] Report: ${REPORT}"
