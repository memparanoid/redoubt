#!/usr/bin/env bash
# Run tests with optional cross-architecture support
#
# Usage:
#   ./scripts/test.sh [ARCH] [cargo test args...] [--no-cache]
#
# ARCH (optional):
#   x86      - x86_64/amd64 architecture
#   arm      - ARM64/AArch64 architecture
#   s390x    - s390x Big Endian architecture
#   riscv64  - RISC-V 64-bit architecture
#   (empty)  - Use native architecture (default)
#
# Flags:
#   --no-cache  - Disable Docker layer caching (force rebuild, must be last arg)
#
# Examples:
#   ./scripts/test.sh                                      # Native arch, all tests
#   ./scripts/test.sh -p redoubt-aead                      # Native arch, specific crate
#   ./scripts/test.sh x86 -p redoubt-aead                  # x86_64, specific crate
#   ./scripts/test.sh arm -p redoubt-codec --features test_utils
#   ./scripts/test.sh s390x -p redoubt-util                # Big-endian testing
#   ./scripts/test.sh x86 -p redoubt-aead --no-cache       # Force rebuild, no cache

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Supported architectures
SUPPORTED_ARCHS=("x86" "arm" "s390x" "riscv64")

# Detect native architecture
detect_native_arch() {
    local machine=$(uname -m)
    case "$machine" in
        x86_64|amd64)
            echo "x86"
            ;;
        aarch64|arm64)
            echo "arm"
            ;;
        s390x)
            echo "s390x"
            ;;
        riscv64)
            echo "riscv64"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Map architecture names to Docker platform names
arch_to_platform() {
    case "$1" in
        x86)
            echo "linux/amd64"
            ;;
        arm)
            echo "linux/arm64"
            ;;
        s390x)
            echo "linux/s390x"
            ;;
        riscv64)
            echo "linux/riscv64"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Show supported architectures and exit
show_archs_and_exit() {
    echo "Error: Invalid architecture '$1'"
    echo ""
    echo "Supported architectures:"
    for arch in "${SUPPORTED_ARCHS[@]}"; do
        echo "  - $arch"
    done
    exit 1
}

# Parse arguments
TARGET_ARCH=""
CARGO_ARGS=()
NO_CACHE=""

# Check if first argument is an architecture
if [[ $# -gt 0 ]]; then
    FIRST_ARG="$1"

    # Check if it's a known architecture
    if [[ " ${SUPPORTED_ARCHS[@]} " =~ " ${FIRST_ARG} " ]]; then
        TARGET_ARCH="$FIRST_ARG"
        shift
    elif [[ "$FIRST_ARG" =~ ^- ]]; then
        # First arg is a flag, use native arch
        TARGET_ARCH=""
    else
        # First arg is not a flag and not a known arch
        # Could be invalid arch or test filter
        # If it looks like it could be an arch name (no special chars), show error
        if [[ "$FIRST_ARG" =~ ^[a-zA-Z0-9]+$ ]]; then
            show_archs_and_exit "$FIRST_ARG"
        fi
        # Otherwise, treat as test filter (use native arch)
        TARGET_ARCH=""
    fi
fi

# Check for --no-cache at the end of arguments
if [[ "${@: -1}" == "--no-cache" ]]; then
    NO_CACHE="--no-cache"
    set -- "${@:1:$(($#-1))}"  # Remove last argument
fi

# Collect remaining args for cargo
CARGO_ARGS=("$@")

# Determine target architecture
if [[ -z "$TARGET_ARCH" ]]; then
    TARGET_ARCH=$(detect_native_arch)
    if [[ "$TARGET_ARCH" == "unknown" ]]; then
        echo "Error: Unable to detect native architecture"
        exit 1
    fi
    echo "Using native architecture: $TARGET_ARCH"
else
    echo "Using target architecture: $TARGET_ARCH"
fi

# Get Docker platform
PLATFORM=$(arch_to_platform "$TARGET_ARCH")
if [[ -z "$PLATFORM" ]]; then
    show_archs_and_exit "$TARGET_ARCH"
fi

# Determine which Dockerfile to use
NATIVE_ARCH=$(detect_native_arch)
if [[ "$TARGET_ARCH" == "$NATIVE_ARCH" ]]; then
    # Native build: use Dockerfile.test with full capabilities
    echo "Building test Docker image (native with capabilities)..."
    DOCKER_BUILDKIT=1 docker build \
        $NO_CACHE \
        -f "$PROJECT_ROOT/docker/Dockerfile.test" \
        -t redoubt-test \
        "$PROJECT_ROOT"

    echo "Running tests with capabilities (mprotect, madvise, prctl)..."
    docker run --rm \
        --cap-add=SYS_RESOURCE \
        --cap-add=SYS_ADMIN \
        --ulimit memlock=67108864:67108864 \
        -v redoubt-cargo-cache:/usr/local/cargo/registry \
        -v redoubt-target-cache:/workspace/target \
        redoubt-test "${CARGO_ARGS[@]}"
else
    # Cross-architecture build: use Dockerfile.arch-test (no capabilities)
    echo "Building cross-architecture test image for $TARGET_ARCH..."
    DOCKER_BUILDKIT=1 docker build \
        $NO_CACHE \
        --platform "$PLATFORM" \
        -f "$PROJECT_ROOT/docker/Dockerfile.arch-test" \
        -t "redoubt-test-$TARGET_ARCH" \
        "$PROJECT_ROOT"

    echo "Running cross-architecture tests on $TARGET_ARCH..."

    # If user provided custom args, override the default CMD
    if [[ ${#CARGO_ARGS[@]} -gt 0 ]]; then
        docker run --rm \
            --platform "$PLATFORM" \
            -v "redoubt-cargo-cache-$TARGET_ARCH:/usr/local/cargo/registry" \
            -v "redoubt-target-cache-$TARGET_ARCH:/workspace/target" \
            "redoubt-test-$TARGET_ARCH" \
            cargo test "${CARGO_ARGS[@]}" -- --nocapture
    else
        # Use default CMD from Dockerfile
        docker run --rm \
            --platform "$PLATFORM" \
            -v "redoubt-cargo-cache-$TARGET_ARCH:/usr/local/cargo/registry" \
            -v "redoubt-target-cache-$TARGET_ARCH:/workspace/target" \
            "redoubt-test-$TARGET_ARCH"
    fi
fi
