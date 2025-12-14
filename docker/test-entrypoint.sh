#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Test runner for Redoubt workspace
#
# Usage:
#   docker run redoubt-test                              # Run all tests
#   docker run redoubt-test -p redoubt-codec-core        # Run specific crate tests
#   docker run redoubt-test -p redoubt-codec-core test_name # Run specific test
#   docker run redoubt-test --lib                        # Run only lib tests
# -----------------------------------------------------------------------------

set -e

# Separate cargo args from test filter
cargo_args=()
test_filter=""
release_mode=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      release_mode="--release"
      ;;
    # Known cargo test flags
    -p|--package|--lib|--bin|--example|--test|--bench|--all-targets|--workspace|--exclude|--features|--all-features|--no-default-features)
      cargo_args+=("$1")
      # If flag takes a value, add it too
      if [[ "$1" == "-p" || "$1" == "--package" || "$1" == "--bin" || "$1" == "--example" || "$1" == "--test" || "$1" == "--bench" || "$1" == "--exclude" || "$1" == "--features" ]]; then
        shift
        cargo_args+=("$1")
      fi
      ;;
    --*)
      # Other flags go to cargo
      cargo_args+=("$1")
      ;;
    *)
      # First non-flag argument is the test filter
      test_filter="$1"
      break
      ;;
  esac
  shift
done

# Build cargo test command
if [[ -n "$test_filter" ]]; then
  cargo test --color always $release_mode "${cargo_args[@]}" "$test_filter" -- --nocapture
else
  cargo test --color always $release_mode "${cargo_args[@]}" -- --nocapture
fi
