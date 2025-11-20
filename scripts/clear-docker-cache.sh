#!/usr/bin/env bash
# Clear Docker cache for Memora project
#
# Usage:
#   ./scripts/clear-docker-cache.sh           # Interactive mode
#   ./scripts/clear-docker-cache.sh --all     # Clear everything
#   ./scripts/clear-docker-cache.sh --test    # Clear only test cache
#   ./scripts/clear-docker-cache.sh --coverage # Clear only coverage cache

set -euo pipefail

# Volume names
TEST_CARGO_CACHE="memora-cargo-cache"
TEST_TARGET_CACHE="memora-target-cache"
COVERAGE_TARGET_CACHE="memora-coverage-target-cache"

# Image names
TEST_IMAGE="memora-test"
COVERAGE_IMAGE="memora-coverage"

clear_test_cache() {
  echo "Removing test caches..."
  docker volume rm -f "$TEST_CARGO_CACHE" 2>/dev/null || echo "  - $TEST_CARGO_CACHE (not found)"
  docker volume rm -f "$TEST_TARGET_CACHE" 2>/dev/null || echo "  - $TEST_TARGET_CACHE (not found)"
  echo "Test caches cleared!"
}

clear_coverage_cache() {
  echo "Removing coverage caches..."
  docker volume rm -f "$COVERAGE_TARGET_CACHE" 2>/dev/null || echo "  - $COVERAGE_TARGET_CACHE (not found)"
  echo "Coverage caches cleared!"
}

clear_images() {
  echo "Removing Docker images..."
  docker rmi -f "$TEST_IMAGE" 2>/dev/null || echo "  - $TEST_IMAGE (not found)"
  docker rmi -f "$COVERAGE_IMAGE" 2>/dev/null || echo "  - $COVERAGE_IMAGE (not found)"
  echo "Docker images removed!"
}

clear_all() {
  echo "Clearing all Docker caches and images..."
  clear_test_cache
  clear_coverage_cache
  clear_images
  echo ""
  echo "All caches cleared!"
}

show_menu() {
  echo "Select what to clear:"
  echo "  1) Test cache only"
  echo "  2) Coverage cache only"
  echo "  3) Docker images only"
  echo "  4) Everything (caches + images)"
  echo "  5) Cancel"
  echo ""
  read -p "Choice [1-5]: " choice

  case $choice in
    1)
      clear_test_cache
      ;;
    2)
      clear_coverage_cache
      ;;
    3)
      clear_images
      ;;
    4)
      clear_all
      ;;
    5)
      echo "Cancelled."
      exit 0
      ;;
    *)
      echo "Invalid choice."
      exit 1
      ;;
  esac
}

# Parse arguments
if [[ $# -eq 0 ]]; then
  # Interactive mode
  show_menu
elif [[ "$1" == "--all" ]]; then
  clear_all
elif [[ "$1" == "--test" ]]; then
  clear_test_cache
elif [[ "$1" == "--coverage" ]]; then
  clear_coverage_cache
elif [[ "$1" == "--images" ]]; then
  clear_images
else
  echo "Usage: $0 [--all|--test|--coverage|--images]"
  exit 1
fi
