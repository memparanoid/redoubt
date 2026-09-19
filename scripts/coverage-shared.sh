#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

# Coverage for every crate in `.cov_crates`, from one build and one run.
#
# The containment comes from which objects a report is rendered over, not from
# stripping instrumentation per crate: a crate's report is rendered over its own
# test binaries, so a monomorphization that another crate instantiated is not in
# the coverage map being read and its counts cannot arrive. Measured on the
# canary — `test-a` reads the same 58.82% here as it does from a contained
# build of its own.
#
# What that buys is the whole cost: one instrumented build of the workspace
# instead of one per crate, and one parallel `nextest` instead of one run per
# crate.
#
# Usage:
#   ./scripts/coverage-shared.sh                        # every crate in .cov_crates
#   ./scripts/coverage-shared.sh redoubt-rand           # one of them
#   ./scripts/coverage-shared.sh --release              # optimized
#
# `--release` is a question, not a setting. Optimization moves what region a
# count is attributed to — an inlined body is counted where it was inlined —
# so the numbers it gives are only usable if they match the ones the dev
# profile gives, and that is what a run of each is for.

set -euo pipefail

NIGHTLY="nightly-2025-10-15"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COV_CRATES_FILE="$REPO_ROOT/.cov_crates"
TARGET_DIR="$REPO_ROOT/target/coverage-shared"
LLVM_BIN="$(rustc "+$NIGHTLY" --print target-libdir)/../bin"

# Test code, by the path segment it lives under rather than by the word: a crate
# called `redoubt-test-utils` is production and has no segment named `tests`,
# and `src/support/test_utils/` is production too — those mocks have tests of
# their own and are measured like anything else.
NOT_PRODUCTION='(^|/)tests?\.rs$|(^|/)tests/|(^|/)test_fixture/'

# Branch counters exist only where the build was told to emit them, and a
# report asked for branches without them reads `0 0 -` rather than failing —
# which is a whole column of a table saying nothing and looking like a result.
export RUSTFLAGS="${RUSTFLAGS:-} -Zcoverage-options=branch"

ONLY=""
PROFILE="debug"
PROFILE_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --release)
      PROFILE="release"
      PROFILE_ARGS+=(--release)
      ;;
    *) ONLY="$arg" ;;
  esac
done

# One directory per profile, so a run of each can be compared against the other
# without either rebuilding the whole graph to get its own artifacts back.
TARGET_DIR="$TARGET_DIR-$PROFILE"

mapfile -t CRATES < <(grep -vE '^[[:space:]]*(#|$)' "$COV_CRATES_FILE" | awk '{print $1}')

if [ -n "$ONLY" ]; then
  CRATES=("$ONLY")
fi

PACKAGE_ARGS=()
for crate in "${CRATES[@]}"; do
  PACKAGE_ARGS+=(-p "$crate")
done

export CARGO_TARGET_DIR="$TARGET_DIR"

echo "=== ${#CRATES[@]} crates, one $PROFILE build ==="

# Every instrumented test binary from before, gone, and the `.rlib`s beside
# them kept.
#
# A report is rendered over the binaries found in the target directory and the
# coverage map lives in the binary rather than in the profile data, so one left
# from an older build is still read, contributes every region it has and not one
# count, and drags the figure down. Deleting the `.profraw` does not touch it.
#
# The dependencies are correct however old they are, and keeping them is the
# difference between rebuilding the graph and relinking.
mkdir -p "$TARGET_DIR"

find "$TARGET_DIR" -type d -name deps -prune -exec \
  find {} -maxdepth 1 -type f -executable -delete \;

find "$TARGET_DIR" -name '*.profraw' -delete

# The environment `cargo llvm-cov` would set for itself, exported so that every
# cargo call below produces the same artifacts and writes its profiles where the
# report will look for them. Without it the listing call below would be a second
# configuration and would rebuild the graph uninstrumented.
source <(cargo "+$NIGHTLY" llvm-cov show-env --export-prefix)

cargo "+$NIGHTLY" nextest run "${PROFILE_ARGS[@]}" "${PACKAGE_ARGS[@]}"

# Which binary belongs to which package, asked rather than guessed from the
# file names: several crates have a `tests/forensics.rs`, so their binaries are
# all called `forensics-<hash>` and the name does not say whose.
SUITES="$(cargo "+$NIGHTLY" nextest list --message-format json "${PROFILE_ARGS[@]}" "${PACKAGE_ARGS[@]}" 2>/dev/null)"

METADATA="$(cargo metadata --no-deps --format-version 1)"

# Beside the tree's own `coverage/` rather than in it, so that a run from here
# and a run from `coverage.py` can be read against each other.
OUT="${TMPDIR:-/tmp}/redoubt-coverage"

rm -rf "$OUT"
mkdir -p "$OUT"

DEPS_DIR="$(find "$TARGET_DIR" -type d -name deps -prune | head -1)"

MERGED="$TARGET_DIR/merged.profdata"

mapfile -t PROFRAW < <(find "$TARGET_DIR" -name '*.profraw')

echo
echo "=== ${#PROFRAW[@]} profraw, merged ==="

"$LLVM_BIN/llvm-profdata" merge -sparse -o "$MERGED" "${PROFRAW[@]}"

for crate in "${CRATES[@]}"; do
  mapfile -t OBJECTS < <(
    echo "$SUITES" | jq -r --arg crate "$crate" '
      ."rust-suites" | to_entries[]
      | select(.value["package-name"] == $crate)
      | .value["binary-path"]
    '
  )

  # A proc-macro's own dylib, which `nextest` does not list because nothing
  # runs it as a test.
  #
  # It is loaded and run by rustc while the crates that derive are compiled, so
  # with the profile file exported for the build that execution is measured —
  # and for a derive crate it is most of what its code does. Rendered over the
  # test binary alone, `redoubt-vault-derive` reads 79.17% of its functions
  # against 100.00% with this.
  if echo "$METADATA" | jq -e --arg crate "$crate" '
    .packages[] | select(.name == $crate) | .targets[] | select(.kind[] == "proc-macro")
  ' >/dev/null; then
    mapfile -t -O "${#OBJECTS[@]}" OBJECTS < <(
      find "$DEPS_DIR" -maxdepth 1 -name "lib${crate//-/_}-*.so"
    )
  fi

  if [ "${#OBJECTS[@]}" -eq 0 ]; then
    echo
    echo "=== $crate: no object ==="
    continue
  fi


  PACKAGE_DIR="$(
    echo "$METADATA" | jq -r --arg crate "$crate" '
      .packages[] | select(.name == $crate) | .manifest_path
    ' | xargs dirname
  )"
  SOURCE_DIR="$PACKAGE_DIR/src"

  # Every other package's files, out. A test binary statically carries every
  # instrumented crate it links, so without this a crate's report is the whole
  # workspace seen from that binary — and a crate that holds others, like
  # `redoubt-zero` with `core/` and `derive/` under it, reports theirs as its
  # own.
  #
  # A package this one sits inside keeps only its own `src/` excluded, or the
  # exclusion would take this package's files with it.
  OTHERS="$(
    echo "$METADATA" | jq -r --arg dir "$PACKAGE_DIR" '
      .packages[].manifest_path
      | rtrimstr("/Cargo.toml")
      | select(. != $dir)
      | . as $other
      | if ($dir | startswith($other + "/"))
        then "|^" + $other + "/src/"
        else "|^" + $other + "/"
        end
    ' | tr -d '\n'
  )"

  IGNORE="$NOT_PRODUCTION$OTHERS|/\\.cargo/registry/|/rustc/"

  # The first object is positional and every one after it needs `-object`,
  # which is what `llvm-cov` takes rather than a list.
  OBJECT_ARGS=("${OBJECTS[0]}")

  for ((at = 1; at < ${#OBJECTS[@]}; at++)); do
    OBJECT_ARGS+=(-object "${OBJECTS[$at]}")
  done

  # `<crate>/html/index.html` is where `coverage.py` reads a crate's totals
  # from, so the page it renders over these is the page it always renders.
  "$LLVM_BIN/llvm-cov" show \
    --format=html \
    --show-branch-summary \
    "--output-dir=$OUT/$crate/html" \
    "--instr-profile=$MERGED" \
    "--ignore-filename-regex=$IGNORE" \
    "${OBJECT_ARGS[@]}" \
    "$SOURCE_DIR" >/dev/null

  echo "  $crate"
done

echo

REDOUBT_COVERAGE_DIR="$OUT" "$REPO_ROOT/scripts/coverage.py" --report-only
