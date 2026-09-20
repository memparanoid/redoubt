#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

# Coverage for the crates in `.cov_crates`, one crate's report at a time, from
# one instrumented build.
#
# # What keeps a crate's numbers its own
#
# The coverage map — which functions and regions exist — lives in the object
# file. The profile is only counts. So a report rendered over one crate's own
# objects cannot show another crate's code: it is not in the map being read,
# and an instantiation some other crate made lives in that other crate's
# binary.
#
# That is where the containment comes from here. It used to come from the
# compiler, by building the workspace once per crate with instrumentation
# stripped from everything else, which cost one full build per crate and — as
# `redoubt-util` showed, reading `0/0` branches against the 16 a plain run
# finds — quietly lost data.
#
# # The objects of a crate
#
# Its test binaries, which `nextest` names, and for a proc-macro its dylib,
# which nothing runs as a test: rustc loads it and runs it while the crates
# that derive are compiled, and for a derive crate that is most of what its
# code does.
#
# Usage:
#   ./scripts/coverage.sh                    # every crate in .cov_crates
#   ./scripts/coverage.sh -p redoubt-rand    # one of them, and open its page
#   ./scripts/coverage.sh --release          # optimized
#   ./scripts/coverage.sh --no-open          # leave the browser alone

set -euo pipefail

NIGHTLY="nightly-2025-10-15"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COV_CRATES_FILE="$REPO_ROOT/.cov_crates"
LLVM_BIN="$(rustc "+$NIGHTLY" --print target-libdir)/../bin"

# Where `insights.py` reads `report.html` from. Overridable so a run can be
# rendered elsewhere and left beside this one to be read against it.
OUT="${REDOUBT_COVERAGE_DIR:-$REPO_ROOT/coverage}"

# Test code, by the path segment it lives under rather than by the word: a
# crate called `redoubt-test-utils` is production and has no segment named
# `tests`, and `src/support/test_utils/` is production too — those mocks have
# tests of their own and are measured like anything else.
NOT_PRODUCTION='(^|/)tests?\.rs$|(^|/)tests/|(^|/)test_fixture/'

# Branch counters exist only where the build was told to emit them, and a
# report asked for branches without them reads `0 0 -` rather than failing.
export RUSTFLAGS="${RUSTFLAGS:-} -Zcoverage-options=branch"

ONLY=""
OPEN=true
PROFILE="debug"
PROFILE_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -p)
      ONLY="${2:-}"
      shift 2
      ;;
    --release)
      PROFILE="release"
      PROFILE_ARGS+=(--release)
      shift
      ;;
    --no-open)
      OPEN=false
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# One directory per profile, so a run of each can be compared without either
# rebuilding the graph to get its own artifacts back.
TARGET_DIR="$REPO_ROOT/target/coverage-$PROFILE"

mapfile -t LISTED < <(grep -vE '^[[:space:]]*(#|$)' "$COV_CRATES_FILE" | awk '{print $1}')

if [ -n "$ONLY" ]; then
  MEASURED=("$ONLY")
else
  MEASURED=("${LISTED[@]}")
fi

PACKAGE_ARGS=()
for crate in "${MEASURED[@]}"; do
  PACKAGE_ARGS+=(-p "$crate")
done

# The second column of `.cov_crates`, as `<package>/<feature>`: one build
# covers several packages at once, so a bare `--features` would be ambiguous
# about whose feature it is.
while read -r crate features; do
  [ -z "${features:-}" ] && continue

  printf '%s\n' "${MEASURED[@]}" | grep -qxF "$crate" || continue

  for feature in $features; do
    PACKAGE_ARGS+=(--features "$crate/$feature")
  done
done < <(grep -vE '^[[:space:]]*(#|$)' "$COV_CRATES_FILE")

export CARGO_TARGET_DIR="$TARGET_DIR"

echo "=== ${#MEASURED[@]} crates, one $PROFILE build ==="

mkdir -p "$TARGET_DIR" "$OUT"

# Every instrumented test binary from before, gone, and the `.rlib`s beside
# them kept.
#
# A report is rendered over the binaries in the target directory and the
# coverage map lives in the binary rather than in the profile data, so one left
# from an older build is still read, contributes every region it has and not one
# count, and drags the figure down. Deleting the `.profraw` does not touch it.
#
# The dependencies are correct however old they are, and keeping them is the
# difference between rebuilding the graph and relinking.
find "$TARGET_DIR" -type d -name deps -prune -exec \
  find {} -maxdepth 1 -type f -executable -delete \;

find "$TARGET_DIR" -name '*.profraw' -delete

# The environment `cargo llvm-cov` would set for itself, exported so that every
# cargo call below produces the same artifacts and writes its profiles where
# the report will look for them. Without it the listing call would be a second
# configuration and would rebuild the graph uninstrumented.
source <(cargo "+$NIGHTLY" llvm-cov show-env --export-prefix)

cargo "+$NIGHTLY" nextest run "${PROFILE_ARGS[@]}" "${PACKAGE_ARGS[@]}"

# Which binary belongs to which package, asked rather than guessed from the
# file names: several crates have a `tests/forensics.rs`, so their binaries are
# all called `forensics-<hash>` and the name does not say whose.
SUITES="$(cargo "+$NIGHTLY" nextest list --message-format json "${PROFILE_ARGS[@]}" "${PACKAGE_ARGS[@]}" 2>/dev/null)"

METADATA="$(cargo metadata --no-deps --format-version 1)"

DEPS_DIR="$(find "$TARGET_DIR" -type d -name deps -prune | head -1)"

MERGED="$TARGET_DIR/merged.profdata"

mapfile -t PROFRAW < <(find "$TARGET_DIR" -name '*.profraw')

echo
echo "=== ${#PROFRAW[@]} profraw, merged ==="

"$LLVM_BIN/llvm-profdata" merge -sparse -o "$MERGED" "${PROFRAW[@]}"

echo

for crate in "${MEASURED[@]}"; do
  mapfile -t OBJECTS < <(
    echo "$SUITES" | jq -r --arg crate "$crate" '
      ."rust-suites" | to_entries[]
      | select(.value["package-name"] == $crate)
      | .value["binary-path"]
    '
  )

  if echo "$METADATA" | jq -e --arg crate "$crate" '
    .packages[] | select(.name == $crate) | .targets[] | select(.kind[] == "proc-macro")
  ' >/dev/null; then
    mapfile -t -O "${#OBJECTS[@]}" OBJECTS < <(
      find "$DEPS_DIR" -maxdepth 1 -name "lib${crate//-/_}-*.so"
    )
  fi

  if [ "${#OBJECTS[@]}" -eq 0 ]; then
    echo "  $crate: no object"
    continue
  fi

  PACKAGE_DIR="$(
    echo "$METADATA" | jq -r --arg crate "$crate" '
      .packages[] | select(.name == $crate) | .manifest_path
    ' | xargs dirname
  )"

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

  rm -rf "${OUT:?}/$crate"

  # `<crate>/html/index.html` is where the renderer reads a crate's totals
  # from.
  "$LLVM_BIN/llvm-cov" show \
    --format=html \
    --show-branch-summary \
    "--output-dir=$OUT/$crate/html" \
    "--instr-profile=$MERGED" \
    "--ignore-filename-regex=$IGNORE" \
    "${OBJECT_ARGS[@]}" >/dev/null

  echo "  $crate"
done

# A crate that left `.cov_crates` leaves the report with it. Its page would
# otherwise stay on disk and go on being read into the totals, which is a
# number for something nobody measures any more.
for page in "$OUT"/*/; do
  name="$(basename "$page")"

  if ! printf '%s\n' "${LISTED[@]}" "${MEASURED[@]}" | grep -qxF "$name"; then
    echo "  $name: gone from .cov_crates, removed"
    rm -rf "$page"
  fi
done

echo

REDOUBT_COVERAGE_DIR="$OUT" "$REPO_ROOT/scripts/coverage_report.py" --no-open

if $OPEN; then
  if [ -n "$ONLY" ]; then
    xdg-open "$OUT/$ONLY/html/index.html" >/dev/null 2>&1 &
  else
    xdg-open "$OUT/index.html" >/dev/null 2>&1 &
  fi
fi
