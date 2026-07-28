#!/usr/bin/env bash
# Runs Miri across the workspace.
#
# Miri interprets the Rust abstract machine and reports undefined behaviour that
# neither the compiler nor an ordinary test can see: out-of-bounds and dangling
# accesses, reads of uninitialised memory, invalid values, misaligned accesses,
# data races, allocator layout mismatches, and — through Stacked Borrows —
# aliasing violations that no other tool catches.
#
# What it CANNOT tell us, and the reason it does not replace the forensic lab:
# Miri runs on MIR, before LLVM. Every failure mode that involves the optimizer
# — a zeroization elided because nothing reads the buffer afterwards, a
# constant-time comparison rewritten to exit early — is invisible here. Miri
# checks that the `unsafe` is sound; only the lab checks the binary we ship.
#
# Usage:
#   ./scripts/miri.sh                 # every runnable crate
#   ./scripts/miri.sh redoubt-alloc   # just these
#   TIMEOUT=1800 ./scripts/miri.sh    # raise the per-crate limit
#
# ── Known interaction: serial_test ───────────────────────────────────────────
#
# `serial_test` reports as leaked memory under Miri. It keeps a process-global
# registry of reentrant mutexes, one per lock name, built with `to_owned()` and
# never freed — nine leaked allocations in `redoubt-buffer` alone, none of them
# ours, all of them reported as errors because Miri checks for live allocations
# at exit.
#
# The obvious fix is `-Zmiri-ignore-leaks`, and it is the wrong one. A leak is
# the one finding that matters most in the crate where it shows up:
# `redoubt-buffer` does raw `mmap`, so a leaked allocation there is a page that
# still holds secrets and was never unmapped. Silencing the check in exactly
# that crate trades a real signal for someone else's bookkeeping.
#
# What is done instead is `#[cfg_attr(not(miri), serial(...))]` on the affected
# tests, which drops `serial_test` from the Miri run entirely. That is sound
# rather than merely convenient: the attribute serializes contention over
# process-wide resources — `RLIMIT_MEMLOCK`, shared by the 21 page buffers
# those tests create, and the irreversible seccomp filters — and under Miri
# `mlock` is a no-op and the seccomp tests are ignored, because they need a
# subprocess. There is nothing left to serialize.
#
# Worth knowing regardless of Miri: `#[serial]` is already inert under
# `cargo nextest`, which runs one process per test, so each gets its own
# registry and its own `RLIMIT_MEMLOCK` budget. The attribute only does
# anything under `cargo test`.
#
# Any future crate that pulls in `serial_test` will need the same treatment.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

TOOLCHAIN="${TOOLCHAIN:-nightly}"
TIMEOUT="${TIMEOUT:-900}"

# Isolation has to be off for anything that reads OS entropy, the clock or the
# filesystem.
#
# `-Zmiri-strict-provenance` is deliberately NOT on by default. It rejects
# integer-to-pointer casts that discard an allocation's lineage, which is worth
# knowing about in our own code — but third-party dependencies do it routinely
# (`sdd` does, reached through `redoubt-buffer`), and a run that fails inside
# someone else's crate teaches nothing and trains you to ignore the output.
# Turn it on when auditing a specific crate of ours:
#
#   MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" ./scripts/miri.sh redoubt-alloc
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}"

# Crates Miri structurally cannot run. Not failures, and not something to fix —
# each is a deliberate escape from the abstract machine Miri implements.
declare -A SKIP=(
  [redoubt-aead-aegis-x86]="AEGIS in linked .S; Miri cannot execute FFI"
  [redoubt-aead-aegis-arm]="AEGIS in linked .S; Miri cannot execute FFI"
  [redoubt-aead-aegis-wycheproof]="drives AEGIS, which has no Rust fallback"
  [redoubt-hkdf-x86]="SHA-256 in linked .S; Miri cannot execute FFI"
  [redoubt-hkdf-arm]="SHA-256 in linked .S; Miri cannot execute FFI"
  [redoubt-forensics]="uses xsave64; inline asm is unsupported"
  [redoubt-guard]="prctl/setrlimit are not modelled"
  [benchmarks]="criterion; meaningless under interpretation"
  [wasm-example]="targets wasm"
)

# Two separate escapes from the abstract machine had to be closed for the facade
# to be checkable at all:
#
#   - AEGIS lives in linked .S. The feature detector reports no AES support
#     under cfg(miri), so `Aead::new()` selects XChaCha20-Poly1305 instead.
#   - XChaCha's quarter round dispatches to inline assembly by target_arch, not
#     by feature, so on x86_64 and aarch64 it was unreachable for Miri no matter
#     which features were set. Those cfgs now carry not(miri) and the pure-Rust
#     fallback takes over.
#
# No `--all-features`, ever: it would pull the `asm` paths back in.
FEATURES=""

if ! cargo "+${TOOLCHAIN}" miri --version >/dev/null 2>&1; then
  echo "[!] Miri is not installed for ${TOOLCHAIN}."
  echo "    rustup component add --toolchain ${TOOLCHAIN} miri"
  exit 1
fi

if [ $# -gt 0 ]; then
  CRATES=("$@")
else
  mapfile -t CRATES < <(
    cargo metadata --no-deps --format-version 1 2>/dev/null |
      python3 -c "import json,sys; [print(p['name']) for p in sorted(json.load(sys.stdin)['packages'], key=lambda x: x['name'])]"
  )
fi

PASS=(); FAIL=(); SKIPPED=(); TIMEDOUT=()
LOG_DIR=$(mktemp -d)
trap 'rm -rf "$LOG_DIR"' EXIT

echo "[*] Miri ${TOOLCHAIN}  |  MIRIFLAGS=${MIRIFLAGS}"
echo "[*] ${#CRATES[@]} crates, ${TIMEOUT}s each"
echo ""

for crate in "${CRATES[@]}"; do
  if [ -n "${SKIP[$crate]:-}" ]; then
    printf "  %-32s \033[90mskip\033[0m   %s\n" "$crate" "${SKIP[$crate]}"
    SKIPPED+=("$crate")
    continue
  fi

  printf "  %-32s " "$crate"
  log="${LOG_DIR}/${crate}.log"

  # `timeout` matters here. A test that is linear when compiled can be
  # quadratic under interpretation, and one of them ran for four hours before
  # anyone noticed it was not hung, just slow.
  if timeout "$TIMEOUT" cargo "+${TOOLCHAIN}" miri test -p "$crate" $FEATURES \
       > "$log" 2>&1; then
    n=$(grep -oP '\d+(?= passed)' "$log" | paste -sd+ | bc 2>/dev/null || echo "?")
    printf "\033[32mok\033[0m     %s tests\n" "${n:-?}"
    PASS+=("$crate")
  else
    rc=$?
    if [ $rc -eq 124 ]; then
      printf "\033[33mtimeout\033[0m after %ss\n" "$TIMEOUT"
      TIMEDOUT+=("$crate")
    else
      printf "\033[31mFAIL\033[0m\n"
      FAIL+=("$crate")
    fi
    cp "$log" "/tmp/miri-${crate}.log"
    sed -n '/^error/,/^$/p' "$log" | head -20 | sed 's/^/      /'
    echo "      full log: /tmp/miri-${crate}.log"
  fi
done

echo ""
echo "  ${#PASS[@]} ok   ${#FAIL[@]} failed   ${#TIMEDOUT[@]} timed out   ${#SKIPPED[@]} skipped"

if [ ${#TIMEDOUT[@]} -gt 0 ]; then
  echo ""
  echo "  Timed out: ${TIMEDOUT[*]}"
  echo "  A timeout is usually a test whose cost is quadratic in some SIZE"
  echo "  constant. Gate the constant on cfg(miri) with a small value rather"
  echo "  than raising TIMEOUT — the property under test rarely depends on it."
fi

[ ${#FAIL[@]} -eq 0 ] && [ ${#TIMEDOUT[@]} -eq 0 ]
