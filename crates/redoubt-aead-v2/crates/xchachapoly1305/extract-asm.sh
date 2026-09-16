#!/usr/bin/env bash
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.
#
# The assembly of every function of this crate, one file each, on both
# architectures, the same bytes every time it is run.
#
# # What this is for
#
# The cipher and the authenticator are audited by reading their `.S` files.
# This crate has none: it is Rust, and what it compiles to is decided by the
# compiler. Auditing it means reading what the compiler decided, and reading
# it twice means the two readings have to be of the same text — so the output
# here carries no addresses, no symbol hashes and no file names that change
# between builds.
#
# # What is deterministic, and what it rests on
#
# The compiler is asked for its own assembly (`--emit=asm`) rather than the
# object being disassembled, which is what removes the addresses. One codegen
# unit, no debug information, and `RUSTFLAGS` emptied, so that nothing in the
# environment — a `target-cpu=native` above all — changes the code under the
# reader. Every symbol is demangled and the crate disambiguator stripped, so
# the text is the same across a rebuild that only moved a hash.
#
# What it does not survive is a different compiler or a different dependency:
# those change the code, and the text changing is the point.
#
# # What is not here
#
# A function the compiler inlined has no symbol and no file. The manifest
# says which of the functions in the source are missing for that reason, so
# an absence is read as an absence and not as a file somebody forgot.
#
# And this is the crate's own assembly, before link-time optimisation. What
# LTO inlines across crates into a consumer's binary is that binary's to
# audit.
#
# # Targets
#
# `x86_64-unknown-linux-gnu`, and `aarch64-unknown-linux-musl` through the
# cross compiler this machine has, which the dependencies' `.S` files need.
# `CROSS_CC` names it if it goes by another name.
#
# # Usage
#
#     ./extract-asm.sh             writes .output/asm/<target>/*.s and MANIFEST
#     ./extract-asm.sh --verify    extracts twice and fails if the two differ

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"

CRATE="redoubt-aead-xchachapoly1305"
LIB="redoubt_aead_xchachapoly1305"
SOURCE="$HERE/src/xchachapoly1305.rs"

# What a function has to be called to be kept: the type, which every method
# and trait impl of it names.
FILTER="XChaCha20Poly1305"

TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-musl)

CROSS_CC="${CROSS_CC:-aarch64-unknown-linux-musl-gcc}"

OUT="${OUT:-$ROOT/.output/asm}"

for needed in cargo c++filt awk sha256sum "$CROSS_CC"; do
  command -v "$needed" >/dev/null || {
    echo "missing: $needed" >&2
    exit 1
  }
done

# Flags handed to rustc for this crate alone; dependencies build as the
# profile says. Written down once so the header of every file can quote them.
RUSTC_FLAGS=(--emit=asm -C codegen-units=1 -C debuginfo=0 -C symbol-mangling-version=v0)

emit() { # emit <target> -> path of the .s
  local target="$1"
  local deps="$OUT/target/$target/release/deps"

  # This crate alone is rebuilt every time, so the file is this run's and not
  # one an earlier run left. A crate cargo finds fresh is not compiled, and
  # the assembly is a by-product it does not track: deleted, it stays gone.
  cargo clean -p "$CRATE" --release --target "$target" --target-dir "$OUT/target" --quiet

  env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo rustc -p "$CRATE" --lib --release --target "$target" \
    --target-dir "$OUT/target" --quiet -- "${RUSTC_FLAGS[@]}"

  find "$deps" -maxdepth 1 -name "$LIB-*.s" | head -1
}

# The demangled name, its crate disambiguators gone. `c++filt` reads v0
# mangling since binutils 2.36.
demangle() {
  c++filt | sed -E 's/\[[0-9a-f]{16}\]//g'
}

# A file name out of a demangled path: module paths dropped, the rest reduced
# to what a file system takes.
#
#   <a::b::XChaCha20Poly1305 as c::d::AeadEncrypt>::encrypt
#   -> XChaCha20Poly1305_as_AeadEncrypt__encrypt
name_of() {
  sed -E 's/([a-z0-9_]+::)+//g' |
    sed -E 's/::/__/g; s/[<>]//g; s/[^A-Za-z0-9_]+/_/g; s/^_+//; s/_+$//'
}

# The functions the source declares, so the manifest can say which of them
# the compiler folded into another.
declared() {
  grep -oE '^\s*(pub(\(crate\))? )?fn [a-z_0-9]+' "$SOURCE" | awk '{print $NF}' | sort -u
}

extract() { # extract <target> <dir>
  local target="$1"
  local dir="$2"
  local asm

  asm="$(emit "$target")"
  [ -n "$asm" ] || {
    echo "no assembly emitted for $target" >&2
    exit 1
  }

  rm -rf "$dir"
  mkdir -p "$dir"

  local rustc_version
  rustc_version="$(rustc --version)"

  # Every function in the file, mangled name and text, from `.type` to
  # `.size`. Each goes to a temporary file named after its position so the
  # manifest below can read them back in the compiler's order.
  local chunks
  chunks="$(mktemp -d)"

  awk -v dir="$chunks" '
    /^\s*\.type\s+[^,]+,\s*[@%]function/ {
      sym = $2; sub(/,.*/, "", sym)
      n++
      file = sprintf("%s/%04d", dir, n)
      print sym > (file ".sym")
      keep = 1
    }
    keep { print > file }
    keep && $1 == ".size" && index($2, sym ",") == 1 { keep = 0; close(file); close(file ".sym") }
  ' "$asm"

  local found=()

  for chunk in "$chunks"/*[0-9]; do
    local mangled demangled name
    mangled="$(cat "$chunk.sym")"
    demangled="$(printf '%s\n' "$mangled" | demangle)"

    case "$demangled" in
      *"$FILTER"*) ;;
      *) continue ;;
    esac

    name="$(printf '%s\n' "$demangled" | name_of)"
    found+=("$demangled")

    {
      printf '# %s\n' "$demangled"
      printf '# %s, %s\n' "$target" "$rustc_version"
      printf '# rustc %s\n\n' "${RUSTC_FLAGS[*]}"
      # The whole text through the demangler, so a call into another crate
      # reads as a name and not as a hash.
      demangle <"$chunk"
    } >"$dir/$name.s"
  done

  rm -rf "$chunks"

  {
    printf '# %s on %s\n# %s\n\n' "$CRATE" "$target" "$rustc_version"
    printf '## Functions, one file each\n\n'
    for each in "${found[@]}"; do
      printf '%s\n    %s.s\n' "$each" "$(printf '%s\n' "$each" | name_of)"
    done

    printf '\n## Declared in the source and without a file: inlined, or behind cfg(test)\n\n'
    for fn in $(declared); do
      local seen=0
      for each in "${found[@]}"; do
        case "$each" in *"::$fn") seen=1 ;; esac
      done
      [ "$seen" -eq 1 ] || printf '%s\n' "$fn"
    done

    printf '\n## Fingerprint\n\n'
    (cd "$dir" && find . -name '*.s' | sort | xargs sha256sum)
  } >"$dir/MANIFEST"

  printf '%s: %d functions -> %s\n' "$target" "${#found[@]}" "$dir"
}

fingerprint() { # fingerprint <dir>
  (cd "$1" && find . -name '*.s' | sort | xargs cat | sha256sum | cut -d' ' -f1)
}

verify=0
[ "${1:-}" = "--verify" ] && verify=1

for target in "${TARGETS[@]}"; do
  extract "$target" "$OUT/$target"

  if [ "$verify" -eq 1 ]; then
    first="$(fingerprint "$OUT/$target")"
    extract "$target" "$OUT/$target.again"
    second="$(fingerprint "$OUT/$target.again")"

    if [ "$first" != "$second" ]; then
      echo "$target: two extractions differ" >&2
      diff -r "$OUT/$target" "$OUT/$target.again" >&2 || true
      exit 1
    fi

    rm -rf "$OUT/$target.again"
    echo "$target: the same text twice, $first"
  fi
done
