#!/usr/bin/env bash
# Audits the zeroize-on-drop surface, then runs the tests that defend it.
#
# Three things go wrong quietly with `#[fast_zeroize(drop)]` and
# `__sentinel: ZeroizeOnDropSentinel`, and none of them fail a build:
#
#   1. A struct carries the sentinel but nothing wires it to `Drop`. The
#      sentinel is a declaration of intent — "this must be wiped when it dies" —
#      and without the wiring, reassigning a field of such a type frees the old
#      value intact. That is how 150,528 bytes of plaintext went unnoticed
#      until a forensic run found them.
#
#   2. A struct carries the attribute but not the sentinel. It wipes on drop,
#      but leaves no witness, so no test can prove it kept doing so.
#
#   3. Either is present and nobody wrote the tests. The mechanism exists, is
#      never invoked, and reports nothing.
#
# The wiring can be either `#[fast_zeroize(drop)]` (derive) or a hand-written
# `impl Drop` — the guards in redoubt-zero-core implement everything manually
# because the derive lives one crate above them and cannot exist there yet.
# Both count as wired; the audit only flags a sentinel with NEITHER.
#
# ── Known exceptions (deliberate, documented at the definition site) ─────────
#
#   ZeroizeOnDropSentinel   must NEVER be wired to Drop. A sentinel that
#                           zeroized itself on drop would report success for
#                           every struct, including the ones that wipe nothing.
#                           Its own test asserts exactly that.
#
#   CipherBox               `zeroizes_on_drop` only, no `is_zeroizable` test.
#                           At rest it holds ciphertext, nonces and tags;
#                           zeroizing a live box is not a real operation — it
#                           just poisons decryption. The tmp plaintext buffers
#                           are asserted per-operation instead.
#
# ── Naming ───────────────────────────────────────────────────────────────────
#
# Two tests per type:
#
#     test_<type>_is_zeroizable        unzeroized value reports NOT zeroized,
#                                      fast_zeroize() flips that
#     test_<type>_zeroizes_on_drop     dropping it marks the sentinel
#
# There is no 1:1 mapping from StructName to test_name — the conversion is not
# mechanical. Matching therefore tries several candidates per type, normalized
# to lowercase with underscores removed:
#
#   - the type name itself         RedoubtString  -> redoubtstring
#   - without the Redoubt prefix   RedoubtCodecBuffer -> codecbuffer
#   - explicit aliases             XChacha20Poly1305  -> aead
#
# Anything between the candidate and the suffix is allowed, because several
# types are generic and one test per instantiation is legitimate —
# `test_chacha20_ietf_is_zeroizable` and `test_chacha20_bernstein_...` both
# count for `ChaCha20`. Each test is assigned to the LONGEST matching
# candidate, so `Poly1305` cannot claim `Poly1305Block`'s tests.
#
# Usage:
#   ./scripts/zeroizing.sh              # audit and run
#   ./scripts/zeroizing.sh --audit      # audit only, no cargo
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

AUDIT_ONLY=false
[ "${1:-}" = "--audit" ] && AUDIT_ONLY=true

INVENTORY=$(mktemp)
LISTS=$(mktemp -d)
trap 'rm -f "$INVENTORY"; rm -rf "$LISTS"' EXIT

# ── 1. Inventory ─────────────────────────────────────────────────────────────
#
# Emits one TSV line per type:
#   name, crate, file, line, has_sentinel, has_attr_drop, has_manual_drop
python3 - "$INVENTORY" <<'PY'
import re, sys, glob, os

def package_of(path):
    """Walks up to the nearest Cargo.toml and reads its package name."""
    d = os.path.dirname(os.path.abspath(path))
    while d != "/":
        manifest = os.path.join(d, "Cargo.toml")
        if os.path.exists(manifest):
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', open(manifest).read(), re.M)
            if m:
                return m.group(1)
        d = os.path.dirname(d)
    return "?"

DECL = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+(\w+)')
MANUAL_DROP = re.compile(r'impl(?:<[^>]*>)?\s+Drop\s+for\s+(\w+)')
rows, manual_drops = [], set()

sources = [p for p in glob.glob("crates/**/*.rs", recursive=True)
           if not any(s in p for s in ("/tests/", "/support/", "test_utils", "/target/"))]

for path in sources:
    text = open(path).read()
    manual_drops.update(MANUAL_DROP.findall(text))

for path in sources:
    lines = open(path).read().split('\n')
    for i, line in enumerate(lines):
        m = DECL.match(line)
        if not m:
            continue
        name = m.group(1)

        # Attribute block directly above the declaration.
        attrs, j = [], i - 1
        while j >= 0:
            s = lines[j].lstrip()
            if s.startswith('#['):
                attrs.append(s)
            elif not (s.startswith('///') or s.startswith('//') or s == ''):
                break
            elif s == '' and attrs:
                break
            j -= 1

        # Body, up to the closing brace.
        body = '\n'.join(lines[i:i + 80])
        end = body.find('\n}')
        if end > 0:
            body = body[:end]

        has_attr = any('fast_zeroize' in a and 'drop' in a for a in attrs)
        has_sent = '__sentinel' in body and 'ZeroizeOnDropSentinel' in body

        if has_sent or has_attr:
            rows.append((name, package_of(path), path.replace('crates/', ''),
                         i + 1, has_sent, has_attr, name in manual_drops))

with open(sys.argv[1], 'w') as f:
    for name, pkg, path, ln, sent, attr, manual in sorted(rows):
        f.write(f"{name}\t{pkg}\t{path}\t{ln}\t{int(sent)}\t{int(attr)}\t{int(manual)}\n")
PY

# ZeroizeOnDropSentinel is the mechanism itself, not a client of it.
SENTINEL_TYPE="ZeroizeOnDropSentinel"

WIRED=$(awk -F'\t' -v s="$SENTINEL_TYPE" '$1!=s && $5==1 && ($6==1 || $7==1)' "$INVENTORY" | wc -l)
GAPS=$(awk -F'\t' -v s="$SENTINEL_TYPE" '$1!=s && $5==1 && $6==0 && $7==0' "$INVENTORY" | wc -l)
NO_WITNESS=$(awk -F'\t' '$5==0 && $6==1' "$INVENTORY" | wc -l)

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ ZEROIZATION SURFACE                                                        ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
printf "  %-52s %3s\n" "sentinel + wired (attribute or manual Drop)" "$WIRED"
printf "  %-52s %3s\n" "sentinel, NOT wired — GAP" "$GAPS"
printf "  %-52s %3s\n" "wired, NO sentinel — untestable by construction" "$NO_WITNESS"
echo ""

if [ "$GAPS" -gt 0 ]; then
    echo "  ── sentinel without any Drop wiring ────────────────────────────────"
    echo "     Declares the intent, nothing wires it to Drop. Replacing a field"
    echo "     of one of these frees the old value intact."
    awk -F'\t' -v s="$SENTINEL_TYPE" '$1!=s && $5==1 && $6==0 && $7==0 \
        {printf "       %-24s %-46s :%s\n", $1, $3, $4}' "$INVENTORY"
    echo ""
fi

if [ "$NO_WITNESS" -gt 0 ]; then
    echo "  ── wired without sentinel ──────────────────────────────────────────"
    echo "     Wipes on drop, but leaves no witness — untestable by construction."
    awk -F'\t' '$5==0 && $6==1 {printf "       %-24s %-46s :%s\n", $1, $3, $4}' "$INVENTORY"
    echo ""
fi

$AUDIT_ONLY && exit $(( GAPS > 0 || NO_WITNESS > 0 ? 1 : 0 ))

# ── 2. Test discovery ────────────────────────────────────────────────────────
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ TESTS                                                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

CRATES=$(cut -f2 "$INVENTORY" | sort -u)
for crate in $CRATES; do
    cargo test -q -p "$crate" -- --list 2>/dev/null \
        | sed 's/: test$//' > "$LISTS/$crate" || true
done

MISSING=$(python3 - "$INVENTORY" "$LISTS" <<'PY'
import re, sys, os

SENTINEL_TYPE = "ZeroizeOnDropSentinel"

# No is_zeroizable for CipherBox: at rest it holds only ciphertext, and
# zeroizing a live box is not a real operation (see tests/cipherbox.rs).
SKIP_IS_ZEROIZABLE = {"CipherBox"}

# No mechanical StructName -> test_name mapping exists; these are the cases
# normalization cannot reach.
ALIASES = {"XChacha20Poly1305": {"aead"}}

def norm(s):
    return re.sub(r'[^0-9a-z]', '', s.lower())

def candidates(name):
    base = norm(name)
    out = {base}
    if base.startswith("redoubt") and len(base) > len("redoubt"):
        out.add(base[len("redoubt"):])
    out |= {norm(a) for a in ALIASES.get(name, ())}
    return out

inventory = []
for line in open(sys.argv[1]):
    name, pkg, path, ln, sent, attr, manual = line.rstrip('\n').split('\t')
    if name == SENTINEL_TYPE:
        continue
    inventory.append((name, pkg))

SUFFIXES = ("is_zeroizable", "zeroizes_on_drop")
counts = {(name, sfx): 0 for name, _ in inventory for sfx in SUFFIXES}

tests_by_crate = {}
for _, pkg in inventory:
    path = os.path.join(sys.argv[2], pkg)
    if pkg not in tests_by_crate and os.path.exists(path):
        tests_by_crate[pkg] = [t.strip().split('::')[-1] for t in open(path)]

for name, pkg in inventory:
    for t in tests_by_crate.get(pkg, ()):
        if not t.startswith("test_"):
            continue
        for sfx in SUFFIXES:
            if not t.endswith("_" + sfx):
                continue
            middle = norm(t[len("test_"):-(len(sfx) + 1)])
            # Longest-match: the test belongs to the type with the longest
            # matching candidate among ALL types in this crate.
            best, best_len = None, -1
            for other, opkg in inventory:
                if opkg != pkg:
                    continue
                for cand in candidates(other):
                    if middle.startswith(cand) and len(cand) > best_len:
                        best, best_len = other, len(cand)
            if best == name:
                counts[(name, sfx)] += 1

missing = 0
GREEN, RED, DIM, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
for name, pkg in inventory:
    cells = []
    for sfx in SUFFIXES:
        if sfx == "is_zeroizable" and name in SKIP_IS_ZEROIZABLE:
            cells.append(f"{DIM}skip{OFF}")
            continue
        n = counts[(name, sfx)]
        if n:
            cells.append(f"{GREEN}{n:>2} ✔{OFF}")
        else:
            cells.append(f"{RED} ✘  {OFF}")
            missing += 1
    print(f"  {name:<24} {pkg:<22} is_zeroizable {cells[0]}   zeroizes_on_drop {cells[1]}",
          file=sys.stderr)

print(missing)
PY
)

echo ""

# ── 3. Run them ──────────────────────────────────────────────────────────────
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ RUN                                                                        ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

FAILED=0
for crate in $CRATES; do
    printf "  %-24s " "$crate"
    out=$(cargo test -q -p "$crate" -- is_zeroizable zeroizes_on_drop 2>&1)
    if echo "$out" | grep -q "test result: FAILED\|error\["; then
        printf "\033[31mFAIL\033[0m\n"
        echo "$out" | grep -E "^(---- |test .* FAILED|assertion|  left|  right)" | head -8 | sed 's/^/      /'
        FAILED=$((FAILED + 1))
    else
        n=$(echo "$out" | grep -oP '\d+(?= passed)' | paste -sd+ | bc 2>/dev/null || echo 0)
        printf "\033[32mok\033[0m  %s tests\n" "${n:-0}"
    fi
done

echo ""
echo "  $MISSING missing test(s), $FAILED crate(s) failing, $GAPS unwired sentinel(s)"
[ "$MISSING" -eq 0 ] && [ "$FAILED" -eq 0 ] && [ "$GAPS" -eq 0 ]
