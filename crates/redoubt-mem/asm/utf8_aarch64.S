/* void redoubt_mem_utf8_valid(const uint8_t *bytes, size_t len, uint8_t *answer);
 *
 * Whether `len` bytes spell UTF-8, written to `*answer` as one or zero, with
 * none of the bytes left in a register. The aarch64 half of `utf8_x86_64.S`,
 * which carries the whole argument for why.
 *
 * # What it promises
 *
 * On a normal return, every register in the budget below is zero: the bytes
 * read, the bounds a second byte is held to, and the caller's pointers and
 * length. General registers only, no vector register is written, nothing goes
 * on the stack, nothing is called, and no callee-saved register is touched.
 *
 * # What it does not promise
 *
 * Constant time. The path branches on the bytes and stops at the first one
 * that is not UTF-8, so how long it takes says where the multibyte sequences
 * are and where the first error is. The answer itself, one bit, is public.
 * Nor residue somebody else left, the range itself, state saved by a signal
 * or a context switch before the epilogue, or anything microarchitectural.
 *
 * What is UTF-8 is RFC 3629: no overlong forms (C0, C1, E0 80..9F, F0
 * 80..8F), no surrogates (ED A0..BF), nothing past U+10FFFF (F4 90..BF, F5..FF),
 * and no sequence cut short by the end of the range.
 *
 * AAPCS64 / Apple ARM64: x0=bytes, x1=len, x2=answer. No feature detection.
 *
 * Preprocess this file (cc/clang -c); it is not `global_asm!` material,
 * because the `#if` below is what picks the object format.
 */
#if !defined(__aarch64__) || defined(_WIN32)
#error "Requires non-Windows AArch64"
#endif
#ifdef __APPLE__
#define FUNC(name) _##name
#else
#define FUNC(name) name
#endif

/* ============================================================================
 * The register budget
 * ============================================================================
 *
 * Every register this routine puts anything in is named once, here, and every
 * operation over the set goes through this one list. It is x0-x17, the
 * pointers the caller handed over included, whether or not the routine writes
 * each one. x18 is the platform register and x30 the link register, and
 * neither is touched.
 */
.macro UTF8_EACH op
    \op x0
    \op x1
    \op x2
    \op x3
    \op x4
    \op x5
    \op x6
    \op x7
    \op x8
    \op x9
    \op x10
    \op x11
    \op x12
    \op x13
    \op x14
    \op x15
    \op x16
    \op x17
.endm

.macro UTF8_CLEAR reg
    mov \reg, xzr
.endm

.macro UTF8_FILL reg
    mov \reg, x0
.endm

.macro UTF8_GATHER reg
    orr x1, x1, \reg
.endm

.macro UTF8_ZEROIZE_ALL
    UTF8_EACH UTF8_CLEAR
.endm

/* ============================================================================
 * redoubt_mem_utf8_valid
 * ============================================================================
 *
 * w3 holds the lead byte, w4 a byte after it, and w5 and w6 the lowest and
 * highest the second byte may be. A continuation byte is 80..BF: less 0x80, at
 * most 0x3F.
 */
.text
.p2align 4
.globl FUNC(redoubt_mem_utf8_valid)
#ifndef __APPLE__
.type FUNC(redoubt_mem_utf8_valid), %function
#endif
FUNC(redoubt_mem_utf8_valid):
    .cfi_startproc
    hint #34 /* BTI c; a NOP where branch tracking is not enforced. */
    cbz x1, .Lvalid

.Lnext:
    ldrb w3, [x0]
    cmp w3, #0x80
    b.lo .Lone
    cmp w3, #0xC2
    b.lo .Linvalid
    cmp w3, #0xE0
    b.lo .Ltwo
    cmp w3, #0xF0
    b.lo .Lthree
    cmp w3, #0xF5
    b.lo .Lfour
    b .Linvalid

.Lone:
    add x0, x0, #1
    subs x1, x1, #1
    b.ne .Lnext
    b .Lvalid

.Ltwo:
    cmp x1, #2
    b.lo .Linvalid
    ldrb w4, [x0, #1]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Linvalid
    add x0, x0, #2
    subs x1, x1, #2
    b.ne .Lnext
    b .Lvalid

.Lthree:
    cmp x1, #3
    b.lo .Linvalid
    /* E0 is followed by A0..BF, ED by 80..9F, and every other by 80..BF. */
    mov w5, #0x80
    mov w6, #0xBF
    cmp w3, #0xE0
    b.ne 1f
    mov w5, #0xA0
1:  cmp w3, #0xED
    b.ne 2f
    mov w6, #0x9F
2:  ldrb w4, [x0, #1]
    cmp w4, w5
    b.lo .Linvalid
    cmp w4, w6
    b.hi .Linvalid
    ldrb w4, [x0, #2]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Linvalid
    add x0, x0, #3
    subs x1, x1, #3
    b.ne .Lnext
    b .Lvalid

.Lfour:
    cmp x1, #4
    b.lo .Linvalid
    /* F0 is followed by 90..BF, F4 by 80..8F, and F1..F3 by 80..BF. */
    mov w5, #0x80
    mov w6, #0xBF
    cmp w3, #0xF0
    b.ne 1f
    mov w5, #0x90
1:  cmp w3, #0xF4
    b.ne 2f
    mov w6, #0x8F
2:  ldrb w4, [x0, #1]
    cmp w4, w5
    b.lo .Linvalid
    cmp w4, w6
    b.hi .Linvalid
    ldrb w4, [x0, #2]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Linvalid
    ldrb w4, [x0, #3]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Linvalid
    add x0, x0, #4
    subs x1, x1, #4
    b.ne .Lnext

.Lvalid:
    mov w4, #1
    strb w4, [x2]
    b .Lwipe

.Linvalid:
    strb wzr, [x2]

    /* The one way out: the answer is written through `x2` before the budget,
     * `x2` with it, is emptied. */
.Lwipe:
    UTF8_ZEROIZE_ALL
    ret
    .cfi_endproc
#ifndef __APPLE__
.size FUNC(redoubt_mem_utf8_valid), .-FUNC(redoubt_mem_utf8_valid)
.section .note.GNU-stack,"",%progbits
#endif
