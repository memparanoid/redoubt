// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 One-Time Authenticator - AArch64 (AAPCS) Implementation
//
// Baseline armv8-a. No SIMD, no SVE, nothing to detect at runtime: the whole of
// it is scalar 64-bit integer arithmetic. That is not the fastest Poly1305
// anybody has written and it is not meant to be — a vectorized one needs a
// runtime check, a second and third copy of the multiply, and a wipe written
// once per register file. This one is the same code on every machine that runs
// it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - `r` and the accumulator are five limbs of twenty-six bits each
//   - The products of one block never leave registers
//   - Any spill region is named and wiped here
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, with the symbol naming below)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there
//     and the crate falls back to the Rust, which answers the same and
//     promises less.
//
// x18 is the platform register and is never read or written here.
//
// What crosses into here, and what does not:
//   Every argument is a pointer to storage the caller declared, and nothing is
//   returned. A returned value leaves in a register, and a register carrying
//   the answer out is a register the wipe below cannot touch — which is why
//   even how much of the buffer is used arrives and leaves through memory. A
//   length and the bit above a block arrive by value because neither is a
//   secret and both are known to anybody watching the call.
//
// What must not branch:
//   The final conditional subtraction is a mask and not a jump. Whether the
//   accumulator was above the modulus is a fact about the key that made it, and
//   a branch there is that fact on a clock.
//
// What this cannot answer for:
//   The limbs are held in registers and in the frame this file named and wiped.
//   That is a statement about this file, not about the machine. When a signal
//   is delivered the kernel writes the whole register context to a frame on the
//   user stack, and nothing in user space wipes that frame on the way back. The
//   same goes for a core dump, for a page that reached swap, and for anything
//   ptrace can read. None of those are reachable from here, and none are made
//   worse by this being assembly: the Rust has every one of them too.
//
// References:
// - RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, section 2.5
// - Procedure Call Standard for the Arm 64-bit Architecture, section 6.1.2

.text

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name)
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// The register budget
// ============================================================================
//
// AAPCS:
//   - Caller-saved GPR: x0-x17
//   - Platform register: x18            (DO NOT TOUCH)
//   - Callee-saved GPR: x19-x28, x29 (FP), x30 (LR)  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and
// every operation over the set goes through that one list. Emptying them and
// asking whether they are empty are the same eighteen registers by
// construction, not by two lists that happen to agree today.
//
// The list is x0-x17: every register a limb or a product lands in, and the
// three pointers the caller handed over on top of them. Those are the caller's
// own and it still has them, so clearing them costs nothing; leaving them is a
// pointer into the caller's key sitting in a register after the routine that
// needed it has returned.
//
// Does NOT include: x18 is the platform register, and x19 upward are the
// caller's, restored by an epilogue where there is one.
//
// Does NOT include the SIMD registers either. Nothing here writes one, so
// clearing them would be clearing registers this code never put anything in.
//
.macro POLY1305_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro POLY1305_CLEAR reg
    mov \reg, xzr
.endm

// Copies what x0 already holds into each of them, x0 included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro POLY1305_FILL reg
    mov \reg, x0
.endm

// Gathers into x1, which is in the list and therefore contributes its own
// value on its own line. What the gather leaves in x1 is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro POLY1305_GATHER reg
    orr x1, x1, \reg
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro POLY1305_ZEROIZE_ALL
    POLY1305_EACH POLY1305_CLEAR
.endm

// ============================================================================
// Frame layout — 160 bytes, entirely above sp
// ============================================================================
//
//   ACC      0..39    the accumulator, five limbs of twenty-six bits
//   SUMS    40..79    one block's five products, then the reduced answer
//   BLOCK   80..95    the last block of the message, padded here
//   SAID    96..103   where the message is up to
//   LEN    104..111   how much of it is left
//   RPTR   112..119   the caller's `r`, read where it lies
//   SPTR   120..127   the caller's `s`
//   OUT    128..135   where the tag goes
//   ACCPTR 136..143   the caller's accumulator, written back at the end
//
// `r` stays in the caller's array and is read thirty-two bits at a time. The
// limb mask, and every other constant below, is a logical immediate: a run of
// ones needs no register to hold it.
//
.set ACC, 0
.set SUMS, 40
.set BLOCK, 80
.set SAID, 96
.set LEN, 104
.set RPTR, 112
.set SPTR, 120
.set OUT, 128
.set ACCPTR, 136
// `update` reaches the caller's partial block and its fill mark where they
// lie, for the same reason `r` is not copied: they outlive the call and the
// caller is the one that empties them.
.set BLOCKPTR, 144
.set FILLEDPTR, 152
.set FRAME, 160

.macro POLY1305_EMPTY_FRAME
    .irp offset,0,16,32,48,64,80,96,112,128,144
        stp xzr, xzr, [sp, #\offset]
    .endr
    add sp, sp, #FRAME
.endm

// One product of the twenty-five, into x2. `five` picks the limb of `r` that
// wrapped past the top and came back worth five times less a power.
.macro POLY1305_TERM at, limb, five
    ldr w3, [x11, #(4 * \limb)]
    .if \five
    add x3, x3, x3, lsl #2
    .endif
    ldr x4, [sp, #(ACC + 8 * \at)]
    madd x2, x3, x4, x2
.endm

.macro POLY1305_FIRST at, limb, five
    ldr w3, [x11, #(4 * \limb)]
    .if \five
    add x3, x3, x3, lsl #2
    .endif
    ldr x4, [sp, #(ACC + 8 * \at)]
    mul x2, x3, x4
.endm

// Every limb of the five at `at` back under twenty-six bits, and what ran off
// the top folded back in worth five.
.macro POLY1305_CARRY at
    .irp step,0,8,16,24
        ldr x2, [sp, #(\at + \step)]
        lsr x3, x2, #26
        ldr x4, [sp, #(\at + \step + 8)]
        add x4, x4, x3
        str x4, [sp, #(\at + \step + 8)]
        and x2, x2, #0x3ffffff
        str x2, [sp, #(\at + \step)]
    .endr

    ldr x2, [sp, #(\at + 32)]
    lsr x3, x2, #26
    add x3, x3, x3, lsl #2
    ldr x4, [sp, #\at]
    add x4, x4, x3
    str x4, [sp, #\at]
    and x2, x2, #0x3ffffff
    str x2, [sp, #(\at + 32)]

    ldr x2, [sp, #\at]
    lsr x3, x2, #26
    ldr x4, [sp, #(\at + 8)]
    add x4, x4, x3
    str x4, [sp, #(\at + 8)]
    and x2, x2, #0x3ffffff
    str x2, [sp, #\at]
.endm

// acc = acc * r, modulo 2^130 - 5. Twenty-five products gathered by which
// power of 2^26 they land on, then every limb put back under its width.
.macro POLY1305_MULTIPLY
    ldr x11, [sp, #RPTR]

    POLY1305_FIRST 0, 0, 0
    POLY1305_TERM  1, 4, 1
    POLY1305_TERM  2, 3, 1
    POLY1305_TERM  3, 2, 1
    POLY1305_TERM  4, 1, 1
    str x2, [sp, #SUMS]

    POLY1305_FIRST 0, 1, 0
    POLY1305_TERM  1, 0, 0
    POLY1305_TERM  2, 4, 1
    POLY1305_TERM  3, 3, 1
    POLY1305_TERM  4, 2, 1
    str x2, [sp, #(SUMS + 8)]

    POLY1305_FIRST 0, 2, 0
    POLY1305_TERM  1, 1, 0
    POLY1305_TERM  2, 0, 0
    POLY1305_TERM  3, 4, 1
    POLY1305_TERM  4, 3, 1
    str x2, [sp, #(SUMS + 16)]

    POLY1305_FIRST 0, 3, 0
    POLY1305_TERM  1, 2, 0
    POLY1305_TERM  2, 1, 0
    POLY1305_TERM  3, 0, 0
    POLY1305_TERM  4, 4, 1
    str x2, [sp, #(SUMS + 24)]

    POLY1305_FIRST 0, 4, 0
    POLY1305_TERM  1, 3, 0
    POLY1305_TERM  2, 2, 0
    POLY1305_TERM  3, 1, 0
    POLY1305_TERM  4, 0, 0
    str x2, [sp, #(SUMS + 32)]

    POLY1305_CARRY SUMS

    .irp offset,0,8,16,24,32
        ldr x2, [sp, #(SUMS + \offset)]
        str x2, [sp, #(ACC + \offset)]
    .endr
.endm

// acc += the sixteen bytes at `src`, with `hibit` above them, and then acc is
// multiplied by `r`. `src` is a register and is not written.
.macro POLY1305_BLOCK src, hibit
    ldp x2, x3, [\src]

    and x4, x2, #0x3ffffff
    ldr x5, [sp, #ACC]
    add x5, x5, x4
    str x5, [sp, #ACC]

    ubfx x4, x2, #26, #26
    ldr x5, [sp, #(ACC + 8)]
    add x5, x5, x4
    str x5, [sp, #(ACC + 8)]

    lsr x4, x2, #52
    orr x4, x4, x3, lsl #12
    and x4, x4, #0x3ffffff
    ldr x5, [sp, #(ACC + 16)]
    add x5, x5, x4
    str x5, [sp, #(ACC + 16)]

    ubfx x4, x3, #14, #26
    ldr x5, [sp, #(ACC + 24)]
    add x5, x5, x4
    str x5, [sp, #(ACC + 24)]

    lsr x4, x3, #40
    .if \hibit
    orr x4, x4, #0x1000000
    .endif
    ldr x5, [sp, #(ACC + 32)]
    add x5, x5, x4
    str x5, [sp, #(ACC + 32)]

    POLY1305_MULTIPLY
.endm

// ============================================================================
// init — x0: r, five u32 limbs out; x1: s, sixteen bytes out;
//        x2: key, thirty-two bytes in
// ============================================================================
//
// No frame and no callee-saved register: the whole clamp fits in the
// caller-saved ones, so there is nothing to give back and nothing to wipe but
// the registers themselves.
//
.p2align 4
.globl FUNC(redoubt_poly1305_init)
HIDDEN_FUNC(redoubt_poly1305_init)
FUNC(redoubt_poly1305_init):
    ldp x3, x4, [x2]

    // RFC 8439 §2.5 masks the top four bits of every fourth byte and the
    // bottom two of three others, which is one AND over each half.
    mov  x5, #0xffff
    movk x5, #0x0fff, lsl #16
    movk x5, #0xfffc, lsl #32
    movk x5, #0x0fff, lsl #48
    mov  x6, #0xfffc
    movk x6, #0x0fff, lsl #16
    movk x6, #0xfffc, lsl #32
    movk x6, #0x0fff, lsl #48
    and x3, x3, x5
    and x4, x4, x6

    // Five limbs of twenty-six bits out of the hundred and twenty-eight.
    ubfx x7, x3, #0, #26
    ubfx x8, x3, #26, #26
    lsr  x9, x3, #52
    orr  x9, x9, x4, lsl #12
    ubfx x9, x9, #0, #26
    ubfx x10, x4, #14, #26
    lsr  x11, x4, #40

    stp w7, w8, [x0]
    stp w9, w10, [x0, #8]
    str w11, [x0, #16]

    // `s` is kept as it arrived: it is added at the very end and never
    // multiplied, so there is no representation to move it into.
    ldp x3, x4, [x2, #16]
    stp x3, x4, [x1]

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// update — x0: acc; x1: r; x2: the partial block; x3: how full it is, read
//          and written; x4: message; x5: its length
// ============================================================================
//
// What arrives is whatever the caller had. Whole blocks go by where they lie;
// only a tail that is not a block yet is copied into the caller's buffer, and
// only the block that filling it completed is counted here.
//
.p2align 4
.globl FUNC(redoubt_poly1305_update)
HIDDEN_FUNC(redoubt_poly1305_update)
FUNC(redoubt_poly1305_update):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial over everything counted so
// ║ far, and SUMS its products by `r`. The partial block is not in here —
// ║ it is the caller's, written where the caller keeps it, and emptied
// ║ there as soon as the block it completes has been counted.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    str x0, [sp, #ACCPTR]
    str x1, [sp, #RPTR]
    str x2, [sp, #BLOCKPTR]
    str x3, [sp, #FILLEDPTR]
    str x4, [sp, #SAID]
    str x5, [sp, #LEN]

    ldp x6, x7, [x0]
    stp x6, x7, [sp, #ACC]
    ldp x6, x7, [x0, #16]
    stp x6, x7, [sp, #(ACC + 16)]
    ldr x6, [x0, #32]
    str x6, [sp, #(ACC + 32)]

    ldr x6, [x3]
    cbz x6, Lupdate_stream

    // As much of the message as the buffer still has room for.
    mov x7, #16
    sub x7, x7, x6
    ldr x8, [sp, #LEN]
    cmp x7, x8
    csel x7, x7, x8, lo

    cbz x7, Lupdate_flush

    ldr x9, [sp, #SAID]
    ldr x10, [sp, #BLOCKPTR]
    add x10, x10, x6
    mov x11, xzr
Lupdate_fill_byte:
    ldrb w12, [x9, x11]
    strb w12, [x10, x11]
    add x11, x11, #1
    cmp x11, x7
    b.lo Lupdate_fill_byte

    add x6, x6, x7
    ldr x9, [sp, #FILLEDPTR]
    str x6, [x9]
    ldr x9, [sp, #SAID]
    add x9, x9, x7
    str x9, [sp, #SAID]
    ldr x9, [sp, #LEN]
    sub x9, x9, x7
    str x9, [sp, #LEN]

Lupdate_flush:
    cmp x6, #16
    b.ne Lupdate_stream

    ldr x7, [sp, #BLOCKPTR]
    POLY1305_BLOCK x7, 1

    // The caller's buffer is emptied here and not left for it to do: what is
    // in it is message, and the next thing written over it is only as much
    // message as the next tail happens to be.
    ldr x7, [sp, #BLOCKPTR]
    stp xzr, xzr, [x7]
    ldr x7, [sp, #FILLEDPTR]
    str xzr, [x7]

Lupdate_stream:
    ldr x6, [sp, #LEN]
    cmp x6, #16
    b.lo Lupdate_tail
    ldr x7, [sp, #SAID]
    POLY1305_BLOCK x7, 1
    ldr x6, [sp, #SAID]
    add x6, x6, #16
    str x6, [sp, #SAID]
    ldr x6, [sp, #LEN]
    sub x6, x6, #16
    str x6, [sp, #LEN]
    b Lupdate_stream

Lupdate_tail:
    ldr x6, [sp, #LEN]
    cbz x6, Lupdate_done

    ldr x9, [sp, #SAID]
    ldr x10, [sp, #BLOCKPTR]
    mov x11, xzr
Lupdate_keep_byte:
    ldrb w12, [x9, x11]
    strb w12, [x10, x11]
    add x11, x11, #1
    cmp x11, x6
    b.lo Lupdate_keep_byte

    ldr x9, [sp, #FILLEDPTR]
    str x6, [x9]

Lupdate_done:
    ldr x9, [sp, #ACCPTR]
    ldp x6, x7, [sp, #ACC]
    stp x6, x7, [x9]
    ldp x6, x7, [sp, #(ACC + 16)]
    stp x6, x7, [x9, #16]
    ldr x6, [sp, #(ACC + 32)]
    str x6, [x9, #32]

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// finalize — x0: acc; x1: r; x2: s; x3: message; x4: its length; x5: tag out
// ============================================================================
//
// One call and not a loop the caller drives: a message handed over whole goes
// through every block of itself without the bytes coming back to Rust in
// between.
//
.p2align 4
.globl FUNC(redoubt_poly1305_finalize)
HIDDEN_FUNC(redoubt_poly1305_finalize)
FUNC(redoubt_poly1305_finalize):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial and then the number the tag
// ║ is made from, SUMS its products by `r`, and BLOCK the last bytes of the
// ║ message with the marker written after them. That last one is message in
// ║ the clear, and it is here rather than in the caller's buffer because a
// ║ caller that handed over a whole message has no buffer to pad.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    str x0, [sp, #ACCPTR]
    str x1, [sp, #RPTR]
    str x2, [sp, #SPTR]
    str x3, [sp, #SAID]
    str x4, [sp, #LEN]
    str x5, [sp, #OUT]

    ldp x6, x7, [x0]
    stp x6, x7, [sp, #ACC]
    ldp x6, x7, [x0, #16]
    stp x6, x7, [sp, #(ACC + 16)]
    ldr x6, [x0, #32]
    str x6, [sp, #(ACC + 32)]

Lwhole:
    ldr x6, [sp, #LEN]
    cmp x6, #16
    b.lo Ltail
    ldr x7, [sp, #SAID]
    POLY1305_BLOCK x7, 1
    ldr x6, [sp, #SAID]
    add x6, x6, #16
    str x6, [sp, #SAID]
    ldr x6, [sp, #LEN]
    sub x6, x6, #16
    str x6, [sp, #LEN]
    b Lwhole

Ltail:
    ldr x6, [sp, #LEN]
    cbz x6, Lwritten_back

    stp xzr, xzr, [sp, #BLOCK]
    add x10, sp, #BLOCK
    ldr x7, [sp, #SAID]
    mov x8, xzr
Lcopy:
    ldrb w9, [x7, x8]
    strb w9, [x10, x8]
    add x8, x8, #1
    cmp x8, x6
    b.lo Lcopy

    // The one bit above the message, which is what keeps a tail of zeros from
    // reading as a shorter message that ended sooner.
    mov w9, #1
    strb w9, [x10, x6]
    mov x7, x10
    POLY1305_BLOCK x7, 0

Lwritten_back:
    // The accumulator the caller gets back is the polynomial, before the
    // reduction below turns it into a tag.
    ldr x9, [sp, #ACCPTR]
    ldp x6, x7, [sp, #ACC]
    stp x6, x7, [x9]
    ldp x6, x7, [sp, #(ACC + 16)]
    stp x6, x7, [x9, #16]
    ldr x6, [sp, #(ACC + 32)]
    str x6, [x9, #32]

    POLY1305_CARRY ACC

    // The accumulator is now below 2^130 but may still be at or above the
    // modulus, and there is exactly one subtraction that could be owed. Adding
    // five says whether it is: if the sum carries past the hundred and
    // thirtieth bit, the accumulator was at least 2^130 - 5.
    ldr x2, [sp, #ACC]
    add x2, x2, #5
    lsr x3, x2, #26
    and x2, x2, #0x3ffffff
    str x2, [sp, #SUMS]

    .irp offset,8,16,24
        ldr x2, [sp, #(ACC + \offset)]
        add x2, x2, x3
        lsr x3, x2, #26
        and x2, x2, #0x3ffffff
        str x2, [sp, #(SUMS + \offset)]
    .endr

    // All ones where the accumulator was already below the modulus, and all
    // zeros where it was not. A comparison instead of a mask would be a branch
    // on the tag, which is a branch on the key that made it.
    ldr x2, [sp, #(ACC + 32)]
    add x2, x2, x3
    lsr x2, x2, #26
    sub x10, x2, #1
    mvn x11, x10

    .irp offset,0,8,16,24
        ldr x2, [sp, #(ACC + \offset)]
        and x2, x2, x10
        ldr x3, [sp, #(SUMS + \offset)]
        and x3, x3, x11
        orr x2, x2, x3
        str x2, [sp, #(ACC + \offset)]
    .endr

    // The sum has no fifth limb, so where it is taken the fifth goes.
    ldr x2, [sp, #(ACC + 32)]
    and x2, x2, x10
    str x2, [sp, #(ACC + 32)]

    // Five limbs of twenty-six into four words of thirty-two.
    ldr x2, [sp, #ACC]
    ldr x3, [sp, #(ACC + 8)]
    and x4, x3, #0x3f
    orr x2, x2, x4, lsl #26

    lsr x5, x3, #6
    ldr x3, [sp, #(ACC + 16)]
    and x4, x3, #0xfff
    orr x5, x5, x4, lsl #20

    lsr x6, x3, #12
    ldr x3, [sp, #(ACC + 24)]
    and x4, x3, #0x3ffff
    orr x6, x6, x4, lsl #14

    lsr x7, x3, #18
    ldr x3, [sp, #(ACC + 32)]
    and x4, x3, #0xffffff
    orr x7, x7, x4, lsl #8

    // `s` added, carrying between the words, and the low half of each is the
    // tag. What runs off the top of the fourth is the modulo 2^128.
    ldr x9, [sp, #SPTR]
    ldr w4, [x9]
    add x2, x2, x4
    ldr w4, [x9, #4]
    add x5, x5, x4
    add x5, x5, x2, lsr #32
    ldr w4, [x9, #8]
    add x6, x6, x4
    add x6, x6, x5, lsr #32
    ldr w4, [x9, #12]
    add x7, x7, x4
    add x7, x7, x6, lsr #32

    ldr x9, [sp, #OUT]
    str w2, [x9]
    str w5, [x9, #4]
    str w6, [x9, #8]
    str w7, [x9, #12]

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================
//
// Nothing in production calls any of it. It is here and not in a file of its
// own because a reader asking whether the measurement is right should not have
// to find a second file and check that a number in it still matches a number
// in this one: FRAME below is the frame, and the register budget it asks about
// is the list the wipe uses, not a copy of either.
//
// What it costs is a few hundred bytes of instructions that ship unused. What
// it buys is that the only `160` in the measurement, and the only list of
// registers, are the ones at the top of this file.
//
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own list
//   frame_is_zeroized        asks the stack, with the file's own FRAME
//   dirty_registers          fills the budget and leaves it that way
//   dirty_frame              one byte of the frame, at an offset given
//   clean_frame              the frame written and emptied, with no arithmetic

// uint64_t redoubt_poly1305_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost x0, and x0
// is one of the registers being asked about — it would arrive holding our own
// pointer rather than the caller's value. With nothing passed, `bl` is the
// whole call sequence and every register read here is the caller's own.
//
// x30 is not in the budget and this is the routine that shows why: `bl` writes
// it on the way here, so asking about it would be asking about the call that
// did the asking.
.p2align 4
.globl FUNC(redoubt_poly1305_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_registers_are_zeroized)
FUNC(redoubt_poly1305_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov x0, x1
    ret

// uint64_t redoubt_poly1305_frame_is_zeroized(void)
//
// Whether any byte of the frame the call before it used is still holding
// something. Zero when it is all empty, and the bits of whatever was not.
//
// Reads below its own sp, and that is the whole of it: `bl` puts the return
// address in x30 and leaves sp where the routine before had it, so what sits
// under this one's sp is what sat under that one's — the frame it took and
// gave back. There is no return-address slot in between, which is the one way
// this differs from the same routine on x86-64.
//
// Asked after the registers, never before: reading a hundred and sixty bytes
// takes registers, and the answer about those has to be taken first.
.p2align 4
.globl FUNC(redoubt_poly1305_frame_is_zeroized)
HIDDEN_FUNC(redoubt_poly1305_frame_is_zeroized)
FUNC(redoubt_poly1305_frame_is_zeroized):
    mov x0, xzr
    sub x1, sp, #FRAME
    mov x2, sp
Lframe_scan:
    ldr x3, [x1], #8
    orr x0, x0, x3
    cmp x1, x2
    b.ne Lframe_scan
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_dirty_registers)
FUNC(redoubt_poly1305_dirty_registers):
    // The pattern does not fit in one instruction, so it is built sixteen bits
    // at a time before anything is copied out of x0.
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    POLY1305_EACH POLY1305_FILL
    ret

// One byte of the frame, dirtied and left. x0 says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// whatever sits next door would show.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_frame)
HIDDEN_FUNC(redoubt_poly1305_dirty_frame)
FUNC(redoubt_poly1305_dirty_frame):
    sub sp, sp, #FRAME
    // Isolate this byte from every previous call's residue. Keep x0, the
    // requested offset, intact until the whole frame is empty.
    mov x1, sp
    add x2, sp, #FRAME
Ldirty_clear:
    str xzr, [x1], #8
    cmp x1, x2
    b.ne Ldirty_clear
    mov w1, #0x5c
    strb w1, [sp, x0]
    add sp, sp, #FRAME
    ret

// The whole frame written and then emptied: what a routine above does, without
// the arithmetic in between.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.globl FUNC(redoubt_poly1305_clean_frame)
HIDDEN_FUNC(redoubt_poly1305_clean_frame)
FUNC(redoubt_poly1305_clean_frame):
    sub sp, sp, #FRAME
    mov x0, #0x5c5c
    movk x0, #0x5c5c, lsl #16
    movk x0, #0x5c5c, lsl #32
    movk x0, #0x5c5c, lsl #48
    mov x1, sp
    add x2, sp, #FRAME
Lclean_write:
    str x0, [x1], #8
    cmp x1, x2
    b.ne Lclean_write
    POLY1305_EMPTY_FRAME
    POLY1305_ZEROIZE_ALL
    ret
