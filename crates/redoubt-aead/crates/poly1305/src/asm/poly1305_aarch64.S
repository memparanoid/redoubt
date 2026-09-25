// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 - AArch64 (AAPCS) Implementation
//
// Armv8-A baseline: scalar integer instructions only, nothing detected at
// runtime.
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, Mach-O naming)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// lengths, which are public. Nothing is returned.
//
// The final subtraction of the modulus is a mask, not a branch: whether the
// accumulator reached the modulus is a fact about the key.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context to a frame on the user stack that nothing in user space wipes. The
//   same for a core dump, a page that reached swap, and anything ptrace can
//   read.
//
// References:
// - RFC 8439, section 2.5
// - Procedure Call Standard for the Arm 64-bit Architecture, section 6.1.2

.text

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// The register budget
// ============================================================================
//
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through this list. A register added to the wipe
// and missing from the verifier is a register nothing looks at, silently.
//
// AAPCS makes x0-x17 caller-saved. Out of the list: x18, the platform register;
// x30, which every `bl` writes; and x19-x28, callee-saved, which nothing here
// writes — saving one would spill the caller's value into this file's stack.
// Nothing here writes a vector register.
.macro POLY1305_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro POLY1305_CLEAR reg
    mov \reg, xzr
.endm

// Copies what x0 already holds into each, itself included. Used by the probe.
.macro POLY1305_FILL reg
    mov \reg, x0
.endm

// Folds each into x1, which is in the list and so contributes its own value.
// Used by the probe.
.macro POLY1305_GATHER reg
    orr x1, x1, \reg
.endm

.macro POLY1305_ZEROIZE_ALL
    POLY1305_EACH POLY1305_CLEAR
.endm

// ============================================================================
// Frame layout
// ============================================================================
//
//   ACC        0..39    the accumulator, five limbs of twenty-six bits
//   SUMS      40..79    one block's five products, then the reduced answer
//   BLOCK     80..95    the last block of the message, padded here
//   SAID      96..103   where the message is up to
//   LEN      104..111   how much of it is left
//   RPTR     112..119   the caller's `r`, read where it lies
//   SPTR     120..127   the caller's `s`
//   OUT      128..135   where the tag goes
//   ACCPTR   136..143   the caller's accumulator
//   BLOCKPTR 144..151   the caller's partial block
//   FILLEDPTR 152..159  how much of it is filled
//
// FRAME is a multiple of sixteen: AArch64 faults on a load or store through an
// sp that is not sixteen-aligned.
.set ACC, 0
.set SUMS, 40
.set BLOCK, 80
.set SAID, 96
.set LEN, 104
.set RPTR, 112
.set SPTR, 120
.set OUT, 128
.set ACCPTR, 136
.set BLOCKPTR, 144
.set FILLEDPTR, 152
.set FRAME, 160

// ============================================================================
// Frame wipe
// ============================================================================

// Every byte of the frame, then the frame given back.
.macro POLY1305_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
    add sp, sp, #FRAME
.endm

// One of the twenty-five products, added into x2. `five` scales the limb of
// `r` by five, for a product that lands past 2^130 and wraps modulo 2^130 - 5.
.macro POLY1305_TERM at, limb, five
    ldr w3, [x11, #(4 * \limb)]
    .if \five
    add x3, x3, x3, lsl #2
    .endif
    ldr x4, [sp, #(ACC + 8 * \at)]
    madd x2, x3, x4, x2
.endm

// The first product of a sum, which starts x2 rather than adding to it.
.macro POLY1305_FIRST at, limb, five
    ldr w3, [x11, #(4 * \limb)]
    .if \five
    add x3, x3, x3, lsl #2
    .endif
    ldr x4, [sp, #(ACC + 8 * \at)]
    mul x2, x3, x4
.endm

// Every limb of the five at `at` carried back under twenty-six bits; what runs
// off the top comes back into the first worth five.
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

// acc = acc * r modulo 2^130 - 5: the products summed by the power of 2^26
// they land on, then every limb carried back under twenty-six bits.
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

// acc += the sixteen bytes at `src`, with `hibit` above them, then acc *= r.
// `src` is not written.
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
// poly1305_init
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_init(uint32_t r[5], uint8_t s[16],
//                              const uint8_t key[32]);
//
// Parameters (AAPCS):
//   x0: r (written), x1: s (written), x2: key (read only)
//
// No frame: the clamp fits in the budget.
.p2align 4
.globl FUNC(redoubt_poly1305_init)
HIDDEN_FUNC(redoubt_poly1305_init)
FUNC(redoubt_poly1305_init):
    ldp x3, x4, [x2]

    // RFC 8439's clamp, as one AND over each half of `r`.
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

    ldp x3, x4, [x2, #16]
    stp x3, x4, [x1]

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// poly1305_update
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_update(uint64_t acc[5], const uint32_t r[5],
//                                uint8_t block[16], size_t *filled,
//                                const uint8_t *said, size_t said_len);
//
// Parameters (AAPCS):
//   x0: acc (read and written), x1: r (read only), x2: block (read and
//   written), x3: filled (read and written), x4: said (read only),
//   x5: said_len
//
// Whole blocks are read where they lie; only a tail short of a block is copied
// into the caller's `block`.
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
    cbz x6, .Lupdate_stream

    mov x7, #16
    sub x7, x7, x6
    ldr x8, [sp, #LEN]
    cmp x7, x8
    csel x7, x7, x8, lo

    cbz x7, .Lupdate_flush

    ldr x9, [sp, #SAID]
    ldr x10, [sp, #BLOCKPTR]
    add x10, x10, x6
    mov x11, xzr
.Lupdate_fill_byte:
    ldrb w12, [x9, x11]
    strb w12, [x10, x11]
    add x11, x11, #1
    cmp x11, x7
    b.lo .Lupdate_fill_byte

    add x6, x6, x7
    ldr x9, [sp, #FILLEDPTR]
    str x6, [x9]
    ldr x9, [sp, #SAID]
    add x9, x9, x7
    str x9, [sp, #SAID]
    ldr x9, [sp, #LEN]
    sub x9, x9, x7
    str x9, [sp, #LEN]

.Lupdate_flush:
    cmp x6, #16
    b.ne .Lupdate_stream

    ldr x7, [sp, #BLOCKPTR]
    POLY1305_BLOCK x7, 1

    // Counted, so emptied: the next tail may not cover all of it.
    ldr x7, [sp, #BLOCKPTR]
    stp xzr, xzr, [x7]
    ldr x7, [sp, #FILLEDPTR]
    str xzr, [x7]

.Lupdate_stream:
    ldr x6, [sp, #LEN]
    cmp x6, #16
    b.lo .Lupdate_tail
    ldr x7, [sp, #SAID]
    POLY1305_BLOCK x7, 1
    ldr x6, [sp, #SAID]
    add x6, x6, #16
    str x6, [sp, #SAID]
    ldr x6, [sp, #LEN]
    sub x6, x6, #16
    str x6, [sp, #LEN]
    b .Lupdate_stream

.Lupdate_tail:
    ldr x6, [sp, #LEN]
    cbz x6, .Lupdate_done

    ldr x9, [sp, #SAID]
    ldr x10, [sp, #BLOCKPTR]
    mov x11, xzr
.Lupdate_keep_byte:
    ldrb w12, [x9, x11]
    strb w12, [x10, x11]
    add x11, x11, #1
    cmp x11, x6
    b.lo .Lupdate_keep_byte

    ldr x9, [sp, #FILLEDPTR]
    str x6, [x9]

.Lupdate_done:
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
// poly1305_finalize
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_finalize(uint64_t acc[5], const uint32_t r[5],
//                                  const uint8_t s[16], const uint8_t *said,
//                                  size_t said_len, uint8_t out[16]);
//
// Parameters (AAPCS):
//   x0: acc (read and written), x1: r (read only), x2: s (read only),
//   x3: said (read only), x4: said_len, x5: out (written)
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

.Lwhole:
    ldr x6, [sp, #LEN]
    cmp x6, #16
    b.lo .Ltail
    ldr x7, [sp, #SAID]
    POLY1305_BLOCK x7, 1
    ldr x6, [sp, #SAID]
    add x6, x6, #16
    str x6, [sp, #SAID]
    ldr x6, [sp, #LEN]
    sub x6, x6, #16
    str x6, [sp, #LEN]
    b .Lwhole

.Ltail:
    ldr x6, [sp, #LEN]
    cbz x6, .Lwritten_back

    stp xzr, xzr, [sp, #BLOCK]
    add x10, sp, #BLOCK
    ldr x7, [sp, #SAID]
    mov x8, xzr
.Lcopy:
    ldrb w9, [x7, x8]
    strb w9, [x10, x8]
    add x8, x8, #1
    cmp x8, x6
    b.lo .Lcopy

    // The bit above the message, so that a tail ending in zeros does not read
    // as a shorter message.
    mov w9, #1
    strb w9, [x10, x6]
    mov x7, x10
    POLY1305_BLOCK x7, 0

.Lwritten_back:
    // Written back before the reduction below: the caller's accumulator is the
    // polynomial, not the tag.
    ldr x9, [sp, #ACCPTR]
    ldp x6, x7, [sp, #ACC]
    stp x6, x7, [x9]
    ldp x6, x7, [sp, #(ACC + 16)]
    stp x6, x7, [x9, #16]
    ldr x6, [sp, #(ACC + 32)]
    str x6, [x9, #32]

    POLY1305_CARRY ACC

    // acc + 5 into SUMS: it carries past bit 130 exactly when acc is at least
    // 2^130 - 5.
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

    // All ones in x10 if acc is below the modulus, all zeros if not, and x11
    // the opposite. A mask and not a branch: which one is a fact about the key.
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

    // acc - (2^130 - 5) has no fifth limb, so the fifth is kept only where acc
    // is.
    ldr x2, [sp, #(ACC + 32)]
    and x2, x2, x10
    str x2, [sp, #(ACC + 32)]

    // Five limbs of twenty-six bits into four words of thirty-two.
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

    // + s, modulo 2^128: the carry out of the fourth word is dropped.
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

// uint64_t redoubt_poly1305_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because x0 is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_poly1305_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_registers_are_zeroized)
FUNC(redoubt_poly1305_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov x0, x1
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_dirty_registers)
FUNC(redoubt_poly1305_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    POLY1305_EACH POLY1305_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_poly1305_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `bl`
//   keeps the return address in x30 and leaves sp where the previous callee
//   found it, so `[sp - \size, sp)` is the frame that callee took. Asked after
//   the registers, never before: reading the frame takes registers.
//
// void redoubt_poly1305_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in x0, marked and left.
//
// void redoubt_poly1305_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro POLY1305_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_poly1305_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_poly1305_frame_is_zeroized_\name)
FUNC(redoubt_poly1305_frame_is_zeroized_\name):
    mov x0, xzr
    sub x1, sp, #\size
    mov x2, sp
1:
    ldr x3, [x1], #8
    orr x0, x0, x3
    cmp x1, x2
    b.lo 1b
    ret

.p2align 4
.globl FUNC(redoubt_poly1305_dirty_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_dirty_frame_\name)
FUNC(redoubt_poly1305_dirty_frame_\name):
    sub sp, sp, #\size
    // The frame is emptied before the byte goes in, so that what a verifier
    // finds is this byte and not a previous call's residue.
    mov x1, xzr
2:
    str xzr, [sp, x1]
    add x1, x1, #8
    cmp x1, #\size
    b.lo 2b
    mov w2, #0x5c
    strb w2, [sp, x0]
    add sp, sp, #\size
    ret

.p2align 4
.globl FUNC(redoubt_poly1305_clean_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_clean_frame_\name)
FUNC(redoubt_poly1305_clean_frame_\name):
    sub sp, sp, #\size
    mov x0, #0x5c5c
    movk x0, #0x5c5c, lsl #16
    movk x0, #0x5c5c, lsl #32
    movk x0, #0x5c5c, lsl #48
    mov x1, xzr
3:
    str x0, [sp, x1]
    add x1, x1, #8
    cmp x1, #\size
    b.lo 3b
    POLY1305_EMPTY_FRAME
    POLY1305_ZEROIZE_ALL
    ret
.endm

POLY1305_FRAME_PROBE poly1305, FRAME

// ============================================================================
// Stack permissions
// ============================================================================
//
// An object with no .note.GNU-stack is one the linker assumes wants an
// executable stack, and one such object gives it to the whole binary. Nothing
// here needs one.
#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
