// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 - AArch64 (AAPCS) Implementation, radix 2^64
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
//   ACC         0..23   the accumulator: two whole words and the bits above
//   BLOCK      24..39   the last block of the message, padded here
//   SAID       40..47   where the message is up to
//   LEN        48..55   how much of it is left
//   RPTR       56..63   the caller's `r`, read where it lies
//   SPTR       64..71   the caller's `s`
//   OUT        72..79   where the tag goes
//   ACCPTR     80..87   the caller's accumulator
//   BLOCKPTR   88..95   the caller's partial block
//   FILLEDPTR  96..103  how much of it is filled
//             104..111  padding
//
// FRAME is a multiple of sixteen: AArch64 faults on a load or store through an
// sp that is not sixteen-aligned.
.set ACC, 0
.set BLOCK, 24
.set SAID, 40
.set LEN, 48
.set RPTR, 56
.set SPTR, 64
.set OUT, 72
.set ACCPTR, 80
.set BLOCKPTR, 88
.set FILLEDPTR, 96
.set FRAME, 112

// ============================================================================
// Frame wipe
// ============================================================================

// Every byte of the frame, padding included, then the frame given back.
.macro POLY1305_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
    add sp, sp, #FRAME
.endm

// acc = acc * r, reduced only as far as the next block needs:
//
//   d0 = h0·r0 + h1·s1            in x11:x10
//   d1 = h0·r1 + h1·r0 + h2·s1    in x13:x12
//   d2 = h2·r0                    in x14
//
// then carried into three words and the bits of the third above two folded
// back. h2 is a few bits, so its products fit a word and take `mul` alone.
.macro POLY1305_MULTIPLY
    ldr x11, [sp, #RPTR]
    ldp x7, x8, [x11]
    // s1 = r1 + r1/4. 2^130 is 5 modulo the prime and the clamp leaves the
    // bottom two bits of r1 empty, so a product with r1 that lands on 2^128
    // comes back as a product with s1.
    add x9, x8, x8, lsr #2
    ldp x4, x5, [sp, #ACC]
    ldr x6, [sp, #(ACC + 16)]

    mul x10, x4, x7
    umulh x11, x4, x7
    mul x12, x5, x9
    umulh x13, x5, x9
    adds x10, x10, x12
    adc x11, x11, x13

    mul x12, x4, x8
    umulh x13, x4, x8
    mul x14, x5, x7
    umulh x15, x5, x7
    adds x12, x12, x14
    adc x13, x13, x15
    mul x14, x6, x9
    adds x12, x12, x14
    adc x13, x13, xzr

    mul x14, x6, x7

    adds x12, x12, x11
    adc x13, x13, xzr
    add x14, x14, x13

    // What stands at or above 2^130 comes back down worth five.
    lsr x15, x14, #2
    add x15, x15, x15, lsl #2
    and x14, x14, #3
    adds x10, x10, x15
    adcs x12, x12, xzr
    adc x14, x14, xzr

    stp x10, x12, [sp, #ACC]
    str x14, [sp, #(ACC + 16)]
.endm

// acc += the sixteen bytes at `src`, with `hibit` above them, then acc *= r.
// `src` is not written.
.macro POLY1305_BLOCK src, hibit
    ldp x2, x3, [\src]
    ldp x4, x5, [sp, #ACC]
    ldr x6, [sp, #(ACC + 16)]
    adds x4, x4, x2
    adcs x5, x5, x3
    adc x6, x6, xzr
    .if \hibit
    add x6, x6, #1
    .endif
    stp x4, x5, [sp, #ACC]
    str x6, [sp, #(ACC + 16)]

    POLY1305_MULTIPLY
.endm

// ============================================================================
// poly1305_init
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_init(uint64_t r[2], uint8_t s[16],
//                                 const uint8_t key[32]);
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
    stp x3, x4, [x0]

    ldp x3, x4, [x2, #16]
    stp x3, x4, [x1]

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// poly1305_update
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_update(uint64_t acc[3], const uint64_t r[2],
//                                   uint8_t block[16], size_t *filled,
//                                   const uint8_t *said, size_t said_len);
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
// ║ far. The partial block is not in here — it is the caller's, written
// ║ where the caller keeps it, and emptied there as soon as the block it
// ║ completes has been counted.
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
    ldr x6, [x0, #16]
    str x6, [sp, #(ACC + 16)]

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
    ldr x6, [sp, #(ACC + 16)]
    str x6, [x9, #16]

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// poly1305_finalize
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_finalize(uint64_t acc[3], const uint64_t r[2],
//                                     const uint8_t s[16], const uint8_t *said,
//                                     size_t said_len, uint8_t out[16]);
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
// ║ is made from, and BLOCK the last bytes of the message with the marker
// ║ written after them. That last one is message in the clear, and it is
// ║ here rather than in the caller's buffer because a caller that handed
// ║ over a whole message has no buffer to pad.
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
    ldr x6, [x0, #16]
    str x6, [sp, #(ACC + 16)]

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
    ldr x6, [sp, #(ACC + 16)]
    str x6, [x9, #16]

    ldp x2, x3, [sp, #ACC]
    ldr x4, [sp, #(ACC + 16)]

    // acc + 5 into x7:x6:x5: it reaches 2^130 exactly when acc is at least
    // 2^130 - 5, and then its low 128 bits are acc less the modulus.
    adds x5, x2, #5
    adcs x6, x3, xzr
    adc x7, x4, xzr

    // All ones in x7 where the difference is taken, all zeros where it is
    // not. A mask and not a branch: which one is a fact about the key.
    lsr x7, x7, #2
    neg x7, x7
    and x5, x5, x7
    and x6, x6, x7
    mvn x7, x7
    and x2, x2, x7
    and x3, x3, x7
    orr x2, x2, x5
    orr x3, x3, x6

    // + s, modulo 2^128: the carry out of the second word is dropped.
    ldr x9, [sp, #SPTR]
    ldp x5, x6, [x9]
    adds x2, x2, x5
    adc x3, x3, x6

    ldr x9, [sp, #OUT]
    stp x2, x3, [x9]

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
