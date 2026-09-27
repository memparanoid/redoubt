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

// ============================================================================
// poly1305_init
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_v2_init(uint64_t r[2], uint8_t s[16],
//                                 const uint8_t key[32]);
//
// Parameters (AAPCS):
//   x0: r (written), x1: s (written), x2: key (read only)
//
// No frame: the clamp fits in the budget.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_init)
HIDDEN_FUNC(redoubt_poly1305_v2_init)
FUNC(redoubt_poly1305_v2_init):
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
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_poly1305_v2_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because x0 is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_v2_registers_are_zeroized)
FUNC(redoubt_poly1305_v2_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov x0, x1
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_v2_dirty_registers)
FUNC(redoubt_poly1305_v2_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    POLY1305_EACH POLY1305_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_poly1305_v2_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `bl`
//   keeps the return address in x30 and leaves sp where the previous callee
//   found it, so `[sp - \size, sp)` is the frame that callee took. Asked after
//   the registers, never before: reading the frame takes registers.
//
// void redoubt_poly1305_v2_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in x0, marked and left.
//
// void redoubt_poly1305_v2_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro POLY1305_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_poly1305_v2_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_poly1305_v2_frame_is_zeroized_\name)
FUNC(redoubt_poly1305_v2_frame_is_zeroized_\name):
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
.globl FUNC(redoubt_poly1305_v2_dirty_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_v2_dirty_frame_\name)
FUNC(redoubt_poly1305_v2_dirty_frame_\name):
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
.globl FUNC(redoubt_poly1305_v2_clean_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_v2_clean_frame_\name)
FUNC(redoubt_poly1305_v2_clean_frame_\name):
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
