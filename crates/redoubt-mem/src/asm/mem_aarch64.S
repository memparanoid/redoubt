// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// A copy, a swap, a UTF-8 check and a zero check that leave nothing in a
// register — AArch64.
//
// Platforms: Linux and macOS, AAPCS64. Windows is not built.
// No runtime feature detection: base A64 and Advanced SIMD, nothing wider than
//   the 128-bit V registers written. `hint #34` is BTI c, a NOP where branch
//   targets are not enforced.
// Crossing: pointers to the caller's storage and lengths. Nothing is returned;
//   each check's answer is one byte written through a pointer.
// Branches: the copy, the swap and the zero check on the length only. The UTF-8
//   check on the bytes, stopping at the first that is not UTF-8: not constant
//   time.
// Not answered for: what other code left in registers, the ranges themselves,
//   a signal frame, a core dump, swap, ptrace, or a fault before the wipe.
// No routine takes a frame, so the probe has no stack half.

.text

#if !defined(__aarch64__) || defined(_WIN32)
#error "Requires non-Windows AArch64"
#endif

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// The whole caller-saved set, the caller's pointers included, whether or not a
// routine writes each: the probe asks about this list, and a shorter one would
// stop covering a register the day a routine reaches for it. Not x18 (the
// platform register), not x30 (every `bl` writes it), not v8-v15 (callee-saved).
.macro MEM_EACH_GENERAL op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro MEM_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        \op \reg
    .endr
.endm

.macro MEM_CLEAR_GENERAL reg
    mov \reg, xzr
.endm

.macro MEM_CLEAR_VECTOR n
    movi v\n\().16b, #0
.endm

.macro MEM_FILL_GENERAL reg
    mov \reg, x0
.endm

.macro MEM_FILL_VECTOR n
    mov v\n\().16b, v0.16b
.endm

.macro MEM_GATHER_GENERAL reg
    orr x1, x1, \reg
.endm

.macro MEM_GATHER_VECTOR n
    orr v0.16b, v0.16b, v\n\().16b
.endm

.macro MEM_ZEROIZE_ALL
    MEM_EACH_GENERAL MEM_CLEAR_GENERAL
    MEM_EACH_VECTOR MEM_CLEAR_VECTOR
.endm

// ============================================================================
// redoubt_mem_copy_nonoverlapping
// ============================================================================
//
// void redoubt_mem_copy_nonoverlapping(const uint8_t *src, uint8_t *dst, size_t bytes)
// x0 = src, x1 = dst, x2 = bytes; the ranges disjoint.

.global FUNC(redoubt_mem_copy_nonoverlapping)
HIDDEN_FUNC(redoubt_mem_copy_nonoverlapping)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_copy_nonoverlapping), %function
#endif
.p2align 4
FUNC(redoubt_mem_copy_nonoverlapping):
    .cfi_startproc
    hint #34
    cmp x2, #64
    b.lo .Lcopy_32
.Lcopy_64:
    ldp q0, q1, [x0]
    ldp q2, q3, [x0, #32]
    add x0, x0, #64
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    add x1, x1, #64
    sub x2, x2, #64
    cmp x2, #64
    b.hs .Lcopy_64
.Lcopy_32:
    tbz x2, #5, .Lcopy_16
    ldp q0, q1, [x0], #32
    stp q0, q1, [x1], #32
.Lcopy_16:
    tbz x2, #4, .Lcopy_8
    ldr q0, [x0], #16
    str q0, [x1], #16
.Lcopy_8:
    tbz x2, #3, .Lcopy_4
    ldr x3, [x0], #8
    str x3, [x1], #8
.Lcopy_4:
    tbz x2, #2, .Lcopy_2
    ldr w3, [x0], #4
    str w3, [x1], #4
.Lcopy_2:
    tbz x2, #1, .Lcopy_1
    ldrh w3, [x0], #2
    strh w3, [x1], #2
.Lcopy_1:
    tbz x2, #0, .Lcopy_wipe
    ldrb w3, [x0]
    strb w3, [x1]
.Lcopy_wipe:
    MEM_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_mem_copy_nonoverlapping), .-FUNC(redoubt_mem_copy_nonoverlapping)
#endif

// ============================================================================
// redoubt_mem_swap_nonoverlapping
// ============================================================================
//
// void redoubt_mem_swap_nonoverlapping(uint8_t *a, uint8_t *b, size_t bytes)
// x0 = a, x1 = b, x2 = bytes; the ranges disjoint.

.global FUNC(redoubt_mem_swap_nonoverlapping)
HIDDEN_FUNC(redoubt_mem_swap_nonoverlapping)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_swap_nonoverlapping), %function
#endif
.p2align 4
FUNC(redoubt_mem_swap_nonoverlapping):
    .cfi_startproc
    hint #34
    cmp x2, #32
    b.lo .Lswap_16
.Lswap_32:
    ldp q0, q1, [x0]
    ldp q2, q3, [x1]
    stp q2, q3, [x0], #32
    stp q0, q1, [x1], #32
    sub x2, x2, #32
    cmp x2, #32
    b.hs .Lswap_32
.Lswap_16:
    tbz x2, #4, .Lswap_8
    ldr q0, [x0]
    ldr q2, [x1]
    str q2, [x0], #16
    str q0, [x1], #16
.Lswap_8:
    tbz x2, #3, .Lswap_4
    ldr x3, [x0]
    ldr x4, [x1]
    str x4, [x0], #8
    str x3, [x1], #8
.Lswap_4:
    tbz x2, #2, .Lswap_2
    ldr w3, [x0]
    ldr w4, [x1]
    str w4, [x0], #4
    str w3, [x1], #4
.Lswap_2:
    tbz x2, #1, .Lswap_1
    ldrh w3, [x0]
    ldrh w4, [x1]
    strh w4, [x0], #2
    strh w3, [x1], #2
.Lswap_1:
    tbz x2, #0, .Lswap_wipe
    ldrb w3, [x0]
    ldrb w4, [x1]
    strb w4, [x0]
    strb w3, [x1]
.Lswap_wipe:
    MEM_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_mem_swap_nonoverlapping), .-FUNC(redoubt_mem_swap_nonoverlapping)
#endif

// ============================================================================
// redoubt_mem_is_utf8
// ============================================================================
//
// void redoubt_mem_is_utf8(const uint8_t *bytes, size_t len, uint8_t *answer)
// x0 = bytes, x1 = len, x2 = answer; one or zero, by RFC 3629.

.global FUNC(redoubt_mem_is_utf8)
HIDDEN_FUNC(redoubt_mem_is_utf8)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_is_utf8), %function
#endif
.p2align 4
FUNC(redoubt_mem_is_utf8):
    .cfi_startproc
    hint #34
    cbz x1, .Lutf8_valid
.Lutf8_next:
    ldrb w3, [x0]
    cmp w3, #0x80
    b.lo .Lutf8_one
    cmp w3, #0xC2
    b.lo .Lutf8_invalid
    cmp w3, #0xE0
    b.lo .Lutf8_two
    cmp w3, #0xF0
    b.lo .Lutf8_three
    cmp w3, #0xF5
    b.lo .Lutf8_four
    b .Lutf8_invalid
.Lutf8_one:
    add x0, x0, #1
    subs x1, x1, #1
    b.ne .Lutf8_next
    b .Lutf8_valid
.Lutf8_two:
    cmp x1, #2
    b.lo .Lutf8_invalid
    ldrb w4, [x0, #1]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Lutf8_invalid
    add x0, x0, #2
    subs x1, x1, #2
    b.ne .Lutf8_next
    b .Lutf8_valid
.Lutf8_three:
    cmp x1, #3
    b.lo .Lutf8_invalid
    // RFC 3629: after E0 only A0..BF (no overlong), after ED only 80..9F (no
    // surrogate).
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
    b.lo .Lutf8_invalid
    cmp w4, w6
    b.hi .Lutf8_invalid
    ldrb w4, [x0, #2]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Lutf8_invalid
    add x0, x0, #3
    subs x1, x1, #3
    b.ne .Lutf8_next
    b .Lutf8_valid
.Lutf8_four:
    cmp x1, #4
    b.lo .Lutf8_invalid
    // RFC 3629: after F0 only 90..BF (no overlong), after F4 only 80..8F
    // (nothing past U+10FFFF).
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
    b.lo .Lutf8_invalid
    cmp w4, w6
    b.hi .Lutf8_invalid
    ldrb w4, [x0, #2]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Lutf8_invalid
    ldrb w4, [x0, #3]
    sub w4, w4, #0x80
    cmp w4, #0x3F
    b.hi .Lutf8_invalid
    add x0, x0, #4
    subs x1, x1, #4
    b.ne .Lutf8_next
    // The answer goes out through x2 before the wipe empties it.
.Lutf8_valid:
    mov w4, #1
    strb w4, [x2]
    b .Lutf8_wipe
.Lutf8_invalid:
    strb wzr, [x2]
.Lutf8_wipe:
    MEM_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_mem_is_utf8), .-FUNC(redoubt_mem_is_utf8)
#endif

// ============================================================================
// redoubt_mem_is_zeroized
// ============================================================================
//
// void redoubt_mem_is_zeroized(const uint8_t *bytes, size_t len, uint8_t *answer)
// x0 = bytes, x1 = len, x2 = answer; one when every byte is zero.

.global FUNC(redoubt_mem_is_zeroized)
HIDDEN_FUNC(redoubt_mem_is_zeroized)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_is_zeroized), %function
#endif
.p2align 4
FUNC(redoubt_mem_is_zeroized):
    .cfi_startproc
    hint #34
    mov w3, #0
    cbz x1, .Lzero_answer
.Lzero_next:
    ldrb w4, [x0], #1
    orr w3, w3, w4
    subs x1, x1, #1
    b.ne .Lzero_next
    // The answer goes out through x2 before the wipe empties it.
.Lzero_answer:
    cmp w3, #0
    cset w4, eq
    strb w4, [x2]
    MEM_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_mem_is_zeroized), .-FUNC(redoubt_mem_is_zeroized)
#endif

// ============================================================================
// THE ZEROIZATION PROBE
// ============================================================================

// uint64_t redoubt_mem_registers_are_zeroized(void)
// Zero when every register in the budget is empty. The general registers are
// folded first, so x0 is read before it carries the answer; no argument,
// because x0 is one of the registers asked about.
.global FUNC(redoubt_mem_registers_are_zeroized)
HIDDEN_FUNC(redoubt_mem_registers_are_zeroized)
.p2align 4
FUNC(redoubt_mem_registers_are_zeroized):
    MEM_EACH_GENERAL MEM_GATHER_GENERAL
    MEM_EACH_VECTOR MEM_GATHER_VECTOR
    mov x0, v0.d[0]
    mov x2, v0.d[1]
    orr x0, x0, x2
    orr x0, x0, x1
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global FUNC(redoubt_mem_dirty_registers)
HIDDEN_FUNC(redoubt_mem_dirty_registers)
.p2align 4
FUNC(redoubt_mem_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    dup v0.2d, x0
    MEM_EACH_VECTOR MEM_FILL_VECTOR
    MEM_EACH_GENERAL MEM_FILL_GENERAL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
