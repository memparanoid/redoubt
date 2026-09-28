// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Bytes to hex and hex to bytes, in constant time, leaving nothing in a
// register — AArch64.
//
// Platforms: Linux and macOS, AAPCS64. Windows is not built.
// No runtime feature detection: base A64, general registers only. `hint #34`
//   is BTI c, a NOP where branch targets are not enforced.
// Crossing: pointers to the caller's storage and lengths. Nothing is returned;
//   the decoding's answer is one byte written through a pointer, one when every
//   character was a hex digit.
// Branches: on the length, and on the decoding's answer once every character
//   has been read. Never on a byte or a digit: each is chosen between by `csel`
//   or turned into a mask by `csetm`, and no table is indexed by one.
// Not answered for: what other code left in registers, the ranges themselves,
//   a signal frame, a core dump, swap, ptrace, or a fault before the wipe.
// No routine takes a frame, and no vector register is written, so the probe
//   has neither a stack half nor a vector half.

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
// platform register), not x30 (every `bl` writes it).
.macro HEX_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro HEX_CLEAR reg
    mov \reg, xzr
.endm

.macro HEX_FILL reg
    mov \reg, x0
.endm

.macro HEX_GATHER reg
    orr x1, x1, \reg
.endm

.macro HEX_ZEROIZE_ALL
    HEX_EACH HEX_CLEAR
.endm

// The nibble in \n as its lowercase digit, through \t: past nine it takes the
// 0x27 that carries `'0' + 10` to `'a'`, chosen by `csel` and not by a branch.
.macro HEX_NIBBLE_TO_DIGIT n, t
    cmp \n, #9
    mov \t, #0x27
    csel \t, \t, wzr, hi
    add \n, \n, #0x30
    add \n, \n, \t
.endm

// The digit in \c as its nibble, through \t: `c ^ '0'` when that is under ten,
// and `(c & ~0x20) - 55` otherwise, chosen by `csel`. Only right for a digit
// the first pass has already accepted.
.macro HEX_DIGIT_TO_NIBBLE c, t
    eor \t, \c, #0x30
    cmp \t, #10
    bic \c, \c, #0x20
    sub \c, \c, #55
    csel \c, \t, \c, lo
.endm

// ============================================================================
// redoubt_hex_bytes_to_hex
// ============================================================================
//
// void redoubt_hex_bytes_to_hex(const uint8_t *src, size_t len, uint8_t *dst)
// x0 = src, x1 = len, x2 = dst, two digits written per byte.

.global FUNC(redoubt_hex_bytes_to_hex)
HIDDEN_FUNC(redoubt_hex_bytes_to_hex)
#if !defined(__APPLE__)
.type FUNC(redoubt_hex_bytes_to_hex), %function
#endif
.p2align 4
FUNC(redoubt_hex_bytes_to_hex):
    .cfi_startproc
    hint #34
    cbz x1, .Lencode_wipe
.Lencode_next:
    ldrb w4, [x0], #1
    lsr w5, w4, #4
    and w4, w4, #15
    HEX_NIBBLE_TO_DIGIT w5, w6
    HEX_NIBBLE_TO_DIGIT w4, w6
    strb w5, [x2], #1
    strb w4, [x2], #1
    subs x1, x1, #1
    b.ne .Lencode_next
.Lencode_wipe:
    HEX_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_hex_bytes_to_hex), .-FUNC(redoubt_hex_bytes_to_hex)
#endif

// ============================================================================
// redoubt_hex_hex_to_bytes
// ============================================================================
//
// void redoubt_hex_hex_to_bytes(const uint8_t *src, size_t len, uint8_t *dst,
//                               uint8_t *answer)
// x0 = src, x1 = len (even), x2 = dst (len / 2), x3 = answer; one when every
// character was a hex digit, and `dst` all zeros when not.

.global FUNC(redoubt_hex_hex_to_bytes)
HIDDEN_FUNC(redoubt_hex_hex_to_bytes)
#if !defined(__APPLE__)
.type FUNC(redoubt_hex_hex_to_bytes), %function
#endif
.p2align 4
FUNC(redoubt_hex_hex_to_bytes):
    .cfi_startproc
    hint #34
    mov w4, #0
    mov x5, #0
    cbz x1, .Ldecode_checked
.Ldecode_check_next:
    ldrb w6, [x0, x5]
    eor w7, w6, #0x30
    cmp w7, #10
    csetm w7, lo
    bic w6, w6, #0x20
    sub w6, w6, #65
    cmp w6, #6
    csetm w6, lo
    orr w6, w6, w7
    mvn w6, w6
    and w6, w6, #1
    orr w4, w4, w6
    add x5, x5, #1
    cmp x5, x1
    b.ne .Ldecode_check_next
.Ldecode_checked:
    lsr x1, x1, #1
    mov x5, #0
    cbnz w4, .Ldecode_refuse
    cbz x1, .Ldecode_answer
.Ldecode_next:
    ldrb w6, [x0], #1
    HEX_DIGIT_TO_NIBBLE w6, w7
    ldrb w8, [x0], #1
    HEX_DIGIT_TO_NIBBLE w8, w7
    orr w6, w8, w6, lsl #4
    strb w6, [x2, x5]
    add x5, x5, #1
    cmp x5, x1
    b.ne .Ldecode_next
    b .Ldecode_answer
.Ldecode_refuse:
    cbz x1, .Ldecode_answer
.Ldecode_refuse_next:
    strb wzr, [x2, x5]
    add x5, x5, #1
    cmp x5, x1
    b.ne .Ldecode_refuse_next
.Ldecode_answer:
    cmp w4, #0
    cset w6, eq
    strb w6, [x3]
    HEX_ZEROIZE_ALL
    ret
    .cfi_endproc
#if !defined(__APPLE__)
.size FUNC(redoubt_hex_hex_to_bytes), .-FUNC(redoubt_hex_hex_to_bytes)
#endif

// ============================================================================
// THE ZEROIZATION PROBE
// ============================================================================

// uint64_t redoubt_hex_registers_are_zeroized(void)
// Zero when every register in the budget is empty. x0 is gathered before it
// carries the answer; no argument, because x0 is one of the registers asked
// about.
.global FUNC(redoubt_hex_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hex_registers_are_zeroized)
.p2align 4
FUNC(redoubt_hex_registers_are_zeroized):
    HEX_EACH HEX_GATHER
    mov x0, x1
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global FUNC(redoubt_hex_dirty_registers)
HIDDEN_FUNC(redoubt_hex_dirty_registers)
.p2align 4
FUNC(redoubt_hex_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    HEX_EACH HEX_FILL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
