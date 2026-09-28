// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Bytes to hex and hex to bytes, in constant time, leaving nothing in a
// register — x86-64.
//
// Platforms: Linux and macOS, SysV. Windows is not built.
// No runtime feature detection, and nothing past the baseline: general
//   registers only. `endbr64` is a NOP where CET is off.
// Crossing: pointers to the caller's storage and lengths. Nothing is returned;
//   the decoding's answer is one byte written through a pointer, one when every
//   character was a hex digit.
// Branches: on the length only. Never on a byte, a digit or the decoding's
//   answer: each is turned into a mask by `cmp` and `sbb`, every byte decoded
//   is ANDed with the answer's mask whether or not it will be kept, and no
//   table is indexed by one.
// Not answered for: what other code left in registers, the ranges themselves,
//   a signal frame, a core dump, swap, ptrace, or a fault before the wipe.
// No routine takes a frame, and no vector register is written, so the probe
//   has neither a stack half nor a vector half.

.intel_syntax noprefix
.text

#if !defined(__x86_64__) || defined(_WIN32)
#error "Requires non-Windows x86-64"
#endif

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name)
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// The whole caller-saved set, the caller's pointers included, whether or not a
// routine writes each: the probe asks about this list, and a shorter one would
// stop covering a register the day a routine reaches for it.
.macro HEX_EACH op
    \op rax
    \op rcx
    \op rdx
    \op rsi
    \op rdi
    \op r8
    \op r9
    \op r10
    \op r11
.endm

.macro HEX_CLEAR reg
    xor \reg, \reg
.endm

.macro HEX_FILL reg
    mov \reg, rax
.endm

.macro HEX_GATHER reg
    or rcx, \reg
.endm

.macro HEX_ZEROIZE_ALL
    HEX_EACH HEX_CLEAR
.endm

// The nibble in \n as its lowercase digit, through \t: `9 - n` is negative
// exactly past nine, and its sign spread over the word adds the 0x27 that
// carries `'0' + 10` to `'a'`.
.macro HEX_NIBBLE_TO_DIGIT n, t
    mov \t, 9
    sub \t, \n
    sar \t, 8
    and \t, 0x27
    add \n, 0x30
    add \n, \t
.endm

// ============================================================================
// redoubt_hex_bytes_to_hex
// ============================================================================
//
// void redoubt_hex_bytes_to_hex(const uint8_t *src, size_t len, uint8_t *dst)
// rdi = src, rsi = len, rdx = dst, two digits written per byte.

.global FUNC(redoubt_hex_bytes_to_hex)
HIDDEN_FUNC(redoubt_hex_bytes_to_hex)
#if !defined(__APPLE__)
.type FUNC(redoubt_hex_bytes_to_hex), @function
#endif
.p2align 4
FUNC(redoubt_hex_bytes_to_hex):
    .cfi_startproc
    endbr64
    test rsi, rsi
    jz .Lencode_wipe
.Lencode_next:
    movzx eax, byte ptr [rdi]
    mov ecx, eax
    shr ecx, 4
    and eax, 15
    HEX_NIBBLE_TO_DIGIT ecx, r8d
    HEX_NIBBLE_TO_DIGIT eax, r8d
    mov [rdx], cl
    mov [rdx + 1], al
    add rdi, 1
    add rdx, 2
    sub rsi, 1
    jnz .Lencode_next
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
// rdi = src, rsi = len (even), rdx = dst (len / 2), rcx = answer; one when
// every character was a hex digit, and `dst` all zeros when not.

.global FUNC(redoubt_hex_hex_to_bytes)
HIDDEN_FUNC(redoubt_hex_hex_to_bytes)
#if !defined(__APPLE__)
.type FUNC(redoubt_hex_hex_to_bytes), @function
#endif
.p2align 4
FUNC(redoubt_hex_hex_to_bytes):
    .cfi_startproc
    endbr64
    xor r9d, r9d
    xor r11d, r11d
    cmp r11, rsi
    je .Ldecode_checked
.Ldecode_check_next:
    movzx eax, byte ptr [rdi + r11]
    mov r8d, eax
    xor r8d, 0x30
    cmp r8d, 10
    sbb r10d, r10d
    and eax, 0xDF
    sub eax, 65
    cmp eax, 6
    sbb r8d, r8d
    or r10d, r8d
    not r10d
    and r10d, 1
    or r9d, r10d
    add r11, 1
    cmp r11, rsi
    jne .Ldecode_check_next
.Ldecode_checked:
    shr rsi, 1
    cmp r9d, 1
    sbb r9d, r9d
    xor r11d, r11d
    cmp r11, rsi
    je .Ldecode_answer
.Ldecode_next:
    movzx eax, byte ptr [rdi + r11 * 2]
    mov r8d, eax
    xor r8d, 0x30
    cmp r8d, 10
    sbb r10d, r10d
    and r8d, r10d
    not r10d
    and eax, 0xDF
    sub eax, 55
    and eax, r10d
    or eax, r8d
    shl eax, 4
    and eax, r9d
    mov [rdx + r11], al
    movzx eax, byte ptr [rdi + r11 * 2 + 1]
    mov r8d, eax
    xor r8d, 0x30
    cmp r8d, 10
    sbb r10d, r10d
    and r8d, r10d
    not r10d
    and eax, 0xDF
    sub eax, 55
    and eax, r10d
    or eax, r8d
    and eax, r9d
    or [rdx + r11], al
    add r11, 1
    cmp r11, rsi
    jne .Ldecode_next
.Ldecode_answer:
    test r9d, r9d
    setnz byte ptr [rcx]
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
// Zero when every register in the budget is empty. rax is gathered before it
// carries the answer; no argument, because rdi is one of the registers asked
// about.
.global FUNC(redoubt_hex_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hex_registers_are_zeroized)
.p2align 4
FUNC(redoubt_hex_registers_are_zeroized):
    HEX_EACH HEX_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global FUNC(redoubt_hex_dirty_registers)
HIDDEN_FUNC(redoubt_hex_dirty_registers)
.p2align 4
FUNC(redoubt_hex_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    HEX_EACH HEX_FILL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
