// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// A copy, a swap, a UTF-8 check and a zero check that leave nothing in a
// register — x86-64.
//
// Platforms: Linux and macOS, SysV. Windows is not built.
// No runtime feature detection. The floor is SSE2: movdqu, movdqa, pxor, por,
//   psrldq, punpcklqdq, movq. `endbr64` is a NOP where CET is off.
// Legacy SSE encodings only: a legacy write to xmmN leaves the upper lanes of
//   ymmN/zmmN as they were and never reaches xmm16-31, so `pxor` reaches every
//   byte these routines wrote.
// Crossing: pointers to the caller's storage and lengths. Nothing is returned;
//   each check's answer is one byte written through a pointer.
// Branches: the copy, the swap and the zero check on the length only. The UTF-8
//   check on the bytes, stopping at the first that is not UTF-8: not constant
//   time.
// Not answered for: what other code left in registers, the ranges themselves,
//   a signal frame, a core dump, swap, ptrace, or a fault before the wipe.
// No routine takes a frame, so the probe has no stack half.

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
.macro MEM_EACH_GENERAL op
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

.macro MEM_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        \op xmm\reg
    .endr
.endm

.macro MEM_CLEAR_GENERAL reg
    xor \reg, \reg
.endm

.macro MEM_CLEAR_VECTOR reg
    pxor \reg, \reg
.endm

.macro MEM_FILL_GENERAL reg
    mov \reg, rax
.endm

.macro MEM_FILL_VECTOR reg
    movdqa \reg, xmm0
.endm

.macro MEM_GATHER_GENERAL reg
    or rcx, \reg
.endm

.macro MEM_GATHER_VECTOR reg
    por xmm0, \reg
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
// rdi = src, rsi = dst, rdx = bytes; the ranges disjoint, DF clear.

.global FUNC(redoubt_mem_copy_nonoverlapping)
HIDDEN_FUNC(redoubt_mem_copy_nonoverlapping)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_copy_nonoverlapping), @function
#endif
.p2align 4
FUNC(redoubt_mem_copy_nonoverlapping):
    .cfi_startproc
    endbr64
    cmp rdx, 32
    ja .Lcopy_bulk
    cmp rdx, 16
    jbe .Lcopy_up_to_16
    mov rax, [rdi]
    mov rcx, [rdi + 8]
    mov [rsi], rax
    mov [rsi + 8], rcx
    mov rax, [rdi + rdx - 16]
    mov rcx, [rdi + rdx - 8]
    mov [rsi + rdx - 16], rax
    mov [rsi + rdx - 8], rcx
    jmp .Lcopy_wipe
.Lcopy_up_to_16:
    cmp rdx, 8
    jb .Lcopy_up_to_8
    mov rax, [rdi]
    mov rcx, [rdi + rdx - 8]
    mov [rsi], rax
    mov [rsi + rdx - 8], rcx
    jmp .Lcopy_wipe
.Lcopy_up_to_8:
    cmp rdx, 4
    jb .Lcopy_up_to_4
    mov eax, [rdi]
    mov ecx, [rdi + rdx - 4]
    mov [rsi], eax
    mov [rsi + rdx - 4], ecx
    jmp .Lcopy_wipe
.Lcopy_up_to_4:
    cmp rdx, 2
    jb .Lcopy_up_to_2
    movzx eax, word ptr [rdi]
    movzx ecx, word ptr [rdi + rdx - 2]
    mov [rsi], ax
    mov [rsi + rdx - 2], cx
    jmp .Lcopy_wipe
.Lcopy_up_to_2:
    test rdx, rdx
    jz .Lcopy_wipe
    movzx eax, byte ptr [rdi]
    mov [rsi], al
    jmp .Lcopy_wipe
.Lcopy_bulk:
    cmp rdx, 512
    ja .Lcopy_string
    cmp rdx, 64
    jbe .Lcopy_32
.Lcopy_64:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqu [rsi], xmm0
    movdqu [rsi + 16], xmm1
    movdqu xmm0, [rdi + 32]
    movdqu xmm1, [rdi + 48]
    movdqu [rsi + 32], xmm0
    movdqu [rsi + 48], xmm1
    add rdi, 64
    add rsi, 64
    sub rdx, 64
    cmp rdx, 64
    ja .Lcopy_64
    cmp rdx, 32
    jbe .Lcopy_last_32
.Lcopy_32:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqu [rsi], xmm0
    movdqu [rsi + 16], xmm1
    add rdi, 32
    add rsi, 32
    sub rdx, 32
.Lcopy_last_32:
    // rdx may be under 32 here, but only after a chunk was copied, so the
    // window reaches back over copied bytes and never before the range.
    movdqu xmm0, [rdi + rdx - 32]
    movdqu xmm1, [rdi + rdx - 16]
    movdqu [rsi + rdx - 32], xmm0
    movdqu [rsi + rdx - 16], xmm1
    jmp .Lcopy_wipe
.Lcopy_string:
    // Memory to memory, through no register. Past 512 bytes it was the faster
    // on the one machine it was measured on.
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rax
    mov rcx, rdx
    rep movsb
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
// rdi = a, rsi = b, rdx = bytes; the ranges disjoint.

.global FUNC(redoubt_mem_swap_nonoverlapping)
HIDDEN_FUNC(redoubt_mem_swap_nonoverlapping)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_swap_nonoverlapping), @function
#endif
.p2align 4
FUNC(redoubt_mem_swap_nonoverlapping):
    .cfi_startproc
    endbr64
    cmp rdx, 32
    jb .Lswap_16
.Lswap_32:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqu xmm2, [rsi]
    movdqu xmm3, [rsi + 16]
    movdqu [rdi], xmm2
    movdqu [rdi + 16], xmm3
    movdqu [rsi], xmm0
    movdqu [rsi + 16], xmm1
    add rdi, 32
    add rsi, 32
    sub rdx, 32
    cmp rdx, 32
    jae .Lswap_32
.Lswap_16:
    test dl, 16
    jz .Lswap_8
    movdqu xmm0, [rdi]
    movdqu xmm2, [rsi]
    movdqu [rdi], xmm2
    movdqu [rsi], xmm0
    add rdi, 16
    add rsi, 16
.Lswap_8:
    test dl, 8
    jz .Lswap_4
    mov rax, [rdi]
    mov rcx, [rsi]
    mov [rdi], rcx
    mov [rsi], rax
    add rdi, 8
    add rsi, 8
.Lswap_4:
    test dl, 4
    jz .Lswap_2
    mov eax, [rdi]
    mov ecx, [rsi]
    mov [rdi], ecx
    mov [rsi], eax
    add rdi, 4
    add rsi, 4
.Lswap_2:
    test dl, 2
    jz .Lswap_1
    movzx eax, word ptr [rdi]
    movzx ecx, word ptr [rsi]
    mov [rdi], cx
    mov [rsi], ax
    add rdi, 2
    add rsi, 2
.Lswap_1:
    test dl, 1
    jz .Lswap_wipe
    movzx eax, byte ptr [rdi]
    movzx ecx, byte ptr [rsi]
    mov [rdi], cl
    mov [rsi], al
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
// rdi = bytes, rsi = len, rdx = answer; one or zero, by RFC 3629.

.global FUNC(redoubt_mem_is_utf8)
HIDDEN_FUNC(redoubt_mem_is_utf8)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_is_utf8), @function
#endif
.p2align 4
FUNC(redoubt_mem_is_utf8):
    .cfi_startproc
    endbr64
    test rsi, rsi
    jz .Lutf8_valid
.Lutf8_next:
    movzx ecx, byte ptr [rdi]
    cmp ecx, 0x80
    jb .Lutf8_one
    cmp ecx, 0xC2
    jb .Lutf8_invalid
    cmp ecx, 0xE0
    jb .Lutf8_two
    cmp ecx, 0xF0
    jb .Lutf8_three
    cmp ecx, 0xF5
    jb .Lutf8_four
    jmp .Lutf8_invalid
.Lutf8_one:
    add rdi, 1
    sub rsi, 1
    jnz .Lutf8_next
    jmp .Lutf8_valid
.Lutf8_two:
    cmp rsi, 2
    jb .Lutf8_invalid
    movzx r8d, byte ptr [rdi + 1]
    sub r8d, 0x80
    cmp r8d, 0x3F
    ja .Lutf8_invalid
    add rdi, 2
    sub rsi, 2
    jnz .Lutf8_next
    jmp .Lutf8_valid
.Lutf8_three:
    cmp rsi, 3
    jb .Lutf8_invalid
    // RFC 3629: after E0 only A0..BF (no overlong), after ED only 80..9F (no
    // surrogate).
    mov r9d, 0x80
    mov r10d, 0xBF
    cmp ecx, 0xE0
    jne 1f
    mov r9d, 0xA0
1:  cmp ecx, 0xED
    jne 2f
    mov r10d, 0x9F
2:  movzx r8d, byte ptr [rdi + 1]
    cmp r8d, r9d
    jb .Lutf8_invalid
    cmp r8d, r10d
    ja .Lutf8_invalid
    movzx r8d, byte ptr [rdi + 2]
    sub r8d, 0x80
    cmp r8d, 0x3F
    ja .Lutf8_invalid
    add rdi, 3
    sub rsi, 3
    jnz .Lutf8_next
    jmp .Lutf8_valid
.Lutf8_four:
    cmp rsi, 4
    jb .Lutf8_invalid
    // RFC 3629: after F0 only 90..BF (no overlong), after F4 only 80..8F
    // (nothing past U+10FFFF).
    mov r9d, 0x80
    mov r10d, 0xBF
    cmp ecx, 0xF0
    jne 1f
    mov r9d, 0x90
1:  cmp ecx, 0xF4
    jne 2f
    mov r10d, 0x8F
2:  movzx r8d, byte ptr [rdi + 1]
    cmp r8d, r9d
    jb .Lutf8_invalid
    cmp r8d, r10d
    ja .Lutf8_invalid
    movzx r8d, byte ptr [rdi + 2]
    sub r8d, 0x80
    cmp r8d, 0x3F
    ja .Lutf8_invalid
    movzx r8d, byte ptr [rdi + 3]
    sub r8d, 0x80
    cmp r8d, 0x3F
    ja .Lutf8_invalid
    add rdi, 4
    sub rsi, 4
    jnz .Lutf8_next
    // The answer goes out through rdx before the wipe empties it.
.Lutf8_valid:
    mov byte ptr [rdx], 1
    jmp .Lutf8_wipe
.Lutf8_invalid:
    mov byte ptr [rdx], 0
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
// rdi = bytes, rsi = len, rdx = answer; one when every byte is zero.

.global FUNC(redoubt_mem_is_zeroized)
HIDDEN_FUNC(redoubt_mem_is_zeroized)
#if !defined(__APPLE__)
.type FUNC(redoubt_mem_is_zeroized), @function
#endif
.p2align 4
FUNC(redoubt_mem_is_zeroized):
    .cfi_startproc
    endbr64
    xor eax, eax
    test rsi, rsi
    jz .Lzero_answer
.Lzero_next:
    movzx ecx, byte ptr [rdi]
    or eax, ecx
    add rdi, 1
    sub rsi, 1
    jnz .Lzero_next
    // The answer goes out through rdx before the wipe empties it.
.Lzero_answer:
    test eax, eax
    sete byte ptr [rdx]
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
// folded first, so rax is read before it carries the answer; no argument,
// because rdi is one of the registers asked about.
.global FUNC(redoubt_mem_registers_are_zeroized)
HIDDEN_FUNC(redoubt_mem_registers_are_zeroized)
.p2align 4
FUNC(redoubt_mem_registers_are_zeroized):
    MEM_EACH_GENERAL MEM_GATHER_GENERAL
    MEM_EACH_VECTOR MEM_GATHER_VECTOR
    movdqa xmm1, xmm0
    psrldq xmm1, 8
    por xmm0, xmm1
    movq rax, xmm0
    or rax, rcx
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global FUNC(redoubt_mem_dirty_registers)
HIDDEN_FUNC(redoubt_mem_dirty_registers)
.p2align 4
FUNC(redoubt_mem_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    punpcklqdq xmm0, xmm0
    MEM_EACH_VECTOR MEM_FILL_VECTOR
    MEM_EACH_GENERAL MEM_FILL_GENERAL
    ret

// The low half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only be those halves.
.global FUNC(redoubt_mem_dirty_vector_low)
HIDDEN_FUNC(redoubt_mem_dirty_vector_low)
FUNC(redoubt_mem_dirty_vector_low):
    MEM_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    xor eax, eax
    MEM_EACH_VECTOR MEM_FILL_VECTOR
    ret

// The high half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only come through its
// fold.
.global FUNC(redoubt_mem_dirty_vector_high)
HIDDEN_FUNC(redoubt_mem_dirty_vector_high)
FUNC(redoubt_mem_dirty_vector_high):
    MEM_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    pslldq xmm0, 8
    xor eax, eax
    MEM_EACH_VECTOR MEM_FILL_VECTOR
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
