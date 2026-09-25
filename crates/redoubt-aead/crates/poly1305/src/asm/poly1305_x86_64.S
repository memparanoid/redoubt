// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 - x86_64 (SysV ABI) Implementation
//
// The floor is the x86-64 baseline: scalar integer instructions only, nothing
// detected at runtime.
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes arguments in other registers and
//     keeps rsi and rdi callee-saved. The build script compiles no assembly there.
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
// - System V AMD64 ABI, section 3.2.3

.intel_syntax noprefix
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
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through this list. A register added to the wipe
// and missing from the verifier is a register nothing looks at, silently.
//
// SysV AMD64 makes rax, rcx, rdx, rsi, rdi and r8-r11 caller-saved, and rbx,
// rbp and r12-r15 callee-saved. Nothing here writes one of the second kind:
// saving one would spill the caller's value into this file's stack. Nothing
// here writes a vector register.
.macro POLY1305_EACH op
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

.macro POLY1305_CLEAR reg
    xor \reg, \reg
.endm

// Copies what rax already holds into each, itself included. Used by the probe.
.macro POLY1305_FILL reg
    mov \reg, rax
.endm

// Folds each into rcx, which is in the list and so contributes its own value.
// Used by the probe.
.macro POLY1305_GATHER reg
    or rcx, \reg
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
//            160..167   padding
//
// FRAME is congruent to eight modulo sixteen, which puts rsp back on a boundary
// after `call`.
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
.set FRAME, 168

// One limb's twenty-six bits.
.set LIMB, 0x3ffffff

// ============================================================================
// Frame wipe
// ============================================================================

// Every qword of the frame, padding included, then the frame given back.
.macro POLY1305_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 8
        mov qword ptr [rsp + _empty_at], 0
        .set _empty_at, _empty_at + 8
    .endr
    add rsp, FRAME
.endm

// One of the twenty-five products, added into rax. `five` scales the limb of
// `r` by five, for a product that lands past 2^130 and wraps modulo 2^130 - 5.
.macro POLY1305_TERM at, limb, five
    mov ecx, [r11 + 4*\limb]
    .if \five
    lea rcx, [rcx + rcx*4]
    .endif
    imul rcx, qword ptr [rsp + ACC + 8*\at]
    add rax, rcx
.endm

// The first product of a sum, which starts rax rather than adding to it.
.macro POLY1305_FIRST at, limb, five
    mov ecx, [r11 + 4*\limb]
    .if \five
    lea rcx, [rcx + rcx*4]
    .endif
    mov rax, rcx
    imul rax, qword ptr [rsp + ACC + 8*\at]
.endm

// acc = acc * r modulo 2^130 - 5: the products summed by the power of 2^26
// they land on, then every limb carried back under twenty-six bits.
.macro POLY1305_MULTIPLY
    mov r11, [rsp + RPTR]

    POLY1305_FIRST 0, 0, 0
    POLY1305_TERM  1, 4, 1
    POLY1305_TERM  2, 3, 1
    POLY1305_TERM  3, 2, 1
    POLY1305_TERM  4, 1, 1
    mov [rsp + SUMS], rax

    POLY1305_FIRST 0, 1, 0
    POLY1305_TERM  1, 0, 0
    POLY1305_TERM  2, 4, 1
    POLY1305_TERM  3, 3, 1
    POLY1305_TERM  4, 2, 1
    mov [rsp + SUMS + 8], rax

    POLY1305_FIRST 0, 2, 0
    POLY1305_TERM  1, 1, 0
    POLY1305_TERM  2, 0, 0
    POLY1305_TERM  3, 4, 1
    POLY1305_TERM  4, 3, 1
    mov [rsp + SUMS + 16], rax

    POLY1305_FIRST 0, 3, 0
    POLY1305_TERM  1, 2, 0
    POLY1305_TERM  2, 1, 0
    POLY1305_TERM  3, 0, 0
    POLY1305_TERM  4, 4, 1
    mov [rsp + SUMS + 24], rax

    POLY1305_FIRST 0, 4, 0
    POLY1305_TERM  1, 3, 0
    POLY1305_TERM  2, 2, 0
    POLY1305_TERM  3, 1, 0
    POLY1305_TERM  4, 0, 0
    mov [rsp + SUMS + 32], rax

    POLY1305_CARRY SUMS

    .irp offset,0,8,16,24,32
        mov rax, [rsp + SUMS + \offset]
        mov [rsp + ACC + \offset], rax
    .endr
.endm

// Every limb of the five at `at` carried back under twenty-six bits; what runs
// off the top comes back into the first worth five.
.macro POLY1305_CARRY at
    mov r8d, LIMB

    .irp step,0,8,16,24
        mov rax, [rsp + \at + \step]
        mov rcx, rax
        shr rcx, 26
        add [rsp + \at + \step + 8], rcx
        and eax, r8d
        mov [rsp + \at + \step], rax
    .endr

    mov rax, [rsp + \at + 32]
    mov rcx, rax
    shr rcx, 26
    lea rcx, [rcx + rcx*4]
    add [rsp + \at], rcx
    and eax, r8d
    mov [rsp + \at + 32], rax

    mov rax, [rsp + \at]
    mov rcx, rax
    shr rcx, 26
    add [rsp + \at + 8], rcx
    and eax, r8d
    mov [rsp + \at], rax
.endm

// acc += the sixteen bytes at `src`, with `hibit` above them, then acc *= r.
// `src` is not written.
.macro POLY1305_BLOCK src, hibit
    mov rax, [\src]
    mov rdx, [\src + 8]
    mov r8d, LIMB

    mov r9, rax
    and r9d, r8d
    add [rsp + ACC], r9

    mov r9, rax
    shr r9, 26
    and r9d, r8d
    add [rsp + ACC + 8], r9

    mov r9, rax
    shr r9, 52
    mov r10, rdx
    shl r10, 12
    or r9, r10
    and r9d, r8d
    add [rsp + ACC + 16], r9

    mov r9, rdx
    shr r9, 14
    and r9d, r8d
    add [rsp + ACC + 24], r9

    mov r9, rdx
    shr r9, 40
    .if \hibit
    or r9, 0x1000000
    .endif
    add [rsp + ACC + 32], r9

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
// Parameters (SysV ABI):
//   rdi: r (written), rsi: s (written), rdx: key (read only)
//
// No frame: the clamp fits in the budget.
.p2align 4
.globl FUNC(redoubt_poly1305_init)
HIDDEN_FUNC(redoubt_poly1305_init)
#if !defined(__APPLE__)
.type FUNC(redoubt_poly1305_init), @function
#endif
FUNC(redoubt_poly1305_init):
    // RFC 8439's clamp, as one AND over each half of `r`.
    mov rax, [rdx]
    mov rcx, [rdx + 8]
    mov r8,  0x0ffffffc0fffffff
    and rax, r8
    mov r8,  0x0ffffffc0ffffffc
    and rcx, r8

    mov r8d, 0x3ffffff

    mov r9, rax
    and r9d, r8d
    mov [rdi], r9d

    mov r9, rax
    shr r9, 26
    and r9d, r8d
    mov [rdi + 4], r9d

    mov r9, rax
    shr r9, 52
    mov r10, rcx
    shl r10, 12
    or  r9, r10
    and r9d, r8d
    mov [rdi + 8], r9d

    mov r9, rcx
    shr r9, 14
    and r9d, r8d
    mov [rdi + 12], r9d

    mov r9, rcx
    shr r9, 40
    mov [rdi + 16], r9d

    mov rax, [rdx + 16]
    mov rcx, [rdx + 24]
    mov [rsi], rax
    mov [rsi + 8], rcx

    POLY1305_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_poly1305_init), .-FUNC(redoubt_poly1305_init)
#endif

// ============================================================================
// poly1305_update
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_update(uint64_t acc[5], const uint32_t r[5],
//                                uint8_t block[16], size_t *filled,
//                                const uint8_t *said, size_t said_len);
//
// Parameters (SysV ABI):
//   rdi: acc (read and written), rsi: r (read only), rdx: block (read and
//   written), rcx: filled (read and written), r8: said (read only),
//   r9: said_len
//
// Whole blocks are read where they lie; only a tail short of a block is copied
// into the caller's `block`.
.p2align 4
.globl FUNC(redoubt_poly1305_update)
HIDDEN_FUNC(redoubt_poly1305_update)
#if !defined(__APPLE__)
.type FUNC(redoubt_poly1305_update), @function
#endif
FUNC(redoubt_poly1305_update):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial over everything counted so
// ║ far, and SUMS its products by `r`. The partial block is not in here —
// ║ it is the caller's, written where the caller keeps it, and emptied
// ║ there as soon as the block it completes has been counted.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + ACCPTR], rdi
    mov [rsp + RPTR], rsi
    mov [rsp + BLOCKPTR], rdx
    mov [rsp + FILLEDPTR], rcx
    mov [rsp + SAID], r8
    mov [rsp + LEN], r9

    .irp offset,0,8,16,24,32
        mov rax, [rdi + \offset]
        mov [rsp + ACC + \offset], rax
    .endr

    mov rcx, [rcx]
    test rcx, rcx
    jz .Lupdate_stream

    mov rax, 16
    sub rax, rcx
    mov rdx, [rsp + LEN]
    cmp rax, rdx
    jbe .Lupdate_fill
    mov rax, rdx
.Lupdate_fill:
    test rax, rax
    jz .Lupdate_flush

    mov rsi, [rsp + SAID]
    mov rdi, [rsp + BLOCKPTR]
    add rdi, rcx
    xor rdx, rdx
.Lupdate_fill_byte:
    mov r8b, [rsi + rdx]
    mov [rdi + rdx], r8b
    inc rdx
    cmp rdx, rax
    jb .Lupdate_fill_byte

    add rcx, rax
    mov rdx, [rsp + FILLEDPTR]
    mov [rdx], rcx
    add [rsp + SAID], rax
    sub [rsp + LEN], rax

.Lupdate_flush:
    cmp rcx, 16
    jne .Lupdate_stream

    mov rsi, [rsp + BLOCKPTR]
    POLY1305_BLOCK rsi, 1

    // Counted, so emptied: the next tail may not cover all of it.
    mov rsi, [rsp + BLOCKPTR]
    mov qword ptr [rsi], 0
    mov qword ptr [rsi + 8], 0
    mov rdx, [rsp + FILLEDPTR]
    mov qword ptr [rdx], 0

.Lupdate_stream:
    cmp qword ptr [rsp + LEN], 16
    jb .Lupdate_tail
    mov rsi, [rsp + SAID]
    POLY1305_BLOCK rsi, 1
    add qword ptr [rsp + SAID], 16
    sub qword ptr [rsp + LEN], 16
    jmp .Lupdate_stream

.Lupdate_tail:
    mov rcx, [rsp + LEN]
    test rcx, rcx
    jz .Lupdate_done

    mov rsi, [rsp + SAID]
    mov rdi, [rsp + BLOCKPTR]
    xor rdx, rdx
.Lupdate_keep_byte:
    mov r8b, [rsi + rdx]
    mov [rdi + rdx], r8b
    inc rdx
    cmp rdx, rcx
    jb .Lupdate_keep_byte

    mov rdx, [rsp + FILLEDPTR]
    mov [rdx], rcx

.Lupdate_done:
    mov r9, [rsp + ACCPTR]
    .irp offset,0,8,16,24,32
        mov rax, [rsp + ACC + \offset]
        mov [r9 + \offset], rax
    .endr

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_poly1305_update), .-FUNC(redoubt_poly1305_update)
#endif

// ============================================================================
// poly1305_finalize
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_finalize(uint64_t acc[5], const uint32_t r[5],
//                                  const uint8_t s[16], const uint8_t *said,
//                                  size_t said_len, uint8_t out[16]);
//
// Parameters (SysV ABI):
//   rdi: acc (read and written), rsi: r (read only), rdx: s (read only),
//   rcx: said (read only), r8: said_len, r9: out (written)
.p2align 4
.globl FUNC(redoubt_poly1305_finalize)
HIDDEN_FUNC(redoubt_poly1305_finalize)
#if !defined(__APPLE__)
.type FUNC(redoubt_poly1305_finalize), @function
#endif
FUNC(redoubt_poly1305_finalize):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial and then the number the tag
// ║ is made from, SUMS its products by `r`, and BLOCK the last bytes of the
// ║ message with the marker written after them. That last one is message in
// ║ the clear, and it is here rather than in the caller's buffer because a
// ║ caller that handed over a whole message has no buffer to pad.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + ACCPTR], rdi
    mov [rsp + RPTR], rsi
    mov [rsp + SPTR], rdx
    mov [rsp + SAID], rcx
    mov [rsp + LEN], r8
    mov [rsp + OUT], r9

    .irp offset,0,8,16,24,32
        mov rax, [rdi + \offset]
        mov [rsp + ACC + \offset], rax
    .endr

.Lwhole:
    cmp qword ptr [rsp + LEN], 16
    jb .Ltail
    mov rsi, [rsp + SAID]
    POLY1305_BLOCK rsi, 1
    add qword ptr [rsp + SAID], 16
    sub qword ptr [rsp + LEN], 16
    jmp .Lwhole

.Ltail:
    mov rcx, [rsp + LEN]
    test rcx, rcx
    jz .Lwritten_back

    mov qword ptr [rsp + BLOCK], 0
    mov qword ptr [rsp + BLOCK + 8], 0
    mov rsi, [rsp + SAID]
    xor edx, edx
.Lcopy:
    mov al, [rsi + rdx]
    mov [rsp + rdx + BLOCK], al
    inc rdx
    cmp rdx, rcx
    jb .Lcopy

    // The bit above the message, so that a tail ending in zeros does not read
    // as a shorter message.
    mov byte ptr [rsp + rcx + BLOCK], 1
    lea rsi, [rsp + BLOCK]
    POLY1305_BLOCK rsi, 0

.Lwritten_back:
    // Written back before the reduction below: the caller's accumulator is the
    // polynomial, not the tag.
    mov r9, [rsp + ACCPTR]
    .irp offset,0,8,16,24,32
        mov rax, [rsp + ACC + \offset]
        mov [r9 + \offset], rax
    .endr

    POLY1305_CARRY ACC

    mov r8d, LIMB

    // acc + 5 into SUMS: it carries past bit 130 exactly when acc is at least
    // 2^130 - 5.
    mov rax, [rsp + ACC]
    add rax, 5
    mov rcx, rax
    shr rcx, 26
    and eax, r8d
    mov [rsp + SUMS], rax

    .irp offset,8,16,24
        mov rax, [rsp + ACC + \offset]
        add rax, rcx
        mov rcx, rax
        shr rcx, 26
        and eax, r8d
        mov [rsp + SUMS + \offset], rax
    .endr

    // All ones in r10 if acc is below the modulus, all zeros if not, and r11
    // the opposite. A mask and not a branch: which one is a fact about the key.
    mov rax, [rsp + ACC + 32]
    add rax, rcx
    shr rax, 26
    sub rax, 1
    mov r10, rax
    mov r11, rax
    not r11

    .irp offset,0,8,16,24
        mov rax, [rsp + ACC + \offset]
        and rax, r10
        mov rcx, [rsp + SUMS + \offset]
        and rcx, r11
        or rax, rcx
        mov [rsp + ACC + \offset], rax
    .endr

    // acc - (2^130 - 5) has no fifth limb, so the fifth is kept only where acc
    // is.
    mov rax, [rsp + ACC + 32]
    and rax, r10
    mov [rsp + ACC + 32], rax

    // Five limbs of twenty-six bits into four words of thirty-two.
    mov rax, [rsp + ACC]
    mov rcx, [rsp + ACC + 8]
    mov rdx, rcx
    and edx, 0x3f
    shl rdx, 26
    or rax, rdx

    mov rsi, rcx
    shr rsi, 6
    mov rcx, [rsp + ACC + 16]
    mov rdx, rcx
    and edx, 0xfff
    shl rdx, 20
    or rsi, rdx

    mov rdi, rcx
    shr rdi, 12
    mov rcx, [rsp + ACC + 24]
    mov rdx, rcx
    and edx, 0x3ffff
    shl rdx, 14
    or rdi, rdx

    mov r8, rcx
    shr r8, 18
    mov rcx, [rsp + ACC + 32]
    and ecx, 0xffffff
    shl rcx, 8
    or r8, rcx

    // + s, modulo 2^128: the carry out of the fourth word is dropped.
    mov r9, [rsp + SPTR]
    mov ecx, [r9]
    add rax, rcx
    mov ecx, [r9 + 4]
    add rsi, rcx
    mov rdx, rax
    shr rdx, 32
    add rsi, rdx
    mov ecx, [r9 + 8]
    add rdi, rcx
    mov rdx, rsi
    shr rdx, 32
    add rdi, rdx
    mov ecx, [r9 + 12]
    add r8, rcx
    mov rdx, rdi
    shr rdx, 32
    add r8, rdx

    mov r9, [rsp + OUT]
    mov [r9], eax
    mov [r9 + 4], esi
    mov [r9 + 8], edi
    mov [r9 + 12], r8d

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_poly1305_finalize), .-FUNC(redoubt_poly1305_finalize)
#endif

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_poly1305_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because rdi is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_poly1305_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_registers_are_zeroized)
FUNC(redoubt_poly1305_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_dirty_registers)
FUNC(redoubt_poly1305_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    POLY1305_EACH POLY1305_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_poly1305_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `call`
//   leaves rsp where the previous callee found it, so the return address lands
//   in the same slot and `[rsp - \size, rsp)` is the frame that callee took.
//   Asked after the registers, never before: reading the frame takes registers.
//
// void redoubt_poly1305_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in rdi, marked and left.
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
    // An x86 address cannot subtract a register, so the index runs up from
    // minus the frame to zero.
    xor eax, eax
    mov rcx, -\size
1:
    or rax, [rsp + rcx]
    add rcx, 8
    jnz 1b
    ret

.p2align 4
.globl FUNC(redoubt_poly1305_dirty_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_dirty_frame_\name)
FUNC(redoubt_poly1305_dirty_frame_\name):
    sub rsp, \size
    // The frame is emptied before the byte goes in, so that what a verifier
    // finds is this byte and not a previous call's residue.
    xor ecx, ecx
2:
    mov qword ptr [rsp + rcx], 0
    add rcx, 8
    cmp rcx, \size
    jb 2b
    mov byte ptr [rsp + rdi], 0x5c
    add rsp, \size
    ret

.p2align 4
.globl FUNC(redoubt_poly1305_clean_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_clean_frame_\name)
FUNC(redoubt_poly1305_clean_frame_\name):
    sub rsp, \size
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
3:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, \size
    jb 3b
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
.section .note.GNU-stack,"",@progbits
#endif
