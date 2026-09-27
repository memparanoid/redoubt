// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 - x86_64 (SysV ABI) Implementation, radix 2^64
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
//
// FRAME is congruent to eight modulo sixteen, which puts rsp back on a boundary
// after `call`.
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
.set FRAME, 104

// ============================================================================
// Frame wipe
// ============================================================================

// Every qword of the frame, then the frame given back.
.macro POLY1305_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 8
        mov qword ptr [rsp + _empty_at], 0
        .set _empty_at, _empty_at + 8
    .endr
    add rsp, FRAME
.endm

// acc = acc * r, reduced only as far as the next block needs:
//
//   d0 = h0·r0 + h1·s1            in rdi:rsi
//   d1 = h0·r1 + h1·r0 + h2·s1    in r11:rcx
//   d2 = h2·r0                    in rax
//
// then carried into three words and the bits of the third above two folded
// back. h2 is a few bits, so its products fit a word and take `imul`.
.macro POLY1305_MULTIPLY
    mov r11, [rsp + RPTR]
    mov r8, [r11]
    mov r9, [r11 + 8]
    // s1 = r1 + r1/4. 2^130 is 5 modulo the prime and the clamp leaves the
    // bottom two bits of r1 empty, so a product with r1 that lands on 2^128
    // comes back as a product with s1.
    mov r10, r9
    shr r10, 2
    add r10, r9

    mov rax, [rsp + ACC]
    mul r8
    mov rsi, rax
    mov rdi, rdx
    mov rax, [rsp + ACC + 8]
    mul r10
    add rsi, rax
    adc rdi, rdx

    mov rax, [rsp + ACC]
    mul r9
    mov rcx, rax
    mov r11, rdx
    mov rax, [rsp + ACC + 8]
    mul r8
    add rcx, rax
    adc r11, rdx
    mov rax, [rsp + ACC + 16]
    imul rax, r10
    add rcx, rax
    adc r11, 0

    mov rax, [rsp + ACC + 16]
    imul rax, r8

    add rcx, rdi
    adc r11, 0
    add rax, r11

    // What stands at or above 2^130 comes back down worth five.
    mov rdx, rax
    shr rdx, 2
    lea rdx, [rdx + rdx*4]
    and rax, 3
    add rsi, rdx
    adc rcx, 0
    adc rax, 0

    mov [rsp + ACC], rsi
    mov [rsp + ACC + 8], rcx
    mov [rsp + ACC + 16], rax
.endm

// acc += the sixteen bytes at `src`, with `hibit` above them, then acc *= r.
// `src` is not written.
.macro POLY1305_BLOCK src, hibit
    mov rax, [\src]
    mov rdx, [\src + 8]
    add [rsp + ACC], rax
    adc [rsp + ACC + 8], rdx
    adc qword ptr [rsp + ACC + 16], \hibit

    POLY1305_MULTIPLY
.endm

// ============================================================================
// poly1305_init
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_v2_init(uint64_t r[2], uint8_t s[16],
//                                 const uint8_t key[32]);
//
// Parameters (SysV ABI):
//   rdi: r (written), rsi: s (written), rdx: key (read only)
//
// No frame: the clamp fits in the budget.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_init)
HIDDEN_FUNC(redoubt_poly1305_v2_init)
#if !defined(__APPLE__)
.type FUNC(redoubt_poly1305_v2_init), @function
#endif
FUNC(redoubt_poly1305_v2_init):
    // RFC 8439's clamp, as one AND over each half of `r`.
    mov rax, [rdx]
    mov rcx, [rdx + 8]
    mov r8,  0x0ffffffc0fffffff
    and rax, r8
    mov r8,  0x0ffffffc0ffffffc
    and rcx, r8
    mov [rdi], rax
    mov [rdi + 8], rcx

    mov rax, [rdx + 16]
    mov rcx, [rdx + 24]
    mov [rsi], rax
    mov [rsi + 8], rcx

    POLY1305_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_poly1305_v2_init), .-FUNC(redoubt_poly1305_v2_init)
#endif

// ============================================================================
// poly1305_update
// ============================================================================
//
// C signature:
//   void redoubt_poly1305_v2_update(uint64_t acc[3], const uint64_t r[2],
//                                   uint8_t block[16], size_t *filled,
//                                   const uint8_t *said, size_t said_len);
//
// Parameters (SysV ABI):
//   rdi: acc (read and written), rsi: r (read only), rdx: block (read and
//   written), rcx: filled (read and written), r8: said (read only),
//   r9: said_len
//
// Whole blocks are read where they lie; only a tail short of a block is copied
// into the caller's `block`.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_update)
HIDDEN_FUNC(redoubt_poly1305_v2_update)
#if !defined(__APPLE__)
.type FUNC(redoubt_poly1305_v2_update), @function
#endif
FUNC(redoubt_poly1305_v2_update):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial over everything counted so
// ║ far. The partial block is not in here — it is the caller's, written
// ║ where the caller keeps it, and emptied there as soon as the block it
// ║ completes has been counted.
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

    .irp offset,0,8,16
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
    .irp offset,0,8,16
        mov rax, [rsp + ACC + \offset]
        mov [r9 + \offset], rax
    .endr

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_poly1305_v2_update), .-FUNC(redoubt_poly1305_v2_update)
#endif

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_poly1305_v2_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because rdi is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_v2_registers_are_zeroized)
FUNC(redoubt_poly1305_v2_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_poly1305_v2_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_v2_dirty_registers)
FUNC(redoubt_poly1305_v2_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    POLY1305_EACH POLY1305_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_poly1305_v2_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `call`
//   leaves rsp where the previous callee found it, so the return address lands
//   in the same slot and `[rsp - \size, rsp)` is the frame that callee took.
//   Asked after the registers, never before: reading the frame takes registers.
//
// void redoubt_poly1305_v2_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in rdi, marked and left.
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
.globl FUNC(redoubt_poly1305_v2_dirty_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_v2_dirty_frame_\name)
FUNC(redoubt_poly1305_v2_dirty_frame_\name):
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
.globl FUNC(redoubt_poly1305_v2_clean_frame_\name)
HIDDEN_FUNC(redoubt_poly1305_v2_clean_frame_\name)
FUNC(redoubt_poly1305_v2_clean_frame_\name):
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
