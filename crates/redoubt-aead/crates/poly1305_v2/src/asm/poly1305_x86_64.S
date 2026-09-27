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
