// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ChaCha20, HChaCha20 and XChaCha20 - x86_64 (SysV ABI) Implementation
//
// Baseline x86_64. No SSE, no AVX, no AVX-512, nothing to detect at runtime:
// the whole of it is scalar 32-bit integer arithmetic. That is not the fastest
// ChaCha20 anybody has written and it is not meant to be — a vectorized one
// needs a runtime check, a second and third copy of the rounds, and a wipe
// written once per register file. This one is the same code on every machine
// that runs it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - Four working words at a time in caller-saved GPRs
//   - One explicit 160-byte frame, wiped on every exit
//   - No callee-saved register is touched
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes its first arguments in rcx, rdx,
//     r8 and r9 and reserves rsi, rdi and xmm6-xmm15 as callee-saved. This
//     file is SysV throughout. The build script compiles no assembly there and
//     the crate falls back to the Rust, which answers the same and promises
//     less.
//
// What crosses into here, and what does not:
//   Every argument is a pointer to storage the caller declared, and nothing is
//   returned. A returned value leaves in a register, and a register carrying
//   the answer out is a register the wipe below cannot touch. A length and a
//   counter arrive by value because neither is a secret and both are known to
//   anybody watching the call.
//
// What this cannot answer for:
//   The state words are written to the frame this file named and wiped. That
//   is a statement about this file, not about the machine. When a signal is
//   delivered the kernel writes the whole register context to a frame on the
//   user stack, wherever in the rounds that happens, and nothing in user space
//   wipes that frame on the way back. The same goes for a core dump, for a page
//   that reached swap, and for anything ptrace can read. None of those are
//   reachable from here, and none are made worse by this being assembly: the
//   Rust has every one of them too.
//
// References:
// - RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, sections 2.1 to 2.4
// - draft-irtf-cfrg-xchacha, XChaCha: eXtended-nonce ChaCha, section 2.2
// - System V AMD64 ABI, section 3.2.3 (parameter passing)

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
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
//
// No callee-saved or SIMD register is used. The flags are overwritten by the
// final xor too. No register leaves carrying a result: outputs are pointers.
//
.macro CHACHA_ZEROIZE_ALL
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8,  r8
    xor r9,  r9
    xor r10, r10
    xor r11, r11
.endm

// ============================================================================
// Frame layout — 160 bytes, entirely above rsp
// ============================================================================
//
//   INITIAL   0..63    state before the rounds, including an XChaCha subkey
//   WORK     64..127   state during the rounds, then one keystream block
//   OUTPUT  128..135   destination pointer
//   LENGTH  136..143   remaining byte count
//   MODE    144..151   nonce length; temporarily the XChaCha nonce pointer
//   COUNTER 152..159   starting counter, needed across HChaCha for XChaCha
//
// Four working words at a time fit in eax, ecx, edx and r8d. Everything else
// lives here. No pushes, calls, red-zone writes or implicit spills.
//
.set INITIAL, 0
.set WORK, 64
.set OUTPUT, 128
.set LENGTH, 136
.set MODE, 144
.set COUNTER, 152
.set FRAME, 160

.macro CHACHA_EMPTY_FRAME
    .irp offset,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152
        mov qword ptr [rsp + \offset], 0
    .endr
    add rsp, FRAME
.endm

// RFC 8439 §2.1. Addresses and rotations are fixed, independent of the state.
.macro CHACHA_QUARTER a,b,c,d
    mov eax, [rsp + WORK + 4*\a]
    mov ecx, [rsp + WORK + 4*\b]
    mov edx, [rsp + WORK + 4*\c]
    mov r8d, [rsp + WORK + 4*\d]

    add eax, ecx
    xor r8d, eax
    rol r8d, 16
    add edx, r8d
    xor ecx, edx
    rol ecx, 12
    add eax, ecx
    xor r8d, eax
    rol r8d, 8
    add edx, r8d
    xor ecx, edx
    rol ecx, 7

    mov [rsp + WORK + 4*\a], eax
    mov [rsp + WORK + 4*\b], ecx
    mov [rsp + WORK + 4*\c], edx
    mov [rsp + WORK + 4*\d], r8d
.endm

.macro CHACHA_ROUNDS
    mov r9d, 10
Lrounds\@:
    CHACHA_QUARTER 0,4,8,12
    CHACHA_QUARTER 1,5,9,13
    CHACHA_QUARTER 2,6,10,14
    CHACHA_QUARTER 3,7,11,15
    CHACHA_QUARTER 0,5,10,15
    CHACHA_QUARTER 1,6,11,12
    CHACHA_QUARTER 2,7,8,13
    CHACHA_QUARTER 3,4,9,14
    dec r9d
    jnz Lrounds\@
.endm

.macro CHACHA_CONSTANTS at
    mov dword ptr [rsp + \at],      0x61707865
    mov dword ptr [rsp + \at + 4],  0x3320646e
    mov dword ptr [rsp + \at + 8],  0x79622d32
    mov dword ptr [rsp + \at + 12], 0x6b206574
.endm

// key and nonce are pointer registers; only rax is scratch.
.macro CHACHA_HSTATE key,nonce
    CHACHA_CONSTANTS WORK
    .irp offset,0,8,16,24
        mov rax, [\key + \offset]
        mov [rsp + WORK + 16 + \offset], rax
    .endr
    mov rax, [\nonce]
    mov [rsp + WORK + 48], rax
    mov rax, [\nonce + 8]
    mov [rsp + WORK + 56], rax
.endm

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: everything below allocates the frame above, and every
// ║ secret this file touches passes through it. INITIAL holds the key spread
// ║ into words, and for XChaCha20 the subkey derived from it; WORK holds the
// ║ state through the rounds and then one keystream block.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced. Every routine below leaves through the one wipe at the end of
// ║ the region, including the ones that jump into the shared loop.
// ║
// ║═══════════════════════════════════════════════════════════════════════

// ============================================================================
// Twenty rounds — rdi: state in/out, sixteen u32 words
// ============================================================================

.p2align 4
.globl FUNC(redoubt_chacha_rounds)
HIDDEN_FUNC(redoubt_chacha_rounds)
FUNC(redoubt_chacha_rounds):
    sub rsp, FRAME
    mov [rsp + OUTPUT], rdi
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rdi + \offset]
        mov [rsp + WORK + \offset], rax
    .endr

    CHACHA_ROUNDS

    mov rdi, [rsp + OUTPUT]
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rsp + WORK + \offset]
        mov [rdi + \offset], rax
    .endr
    jmp Lempty_frame

// ============================================================================
// HChaCha20 — rdi: out, rsi: key, rdx: sixteen-byte nonce
// ============================================================================

.p2align 4
.globl FUNC(redoubt_hchacha_subkey)
HIDDEN_FUNC(redoubt_hchacha_subkey)
FUNC(redoubt_hchacha_subkey):
    sub rsp, FRAME
    mov [rsp + OUTPUT], rdi
    CHACHA_HSTATE rsi,rdx
    CHACHA_ROUNDS

    mov rdi, [rsp + OUTPUT]
    mov rax, [rsp + WORK]
    mov [rdi], rax
    mov rax, [rsp + WORK + 8]
    mov [rdi + 8], rax
    mov rax, [rsp + WORK + 48]
    mov [rdi + 16], rax
    mov rax, [rsp + WORK + 56]
    mov [rdi + 24], rax
    jmp Lempty_frame

// ============================================================================
// ChaCha20 — rdi: key, rsi: nonce, rdx: counter, rcx: data,
//            r8: length, r9: nonce length (8 or 12)
// ============================================================================
//
// The safe backend wrapper validates the public counter range before entry.
//
.p2align 4
.globl FUNC(redoubt_chacha_xor)
HIDDEN_FUNC(redoubt_chacha_xor)
FUNC(redoubt_chacha_xor):
    test r8, r8
    jz Lreturn
    sub rsp, FRAME
    mov [rsp + OUTPUT], rcx
    mov [rsp + LENGTH], r8
    mov [rsp + MODE], r9

    CHACHA_CONSTANTS INITIAL
    .irp offset,0,8,16,24
        mov rax, [rdi + \offset]
        mov [rsp + INITIAL + 16 + \offset], rax
    .endr
    mov [rsp + INITIAL + 48], edx
    cmp r9, 8
    je Lbernstein_nonce

    mov eax, [rsi]
    mov [rsp + INITIAL + 52], eax
    mov rax, [rsi + 4]
    mov [rsp + INITIAL + 56], rax
    jmp Lblock

Lbernstein_nonce:
    shr rdx, 32
    mov [rsp + INITIAL + 52], edx
    mov rax, [rsi]
    mov [rsp + INITIAL + 56], rax
    jmp Lblock

// ============================================================================
// XChaCha20 — rdi: key, rsi: nonce, rdx: counter, rcx: data, r8: length
// ============================================================================

.p2align 4
.globl FUNC(redoubt_xchacha_xor)
HIDDEN_FUNC(redoubt_xchacha_xor)
FUNC(redoubt_xchacha_xor):
    test r8, r8
    jz Lreturn
    sub rsp, FRAME
    mov [rsp + OUTPUT], rcx
    mov [rsp + LENGTH], r8
    mov [rsp + MODE], rsi
    mov [rsp + COUNTER], rdx

    CHACHA_HSTATE rdi,rsi
    CHACHA_ROUNDS

    // Keep the subkey inside the frame. No Rust call or intermediate output.
    CHACHA_CONSTANTS INITIAL
    mov rax, [rsp + WORK]
    mov [rsp + INITIAL + 16], rax
    mov rax, [rsp + WORK + 8]
    mov [rsp + INITIAL + 24], rax
    mov rax, [rsp + WORK + 48]
    mov [rsp + INITIAL + 32], rax
    mov rax, [rsp + WORK + 56]
    mov [rsp + INITIAL + 40], rax
    mov eax, [rsp + COUNTER]
    mov [rsp + INITIAL + 48], eax
    mov dword ptr [rsp + INITIAL + 52], 0
    mov rsi, [rsp + MODE]
    mov rax, [rsi + 16]
    mov [rsp + INITIAL + 56], rax
    mov qword ptr [rsp + MODE], 12

// ============================================================================
// Shared stream loop — branches depend only on public lengths and counters
// ============================================================================
//
// Not a function and not called: the two routines above reach here and become
// it, one by jumping and one by running out of instructions before it. There
// is no way back to either.
//
// ENTERED WITH: INITIAL holding the sixteen state words, OUTPUT the next byte
//   to write, LENGTH what is left of the message, and MODE the nonce length.
//   Whoever jumps here has filled all four.
//
// LEFT BY: `jz Lempty_frame` below, and nothing else. The other two jumps come
//   back to the top. A branch out of here that skipped that one would skip the
//   frame wipe and the register wipe with it, and the assembler would not say
//   a word about it.
//
Lblock:
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rsp + INITIAL + \offset]
        mov [rsp + WORK + \offset], rax
    .endr
    CHACHA_ROUNDS
    .irp offset,0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60
        mov eax, [rsp + INITIAL + \offset]
        add [rsp + WORK + \offset], eax
    .endr

    mov rdi, [rsp + OUTPUT]
    mov rcx, [rsp + LENGTH]
    mov edx, 64
    cmp rcx, rdx
    cmova rcx, rdx
    xor esi, esi
Lbytes:
    movzx eax, byte ptr [rsp + WORK + rsi]
    xor byte ptr [rdi + rsi], al
    inc rsi
    cmp rsi, rcx
    jb Lbytes

    add [rsp + OUTPUT], rcx
    sub [rsp + LENGTH], rcx
    jz Lempty_frame

    cmp qword ptr [rsp + MODE], 8
    je Lbernstein_step
    add dword ptr [rsp + INITIAL + 48], 1
    jmp Lblock
Lbernstein_step:
    add dword ptr [rsp + INITIAL + 48], 1
    adc dword ptr [rsp + INITIAL + 52], 0
    jmp Lblock

// Every allocated frame leaves through this wipe, before rsp is advanced.
Lempty_frame:
    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

Lreturn:
    CHACHA_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
