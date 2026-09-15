// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 One-Time Authenticator - x86_64 (SysV ABI) Implementation
//
// Baseline x86_64. No BMI2, no ADX, no AVX2, nothing to detect at runtime: the
// whole of it is scalar 64-bit integer arithmetic. That is not the fastest
// Poly1305 anybody has written and it is not meant to be — a vectorized one
// needs a runtime check, a second and third copy of the multiply, and a wipe
// written once per register file. This one is the same code on every machine
// that runs it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - `r` and the accumulator are five limbs of twenty-six bits each
//   - The products of one block never leave registers
//   - Any spill region is named and wiped here
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
//   the answer out is a register the wipe below cannot touch — which is why
//   even how much of the buffer is used arrives and leaves through memory. A
//   length and the bit above a block arrive by value because neither is a
//   secret and both are known to anybody watching the call.
//
// What must not branch:
//   The final conditional subtraction is a mask and not a jump. Whether the
//   accumulator was above the modulus is a fact about the key that made it, and
//   a branch there is that fact on a clock.
//
// What this cannot answer for:
//   The limbs are held in registers and in the frame this file named and wiped.
//   That is a statement about this file, not about the machine. When a signal
//   is delivered the kernel writes the whole register context to a frame on the
//   user stack, and nothing in user space wipes that frame on the way back. The
//   same goes for a core dump, for a page that reached swap, and for anything
//   ptrace can read. None of those are reachable from here, and none are made
//   worse by this being assembly: the Rust has every one of them too.
//
// References:
// - RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, section 2.5
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
// SysV AMD64 ABI:
//   - Caller-saved GPR: rax, rcx, rdx, rsi, rdi, r8-r11
//   - Callee-saved GPR: rbx, rbp, r12-r15  (DO NOT TOUCH)
//
// Zeroizes:
//   - rax, rcx, rdx, rsi, rdi, r8-r11
//
// Does NOT touch: rsp, rbx, rbp, r12-r15. Those hold limbs too, and what
// empties them is the epilogue restoring the caller's values over them. The
// memory the prologue put those values in is a separate matter, and
// POLY1305_RESTORE_AND_EMPTY below is what deals with it.
//
// Does NOT touch the SIMD registers either. Nothing here writes one, so
// clearing them would be clearing registers this code never put anything in.
//
.macro POLY1305_ZEROIZE_ALL
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
// Callee-Saved Save and Restore Macros
// ============================================================================
//
// The six registers this file uses that the ABI says a callee gives back as it
// found them. They are a pair: the offsets the restore reads are the order the
// save pushed in, and neither is written out anywhere else.
//
// The restore does what a `pop` does not. `pop` puts the caller's value back in
// the register and leaves the copy where it was, below rsp, until something
// else happens to write over it. If one of those registers held something of
// the caller's — and a compiler will keep a value in a callee-saved register
// across a call — then this file's prologue is what put a copy of it in memory,
// which makes this file's epilogue what has to take it out.
//
// Each slot is read and then written over while it is still above rsp, so
// nothing is ever written below the stack pointer. The zeros are immediates:
// no register is borrowed.
//
.macro POLY1305_SAVE
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
.endm

// PRECONDITION: rsp points at the six words POLY1305_SAVE pushed, which is
//   after the frame, if there was one, has been given back.
.macro POLY1305_RESTORE_AND_EMPTY
    mov r15, [rsp]
    mov r14, [rsp + 8]
    mov r13, [rsp + 16]
    mov r12, [rsp + 24]
    mov rbp, [rsp + 32]
    mov rbx, [rsp + 40]

    mov qword ptr [rsp],      0
    mov qword ptr [rsp + 8],  0
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov qword ptr [rsp + 32], 0
    mov qword ptr [rsp + 40], 0

    add rsp, 48
.endm
