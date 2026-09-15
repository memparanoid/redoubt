// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 One-Time Authenticator - AArch64 (AAPCS) Implementation
//
// Baseline armv8-a. No SIMD, no SVE, nothing to detect at runtime: the whole of
// it is scalar 64-bit integer arithmetic. That is not the fastest Poly1305
// anybody has written and it is not meant to be — a vectorized one needs a
// runtime check, a second and third copy of the multiply, and a wipe written
// once per register file. This one is the same code on every machine that runs
// it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - `r` and the accumulator are five limbs of twenty-six bits each
//   - The products of one block never leave registers
//   - Any spill region is named and wiped here
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, with the symbol naming below)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there
//     and the crate falls back to the Rust, which answers the same and
//     promises less.
//
// x18 is the platform register and is never read or written here.
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
// - Procedure Call Standard for the Arm 64-bit Architecture, section 6.1.2

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
// AAPCS:
//   - Caller-saved GPR: x0-x17
//   - Platform register: x18            (DO NOT TOUCH)
//   - Callee-saved GPR: x19-x28, x29 (FP), x30 (LR)  (DO NOT TOUCH)
//
// Zeroizes:
//   - x3-x17, which are every register this file puts a limb or a product in
//
// Does NOT touch: x0, x1 and x2 are the caller's own pointers, which the caller
// already has. x19 upward are the caller's, restored by an epilogue where there
// is one.
//
// Does NOT touch the SIMD registers either. Nothing here writes one, so
// clearing them would be clearing registers this code never put anything in.
//
.macro POLY1305_ZEROIZE_ALL
    mov x3,  xzr
    mov x4,  xzr
    mov x5,  xzr
    mov x6,  xzr
    mov x7,  xzr
    mov x8,  xzr
    mov x9,  xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
.endm

// ============================================================================
// Callee-Saved Save and Restore Macros
// ============================================================================
//
// The six registers a function here uses that the ABI says a callee gives back
// as it found them, and the frame and link registers it needs for calling at
// all. They are a pair: the offsets the restore reads are the ones the save
// wrote, and neither is written out anywhere else. The eighty bytes are for the
// sixteen-byte alignment the ABI asks of the stack pointer; the last sixteen
// are never written.
//
// The restore does what an `ldp` does not. `ldp` puts the caller's value back
// in the register and leaves the copy where it was, below the stack pointer,
// until something else happens to write over it. If one of those registers held
// something of the caller's — and a compiler will keep a value in a
// callee-saved register across a call — then this file's prologue is what put a
// copy of it in memory, which makes this file's epilogue what has to take it
// out. A function that used none of these registers would leave no copy at all.
//
// Each slot is read and then written over while it is still above the stack
// pointer, so nothing is ever written below it.
//
.macro POLY1305_SAVE
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
.endm

// PRECONDITION: the stack pointer is where POLY1305_SAVE left it, which is
//   after the frame, if there was one, has been given back.
.macro POLY1305_RESTORE_AND_EMPTY
    ldp x23, x24, [sp, #48]
    stp xzr, xzr, [sp, #48]
    ldp x21, x22, [sp, #32]
    stp xzr, xzr, [sp, #32]
    ldp x19, x20, [sp, #16]
    stp xzr, xzr, [sp, #16]
    ldp x29, x30, [sp]
    stp xzr, xzr, [sp]

    add sp, sp, #80
.endm
