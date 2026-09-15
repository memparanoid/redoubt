// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ChaCha20, HChaCha20 and XChaCha20 - AArch64 (AAPCS) Implementation
//
// Baseline armv8-a. No SIMD, no SVE, nothing to detect at runtime: the whole of
// it is scalar 32-bit integer arithmetic. That is not the fastest ChaCha20
// anybody has written and it is not meant to be — a vectorized one needs a
// runtime check, a second and third copy of the rounds, and a wipe written once
// per register file. This one is the same code on every machine that runs it,
// which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - Sixteen working words in w2-w17, with no working-state spills
//   - Stream operations retain their initial state in a wiped 96-byte frame
//   - HChaCha and standalone rounds use no stack
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
// State words occupy w2-w17; w1 also carries plaintext during the xor.
// x18, x19-x30 and the SIMD registers are never touched. Clearing x0-x17
// also removes the public pointers and clears the high halves of every word.
//
.macro CHACHA_ZEROIZE_ALL
    mov x0,  xzr
    mov x1,  xzr
    mov x2,  xzr
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
    cmp xzr, xzr
.endm

// ============================================================================
// BEGIN SPILL REGION — stream operations only, 96 bytes above sp
// ============================================================================
//
//   INITIAL  0..63   state before the rounds, including an XChaCha subkey
//   LENGTH  64..71   remaining byte count
//   MODE    72..79   nonce length (8 or 12)
//   OUTPUT  80..87   XChaCha destination, held across the derivation
//   NONCE   88..95   XChaCha nonce, held across the derivation
//
// The working state never spills. The initial state is retained for the
// feed-forward addition. HChaCha and the standalone rounds allocate no frame.
// No callee-saved register needs saving, and no routine calls another.
//
.set INITIAL, 0
.set LENGTH, 64
.set MODE, 72
.set OUTPUT, 80
.set NONCE, 88
.set FRAME, 96

.macro CHACHA_EMPTY_FRAME
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    stp xzr, xzr, [sp, #32]
    stp xzr, xzr, [sp, #48]
    stp xzr, xzr, [sp, #64]
    stp xzr, xzr, [sp, #80]
    add sp, sp, #FRAME
.endm

// ============================================================================
// END SPILL REGION
// ============================================================================

// Word i lives in w(i+2). Only the fixed round count in w1 changes flags.
.macro CHACHA_QUARTER a,b,c,d
    add \a, \a, \b
    eor \d, \d, \a
    ror \d, \d, #16
    add \c, \c, \d
    eor \b, \b, \c
    ror \b, \b, #20
    add \a, \a, \b
    eor \d, \d, \a
    ror \d, \d, #24
    add \c, \c, \d
    eor \b, \b, \c
    ror \b, \b, #25
.endm

.macro CHACHA_ROUNDS
    mov w1, #10
Lrounds\@:
    CHACHA_QUARTER w2,w6,w10,w14
    CHACHA_QUARTER w3,w7,w11,w15
    CHACHA_QUARTER w4,w8,w12,w16
    CHACHA_QUARTER w5,w9,w13,w17
    CHACHA_QUARTER w2,w7,w12,w17
    CHACHA_QUARTER w3,w8,w13,w14
    CHACHA_QUARTER w4,w9,w10,w15
    CHACHA_QUARTER w5,w6,w11,w16
    subs w1, w1, #1
    b.ne Lrounds\@
.endm

.macro CHACHA_CONSTANTS
    mov w2, #0x7865
    movk w2, #0x6170, lsl #16
    mov w3, #0x646e
    movk w3, #0x3320, lsl #16
    mov w4, #0x2d32
    movk w4, #0x7962, lsl #16
    mov w5, #0x6574
    movk w5, #0x6b20, lsl #16
.endm

// Read both pointers before their registers can become state words.
.macro CHACHA_HSTATE key,nonce
    ldp w6, w7, [\key]
    ldp w8, w9, [\key, #8]
    ldp w10, w11, [\key, #16]
    ldp w12, w13, [\key, #24]
    ldp w14, w15, [\nonce]
    ldp w16, w17, [\nonce, #8]
    CHACHA_CONSTANTS
.endm

// ============================================================================
// Twenty rounds — x0: state in/out, sixteen u32 words; no frame
// ============================================================================

.p2align 4
.globl FUNC(redoubt_chacha_rounds)
HIDDEN_FUNC(redoubt_chacha_rounds)
FUNC(redoubt_chacha_rounds):
    ldp w2, w3, [x0]
    ldp w4, w5, [x0, #8]
    ldp w6, w7, [x0, #16]
    ldp w8, w9, [x0, #24]
    ldp w10, w11, [x0, #32]
    ldp w12, w13, [x0, #40]
    ldp w14, w15, [x0, #48]
    ldp w16, w17, [x0, #56]
    CHACHA_ROUNDS
    stp w2, w3, [x0]
    stp w4, w5, [x0, #8]
    stp w6, w7, [x0, #16]
    stp w8, w9, [x0, #24]
    stp w10, w11, [x0, #32]
    stp w12, w13, [x0, #40]
    stp w14, w15, [x0, #48]
    stp w16, w17, [x0, #56]
    b Lreturn

// ============================================================================
// HChaCha20 — x0: out, x1: key, x2: sixteen-byte nonce; no frame
// ============================================================================

.p2align 4
.globl FUNC(redoubt_hchacha_subkey)
HIDDEN_FUNC(redoubt_hchacha_subkey)
FUNC(redoubt_hchacha_subkey):
    CHACHA_HSTATE x1,x2
    CHACHA_ROUNDS
    stp w2, w3, [x0]
    stp w4, w5, [x0, #8]
    stp w14, w15, [x0, #16]
    stp w16, w17, [x0, #24]
    b Lreturn

// ============================================================================
// ChaCha20 — x0: key, x1: nonce, x2: counter, x3: data,
//            x4: length, x5: nonce length (8 or 12)
// ============================================================================
//
// The safe backend wrapper validates the public counter range before entry.
//
.p2align 4
.globl FUNC(redoubt_chacha_xor)
HIDDEN_FUNC(redoubt_chacha_xor)
FUNC(redoubt_chacha_xor):
    cbz x4, Lreturn
    sub sp, sp, #FRAME
    str x4, [sp, #LENGTH]
    str x5, [sp, #MODE]
    str w2, [sp, #48]
    cmp x5, #8
    b.eq Lbernstein_nonce
    ldr w6, [x1]
    str w6, [sp, #52]
    ldur x6, [x1, #4]
    str x6, [sp, #56]
    b Lkey
Lbernstein_nonce:
    lsr x6, x2, #32
    str w6, [sp, #52]
    ldr x6, [x1]
    str x6, [sp, #56]
Lkey:
    ldp x6, x7, [x0]
    stp x6, x7, [sp, #16]
    ldp x6, x7, [x0, #16]
    stp x6, x7, [sp, #32]
    mov x0, x3
    CHACHA_CONSTANTS
    stp w2, w3, [sp]
    stp w4, w5, [sp, #8]
    b Lblock

// ============================================================================
// XChaCha20 — x0: key, x1: nonce, x2: counter, x3: data, x4: length
// ============================================================================

.p2align 4
.globl FUNC(redoubt_xchacha_xor)
HIDDEN_FUNC(redoubt_xchacha_xor)
FUNC(redoubt_xchacha_xor):
    cbz x4, Lreturn
    sub sp, sp, #FRAME
    str w2, [sp, #48]
    str wzr, [sp, #52]
    str x4, [sp, #LENGTH]
    mov x5, #12
    str x5, [sp, #MODE]
    str x3, [sp, #OUTPUT]
    str x1, [sp, #NONCE]

    CHACHA_HSTATE x0,x1
    CHACHA_ROUNDS

    // Store the subkey only where the stream's key belongs.
    stp w2, w3, [sp, #16]
    stp w4, w5, [sp, #24]
    stp w14, w15, [sp, #32]
    stp w16, w17, [sp, #40]
    CHACHA_CONSTANTS
    stp w2, w3, [sp]
    stp w4, w5, [sp, #8]
    ldr x1, [sp, #NONCE]
    ldr x2, [x1, #16]
    str x2, [sp, #56]
    ldr x0, [sp, #OUTPUT]

// ============================================================================
// Shared stream loop
// ============================================================================

// Consume a word directly from a register. The final one to three bytes are
// read and written individually: no access extends past the caller's slice.
.macro CHACHA_XOR_WORD word
    ldr x1, [sp, #LENGTH]
    cmp x1, #4
    b.lo Ltail\@
    sub x1, x1, #4
    str x1, [sp, #LENGTH]
    ldr w1, [x0]
    eor w1, w1, \word
    str w1, [x0], #4
    b Ldone\@
Ltail\@:
    cbz x1, Lempty_frame
Lbyte\@:
    ldrb w1, [x0]
    eor w1, w1, \word
    strb w1, [x0], #1
    lsr \word, \word, #8
    ldr x1, [sp, #LENGTH]
    sub x1, x1, #1
    str x1, [sp, #LENGTH]
    cbnz x1, Lbyte\@
    b Lempty_frame
Ldone\@:
.endm

.macro CHACHA_ADD word,offset
    ldr w1, [sp, #\offset]
    add \word, \word, w1
.endm

Lblock:
    ldp w2, w3, [sp]
    ldp w4, w5, [sp, #8]
    ldp w6, w7, [sp, #16]
    ldp w8, w9, [sp, #24]
    ldp w10, w11, [sp, #32]
    ldp w12, w13, [sp, #40]
    ldp w14, w15, [sp, #48]
    ldp w16, w17, [sp, #56]
    CHACHA_ROUNDS
    CHACHA_ADD w2,0
    CHACHA_ADD w3,4
    CHACHA_ADD w4,8
    CHACHA_ADD w5,12
    CHACHA_ADD w6,16
    CHACHA_ADD w7,20
    CHACHA_ADD w8,24
    CHACHA_ADD w9,28
    CHACHA_ADD w10,32
    CHACHA_ADD w11,36
    CHACHA_ADD w12,40
    CHACHA_ADD w13,44
    CHACHA_ADD w14,48
    CHACHA_ADD w15,52
    CHACHA_ADD w16,56
    CHACHA_ADD w17,60

    .irp word,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15,w16,w17
        CHACHA_XOR_WORD \word
    .endr
    ldr x1, [sp, #LENGTH]
    cbz x1, Lempty_frame
    ldr x1, [sp, #MODE]
    cmp x1, #8
    b.eq Lbernstein_step
    ldr w1, [sp, #48]
    add w1, w1, #1
    str w1, [sp, #48]
    b Lblock
Lbernstein_step:
    ldr x1, [sp, #48]
    add x1, x1, #1
    str x1, [sp, #48]
    b Lblock

// Every stream exit wipes the entire frame before releasing it.
Lempty_frame:
    CHACHA_EMPTY_FRAME
Lreturn:
    CHACHA_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
