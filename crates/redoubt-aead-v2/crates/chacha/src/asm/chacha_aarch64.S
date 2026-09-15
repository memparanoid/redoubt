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
// The register budget
// ============================================================================
//
// AAPCS:
//   - Caller-saved GPR: x0-x17
//   - Platform register: x18            (DO NOT TOUCH)
//   - Callee-saved GPR: x19-x28, x29 (FP), x30 (LR)  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and
// every operation over the set goes through that one list. Emptying them and
// asking whether they are empty are the same eighteen registers by
// construction, not by two lists that happen to agree today.
//
// The list is x0-x17: state words occupy w2-w17, w1 also carries plaintext
// during the xor, and the pointers the caller handed over sit in the rest.
// Those are the caller's own and it still has them, so clearing them costs
// nothing; leaving them is a pointer into the caller's key sitting in a
// register after the routine that needed it has returned. Clearing the whole
// x register also takes the high half of every word.
//
// Does NOT include: x18 is the platform register, and x19 upward are the
// caller's, restored by an epilogue where there is one.
//
// Does NOT include the SIMD registers either. Nothing here writes one, so
// clearing them would be clearing registers this code never put anything in.
//
.macro CHACHA_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro CHACHA_CLEAR reg
    mov \reg, xzr
.endm

// Copies what x0 already holds into each of them, x0 included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro CHACHA_FILL reg
    mov \reg, x0
.endm

// Gathers into x1, which is in the list and therefore contributes its own
// value on its own line. What the gather leaves in x1 is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro CHACHA_GATHER reg
    orr x1, x1, \reg
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro CHACHA_ZEROIZE_ALL
    CHACHA_EACH CHACHA_CLEAR
    cmp xzr, xzr
.endm

// ============================================================================
// Frame layout — stream operations only, 96 bytes above sp
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

    // No frame here and so no wipe of one: sixteen words fit in w2-w17, and
    // what is left of them is what the register wipe takes.
    CHACHA_ZEROIZE_ALL
    ret

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

    // The key and the subkey it derives never leave w2-w17, so there is no
    // frame here either and the register wipe is the whole of the cleanup.
    CHACHA_ZEROIZE_ALL
    ret

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
    // Nothing to encipher is answered here and not in the loop: no frame is
    // taken, so there is none to wipe, and the registers are the whole of what
    // this call touched.
    cbnz x4, Lchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

Lchacha_xor_body:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the key spread into words at offset 16
// ║ and the counter it is streamed from, for as long as the message takes. The
// ║ working state never reaches it — it lives in w2-w17 throughout.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced. This routine leaves through the loop's wipe, and only through
// ║ it, the early exit out of a partial block included.
// ║
// ║═══════════════════════════════════════════════════════════════════════
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
    // As above: nothing to encipher takes no frame, so the register wipe is
    // the whole of the cleanup.
    cbnz x4, Lxchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

Lxchacha_xor_body:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the subkey the whole message is
// ║ enciphered with, written at offset 16 where the stream's key belongs. It
// ║ never leaves: there is no intermediate output and no call back into Rust.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced. This routine leaves through the loop's wipe, and only through
// ║ it, the early exit out of a partial block included.
// ║
// ║═══════════════════════════════════════════════════════════════════════
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

// Not a function and not called: the two routines above reach here and become
// it, one by branching and one by running out of instructions before it. There
// is no way back to either.
//
// ENTERED WITH: the first sixteen words of the frame holding the state, OUTPUT
//   the next byte to write, LENGTH what is left of the message, and MODE the
//   nonce length. Whoever branches here has filled all four.
//
// LEFT BY: `b Lempty_frame`, from the `cbz` below or from the tail of
//   CHACHA_XOR_WORD, and nothing else. The other two branches come back to the
//   top. A branch out of here that skipped those would skip the frame wipe and
//   the register wipe with it, and the assembler would not say a word about it.
//
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

// The loop's one exit, and the end of both spill regions that reach it.
Lempty_frame:
    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================
//
// Nothing in production calls any of it. It is here and not in a file of its
// own because a reader asking whether the measurement is right should not have
// to find a second file and check that a number in it still matches a number
// in this one: FRAME below is the frame, and the register budget it asks about
// is the list the wipe uses, not a copy of either.
//
// What it costs is a few hundred bytes of instructions that ship unused. What
// it buys is that the only `96` in the measurement, and the only list of
// registers, are the ones at the top of this file.
//
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own list
//   frame_is_zeroized        asks the stack, with the file's own FRAME
//   dirty_registers          fills the budget and leaves it that way
//   dirty_frame              one byte of the frame, at an offset given
//   clean_frame              the frame written and emptied, with no rounds

// uint64_t redoubt_chacha_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost x0, and x0
// is one of the registers being asked about — it would arrive holding our own
// pointer rather than the caller's value. With nothing passed, `bl` is the
// whole call sequence and every register read here is the caller's own.
//
// x30 is not in the budget and this is the routine that shows why: `bl` writes
// it on the way here, so asking about it would be asking about the call that
// did the asking.
.p2align 4
.globl FUNC(redoubt_chacha_registers_are_zeroized)
HIDDEN_FUNC(redoubt_chacha_registers_are_zeroized)
FUNC(redoubt_chacha_registers_are_zeroized):
    CHACHA_EACH CHACHA_GATHER
    mov x0, x1
    ret

// uint64_t redoubt_chacha_frame_is_zeroized(void)
//
// Whether any byte of the frame the call before it used is still holding
// something. Zero when it is all empty, and the bits of whatever was not.
//
// Reads below its own sp, and that is the whole of it: `bl` puts the return
// address in x30 and leaves sp where the routine before had it, so what sits
// under this one's sp is what sat under that one's — the frame it took and
// gave back. There is no return-address slot in between, which is the one way
// this differs from the same routine on x86-64.
//
// Asked after the registers, never before: reading ninety-six bytes takes
// registers, and the answer about those has to be taken first.
.p2align 4
.globl FUNC(redoubt_chacha_frame_is_zeroized)
HIDDEN_FUNC(redoubt_chacha_frame_is_zeroized)
FUNC(redoubt_chacha_frame_is_zeroized):
    mov x0, xzr
    sub x1, sp, #FRAME
    mov x2, sp
Lframe_scan:
    ldr x3, [x1], #8
    orr x0, x0, x3
    cmp x1, x2
    b.ne Lframe_scan
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_chacha_dirty_registers)
HIDDEN_FUNC(redoubt_chacha_dirty_registers)
FUNC(redoubt_chacha_dirty_registers):
    // The pattern does not fit in one instruction, so it is built sixteen bits
    // at a time before anything is copied out of x0.
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    CHACHA_EACH CHACHA_FILL
    ret

// One byte of the frame, dirtied and left. x0 says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// whatever sits next door would show.
.p2align 4
.globl FUNC(redoubt_chacha_dirty_frame)
HIDDEN_FUNC(redoubt_chacha_dirty_frame)
FUNC(redoubt_chacha_dirty_frame):
    sub sp, sp, #FRAME
    // Isolate this byte from every previous call's residue. Keep x0, the
    // requested offset, intact until the whole frame is empty.
    mov x1, sp
    add x2, sp, #FRAME
Ldirty_clear:
    str xzr, [x1], #8
    cmp x1, x2
    b.ne Ldirty_clear
    mov w1, #0x5c
    strb w1, [sp, x0]
    add sp, sp, #FRAME
    ret

// The whole frame written and then emptied: what a routine above does, without
// the rounds in between.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.globl FUNC(redoubt_chacha_clean_frame)
HIDDEN_FUNC(redoubt_chacha_clean_frame)
FUNC(redoubt_chacha_clean_frame):
    sub sp, sp, #FRAME
    mov x0, #0x5c5c
    movk x0, #0x5c5c, lsl #16
    movk x0, #0x5c5c, lsl #32
    movk x0, #0x5c5c, lsl #48
    mov x1, sp
    add x2, sp, #FRAME
Lclean_write:
    str x0, [x1], #8
    cmp x1, x2
    b.ne Lclean_write
    CHACHA_EMPTY_FRAME
    CHACHA_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
