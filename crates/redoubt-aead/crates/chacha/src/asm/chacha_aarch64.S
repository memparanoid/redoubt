// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ChaCha20, HChaCha20 and XChaCha20 - AArch64 (AAPCS) Implementation
//
// Armv8-A baseline: scalar integer instructions only, nothing detected at
// runtime.
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, Mach-O naming)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// counter and the lengths, which are public. Nothing is returned.
//
// Nothing branches on a secret: the stream loop and the nonce layout branch on
// lengths only.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context to a frame on the user stack that nothing in user space wipes. The
//   same for a core dump, a page that reached swap, and anything ptrace can
//   read.
//
// References:
// - RFC 8439, sections 2.1 to 2.4
// - draft-irtf-cfrg-xchacha, section 2.2
// - Procedure Call Standard for the Arm 64-bit Architecture, section 6.1.2

.text

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
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
// AAPCS makes x0-x17 caller-saved. Out of the list: x18, the platform register;
// x30, which every `bl` writes; and x19-x28, callee-saved, which nothing here
// writes — saving one would spill the caller's value into this file's stack.
// Nothing here writes a vector register.
.macro CHACHA_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro CHACHA_CLEAR reg
    mov \reg, xzr
.endm

// Copies what x0 already holds into each, itself included. Used by the probe.
.macro CHACHA_FILL reg
    mov \reg, x0
.endm

// Folds each into x1, which is in the list and so contributes its own value.
// Used by the probe.
.macro CHACHA_GATHER reg
    orr x1, x1, \reg
.endm

// The budget emptied, and the flags set to one fixed value whatever the last
// comparison left.
.macro CHACHA_ZEROIZE_ALL
    CHACHA_EACH CHACHA_CLEAR
    cmp xzr, xzr
.endm

// ============================================================================
// Frame layout
// ============================================================================
//
//   INITIAL  0..63   the state before the rounds, the XChaCha subkey in it
//   LENGTH  64..71   how much of the data is left
//   MODE    72..79   the nonce length
//   OUTPUT  80..87   XChaCha's data pointer, held across HChaCha
//   NONCE   88..95   XChaCha's nonce pointer, held across HChaCha
//
// The sixteen state words live in w2-w17 through the rounds, so only the
// stream routines take a frame, to keep the state for the feed-forward. FRAME
// is a multiple of sixteen: AArch64 faults on a load or store through an sp
// that is not sixteen-aligned.
.set INITIAL, 0
.set LENGTH, 64
.set MODE, 72
.set OUTPUT, 80
.set NONCE, 88
.set FRAME, 96

// ============================================================================
// Frame wipe
// ============================================================================

// Every byte of the frame, then the frame given back.
.macro CHACHA_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
    add sp, sp, #FRAME
.endm

// RFC 8439's quarter round over four state registers. The rotations are fixed:
// nothing here depends on the state.
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

// Twenty rounds over word i in w(i+2), as ten double rounds: the columns, then
// the diagonals. w1 counts them.
.macro CHACHA_ROUNDS
    mov w1, #10
.Lrounds\@:
    CHACHA_QUARTER w2,w6,w10,w14
    CHACHA_QUARTER w3,w7,w11,w15
    CHACHA_QUARTER w4,w8,w12,w16
    CHACHA_QUARTER w5,w9,w13,w17
    CHACHA_QUARTER w2,w7,w12,w17
    CHACHA_QUARTER w3,w8,w13,w14
    CHACHA_QUARTER w4,w9,w10,w15
    CHACHA_QUARTER w5,w6,w11,w16
    subs w1, w1, #1
    b.ne .Lrounds\@
.endm

// "expand 32-byte k", the first four state words, into w2-w5.
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

// The HChaCha state: the constants, the key and the first sixteen bytes of the
// nonce. Both pointers are read before the constants go into w2-w5, so either
// may be one of those registers.
.macro CHACHA_HSTATE key,nonce
    ldp w6, w7, [\key]
    ldp w8, w9, [\key, #8]
    ldp w10, w11, [\key, #16]
    ldp w12, w13, [\key, #24]
    ldp w14, w15, [\nonce]
    ldp w16, w17, [\nonce, #8]
    CHACHA_CONSTANTS
.endm

// One keystream word against the data at x0: four bytes at once while four are
// left, then the last one to three a byte at a time, so nothing is read or
// written past the caller's slice. The end of the data leaves through
// .Lempty_frame.
.macro CHACHA_XOR_WORD word
    ldr x1, [sp, #LENGTH]
    cmp x1, #4
    b.lo .Ltail\@
    sub x1, x1, #4
    str x1, [sp, #LENGTH]
    ldr w1, [x0]
    eor w1, w1, \word
    str w1, [x0], #4
    b .Ldone\@
.Ltail\@:
    cbz x1, .Lempty_frame
.Lbyte\@:
    ldrb w1, [x0]
    eor w1, w1, \word
    strb w1, [x0], #1
    lsr \word, \word, #8
    ldr x1, [sp, #LENGTH]
    sub x1, x1, #1
    str x1, [sp, #LENGTH]
    cbnz x1, .Lbyte\@
    b .Lempty_frame
.Ldone\@:
.endm

// The feed-forward: a state word plus its value before the rounds.
.macro CHACHA_ADD word,offset
    ldr w1, [sp, #\offset]
    add \word, \word, w1
.endm

// ============================================================================
// chacha_rounds
// ============================================================================
//
// C signature:
//   void redoubt_chacha_rounds(uint32_t state[16]);
//
// Parameters (AAPCS):
//   x0: state (read and written)
//
// The rounds alone, with no feed-forward: the block function's core, reached
// only by the tests. No frame: the state fits in the budget.
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

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// hchacha_subkey
// ============================================================================
//
// C signature:
//   void redoubt_hchacha_subkey(uint8_t out[32], const uint8_t key[32],
//                               const uint8_t nonce[16]);
//
// Parameters (AAPCS):
//   x0: out (written), x1: key (read only), x2: nonce (read only)
//
// The subkey is words 0-3 and 12-15 of the state after the rounds. No frame:
// the key and the state stay in w2-w17 until the subkey is written to `out`.
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

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// chacha_xor
// ============================================================================
//
// C signature:
//   void redoubt_chacha_xor(const uint8_t key[32], const uint8_t *nonce,
//                           uint64_t counter, uint8_t *data, size_t len,
//                           size_t nonce_len);
//
// Parameters (AAPCS):
//   x0: key (read only), x1: nonce (read only), x2: counter, x3: data (read
//   and written), x4: len, x5: nonce_len (8 or 12)
//
// The counter is not checked here: the Rust caller refuses one the data would
// run past.
.p2align 4
.globl FUNC(redoubt_chacha_xor)
HIDDEN_FUNC(redoubt_chacha_xor)
FUNC(redoubt_chacha_xor):
    // Nothing to encipher returns here: no frame is taken, and the register
    // wipe is the whole of the cleanup.
    cbnz x4, .Lchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

.Lchacha_xor_body:
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
    // RFC 8439's layout, a 32-bit counter and a twelve-byte nonce, unless the
    // nonce is eight bytes: then Bernstein's, a 64-bit counter in words 12 and
    // 13.
    str w2, [sp, #48]
    cmp x5, #8
    b.eq .Lbernstein_nonce
    ldr w6, [x1]
    str w6, [sp, #52]
    ldur x6, [x1, #4]
    str x6, [sp, #56]
    b .Lkey
.Lbernstein_nonce:
    lsr x6, x2, #32
    str w6, [sp, #52]
    ldr x6, [x1]
    str x6, [sp, #56]
.Lkey:
    ldp x6, x7, [x0]
    stp x6, x7, [sp, #16]
    ldp x6, x7, [x0, #16]
    stp x6, x7, [sp, #32]
    // The data pointer lives in x0 from here, where the loop expects it.
    mov x0, x3
    CHACHA_CONSTANTS
    stp w2, w3, [sp]
    stp w4, w5, [sp, #8]
    b .Lblock

// ============================================================================
// xchacha_xor
// ============================================================================
//
// C signature:
//   void redoubt_xchacha_xor(const uint8_t key[32], const uint8_t nonce[24],
//                            uint64_t counter, uint8_t *data, size_t len);
//
// Parameters (AAPCS):
//   x0: key (read only), x1: nonce (read only), x2: counter, x3: data (read
//   and written), x4: len
//
// The subkey is made and used inside one frame, and never written out. The
// counter is not checked here: the Rust caller refuses one the data would run
// past.
.p2align 4
.globl FUNC(redoubt_xchacha_xor)
HIDDEN_FUNC(redoubt_xchacha_xor)
FUNC(redoubt_xchacha_xor):
    // Nothing to encipher returns here: no frame is taken, and the register
    // wipe is the whole of the cleanup.
    cbnz x4, .Lxchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

.Lxchacha_xor_body:
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
    // RFC 8439's layout over the subkey: the counter, four zero bytes and the
    // last eight bytes of the nonce. MODE is twelve.
    str w2, [sp, #48]
    str wzr, [sp, #52]
    str x4, [sp, #LENGTH]
    mov x5, #12
    str x5, [sp, #MODE]
    str x3, [sp, #OUTPUT]
    str x1, [sp, #NONCE]

    CHACHA_HSTATE x0,x1
    CHACHA_ROUNDS

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
// The shared stream loop
// ============================================================================
//
// Not a function and not called: `chacha_xor` reaches here by branching and
// `xchacha_xor` by running out of instructions before it, and both become it.
// There is no way back to either.
//
// ENTERED WITH: INITIAL holding the state words, x0 the next byte to write,
//   LENGTH what is left of the data, and MODE the nonce length. Whoever reaches
//   here has filled them.
//
// LEFT BY: `b .Lempty_frame`, from the `cbz` below or from the tail of
//   CHACHA_XOR_WORD, and nothing else; every other branch goes back to the top.
//   A branch out of here that skipped those would skip the frame wipe and the
//   register wipe with it, and the assembler would not say a word about it.
.Lblock:
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
    cbz x1, .Lempty_frame
    ldr x1, [sp, #MODE]
    cmp x1, #8
    b.eq .Lbernstein_step
    ldr w1, [sp, #48]
    add w1, w1, #1
    str w1, [sp, #48]
    b .Lblock
.Lbernstein_step:
    // The 64-bit counter, words 12 and 13 as one.
    ldr x1, [sp, #48]
    add x1, x1, #1
    str x1, [sp, #48]
    b .Lblock

// The loop's one exit, and the end of every spill region that reaches it.
.Lempty_frame:
    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_chacha_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because x0 is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_chacha_registers_are_zeroized)
HIDDEN_FUNC(redoubt_chacha_registers_are_zeroized)
FUNC(redoubt_chacha_registers_are_zeroized):
    CHACHA_EACH CHACHA_GATHER
    mov x0, x1
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_chacha_dirty_registers)
HIDDEN_FUNC(redoubt_chacha_dirty_registers)
FUNC(redoubt_chacha_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    CHACHA_EACH CHACHA_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_chacha_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `bl`
//   keeps the return address in x30 and leaves sp where the previous callee
//   found it, so `[sp - \size, sp)` is the frame that callee took. Asked after
//   the registers, never before: reading the frame takes registers.
//
// void redoubt_chacha_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in x0, marked and left.
//
// void redoubt_chacha_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro CHACHA_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_chacha_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_chacha_frame_is_zeroized_\name)
FUNC(redoubt_chacha_frame_is_zeroized_\name):
    mov x0, xzr
    sub x1, sp, #\size
    mov x2, sp
1:
    ldr x3, [x1], #8
    orr x0, x0, x3
    cmp x1, x2
    b.lo 1b
    ret

.p2align 4
.globl FUNC(redoubt_chacha_dirty_frame_\name)
HIDDEN_FUNC(redoubt_chacha_dirty_frame_\name)
FUNC(redoubt_chacha_dirty_frame_\name):
    sub sp, sp, #\size
    // The frame is emptied before the byte goes in, so that what a verifier
    // finds is this byte and not a previous call's residue.
    mov x1, xzr
2:
    str xzr, [sp, x1]
    add x1, x1, #8
    cmp x1, #\size
    b.lo 2b
    mov w2, #0x5c
    strb w2, [sp, x0]
    add sp, sp, #\size
    ret

.p2align 4
.globl FUNC(redoubt_chacha_clean_frame_\name)
HIDDEN_FUNC(redoubt_chacha_clean_frame_\name)
FUNC(redoubt_chacha_clean_frame_\name):
    sub sp, sp, #\size
    mov x0, #0x5c5c
    movk x0, #0x5c5c, lsl #16
    movk x0, #0x5c5c, lsl #32
    movk x0, #0x5c5c, lsl #48
    mov x1, xzr
3:
    str x0, [sp, x1]
    add x1, x1, #8
    cmp x1, #\size
    b.lo 3b
    CHACHA_EMPTY_FRAME
    CHACHA_ZEROIZE_ALL
    ret
.endm

CHACHA_FRAME_PROBE chacha, FRAME

// ============================================================================
// Stack permissions
// ============================================================================
//
// An object with no .note.GNU-stack is one the linker assumes wants an
// executable stack, and one such object gives it to the whole binary. Nothing
// here needs one.
#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
