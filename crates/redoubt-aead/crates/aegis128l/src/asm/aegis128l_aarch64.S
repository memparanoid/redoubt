// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L - AArch64 (AAPCS) Implementation
//
// Eight 128-bit blocks of state, and the AES round function used as a
// permutation. The state lives in v0-v7 from the first instruction to the tag,
// and what does not fit a register — the tail of an AAD or a message that does
// not fill a block — goes through a frame this file names and empties.
//
// Armv8-A with the cryptographic extension, nothing else, and nothing detected
// at runtime. A machine without it does not answer wrong: the first `aese` is
// an illegal instruction. The build script assembles this for every AAPCS
// AArch64 target, so asking whether the machine has AES belongs to whoever
// chooses this AEAD.
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, Mach-O naming)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// lengths, which are public. Nothing is returned. `decrypt` writes the tag it
// computed and does not compare: the comparison is `redoubt-aead-core`'s, in
// constant time, and the tag the caller expected never arrives here.
//
// Nothing branches on a key, a nonce, a message or a tag. Every branch is on a
// length.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context, vectors included, to a frame on the user stack that nothing in
//   user space wipes. The same for a core dump, a page that reached swap, and
//   anything ptrace can read.
//
// References:
// - draft-irtf-cfrg-aegis-aead-17
// - Arm Architecture Reference Manual, AESE and AESMC

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
// Shared constants
// ============================================================================

#if defined(__APPLE__)
.const_data
#else
.section .rodata
#endif
.p2align 4
AEGIS_C0:
    .byte 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d
    .byte 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
.p2align 4
AEGIS_C1:
    .byte 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1
    .byte 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd

.text

// ============================================================================
// The register budget
// ============================================================================
//
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through these two lists. A register added to the
// wipe and missing from the verifier is a register nothing looks at, silently.
//
// AAPCS makes x0-x17, v0-v7 and v16-v31 caller-saved. Out of the lists: x18,
// the platform register; x30, which every `bl` writes; and x19-x28 and v8-v15,
// callee-saved, which nothing here writes — saving one would spill the caller's
// value into this file's stack.
//
// The vector half is here because the state is: v0-v7 hold S0-S7, v16-v20 the
// blocks absorbed and the round's temporaries, v22 the zero `aese` takes. The
// rest are written by nothing and listed anyway, so the verifier still asks
// about them the day somebody reaches for a spare.
.macro AEGIS_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        \op \reg
    .endr
.endm

.macro AEGIS_EACH_GENERAL op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro AEGIS_CLEAR_VECTOR n
    movi v\n\().16b, #0
.endm

.macro AEGIS_CLEAR_GENERAL reg
    mov \reg, xzr
.endm

// Copies what v0 and x0 already hold into each, themselves included. Used by
// the probe.
.macro AEGIS_FILL_VECTOR n
    mov v\n\().16b, v0.16b
.endm

.macro AEGIS_FILL_GENERAL reg
    mov \reg, x0
.endm

// Folds each half into v0 and x1, which are in their lists and so contribute
// their own values. Used by the probe.
.macro AEGIS_GATHER_VECTOR n
    orr v0.16b, v0.16b, v\n\().16b
.endm

.macro AEGIS_GATHER_GENERAL reg
    orr x1, x1, \reg
.endm

.macro AEGIS_ZEROIZE_ALL
    AEGIS_EACH_VECTOR AEGIS_CLEAR_VECTOR
    AEGIS_EACH_GENERAL AEGIS_CLEAR_GENERAL
.endm

// ============================================================================
// Frame layout
// ============================================================================
//
// PARTIAL is one pair of blocks: the tail of an AAD or a message, padded with
// zeros. Each tail takes the frame and gives it back before the round that
// absorbs it.
//
// A tail goes through memory and not a lane at a time because `ins` takes a
// constant lane, and a tail is as long as it is.
//
// FRAME is a multiple of sixteen: AAPCS faults an sp-relative access through an
// sp that is not.
.set PARTIAL, 0
.set FRAME, 32

// ============================================================================
// Frame wipe
// ============================================================================

// Every byte of the frame. Run before a tail is written, so the zeros past it
// are the padding the standard asks for, and again on the way out.
.macro AEGIS_CLEAR_FRAME
    .set _empty_at, 0
    .rept FRAME / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
.endm

.macro AEGIS_EMPTY_FRAME
    AEGIS_CLEAR_FRAME
    add sp, sp, #FRAME
.endm

// ============================================================================
// Arithmetic macros
// ============================================================================

// One state update: S'i = AESRound(S(i-1), Si), with m0 folded into S0 and m1
// into S4. `aese` adds its key before SubBytes and ShiftRows, and AESRound adds
// it after MixColumns: so `aese` against the zero in v22, then `aesmc`, then the
// key added by hand.
//
// Written in place from S'7 down to S'1, so each reads S(i-1) before it is
// overwritten. S'0 needs the old S7, which is gone by then: v20 keeps it. v18
// and v19 are scratch.
.macro AEGIS_UPDATE m0, m1
    mov v20.16b, v7.16b

    mov v18.16b, v6.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v7.16b, v18.16b, v7.16b

    mov v18.16b, v5.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v6.16b, v18.16b, v6.16b

    mov v18.16b, v4.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v5.16b, v18.16b, v5.16b

    eor v19.16b, v4.16b, \m1\().16b
    mov v18.16b, v3.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v4.16b, v18.16b, v19.16b

    mov v18.16b, v2.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v3.16b, v18.16b, v3.16b

    mov v18.16b, v1.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v2.16b, v18.16b, v2.16b

    mov v18.16b, v0.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v1.16b, v18.16b, v1.16b

    eor v19.16b, v0.16b, \m0\().16b
    mov v18.16b, v20.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v0.16b, v18.16b, v19.16b
.endm

// C0 into v18 and C1 into v19, through x0.
.macro AEGIS_LOAD_CONSTANTS
#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add  x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]
    adrp x0, AEGIS_C1@PAGE
    add  x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]
#else
    adrp x0, AEGIS_C0
    add  x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]
    adrp x0, AEGIS_C1
    add  x0, x0, :lo12:AEGIS_C1
    ld1 {v19.16b}, [x0]
#endif
.endm

// ============================================================================
// aegis128l_encrypt
// ============================================================================
//
// C signature:
//   void redoubt_aegis128l_encrypt(
//       const uint8_t key[16],
//       const uint8_t nonce[16],
//       const uint8_t *aad,
//       size_t         aad_len,
//       uint8_t       *data,
//       size_t         data_len,
//       uint8_t        tag[16]
//   );
//
// Parameters (AAPCS):
//   x0: key, x1: nonce, x2: aad, x3: aad_len, x4: data, x5: data_len, x6: tag.
//
// `data` is enciphered where it lies. x8-x12 keep what the arguments were
// until the tag is made from them.
.global FUNC(redoubt_aegis128l_encrypt)
HIDDEN_FUNC(redoubt_aegis128l_encrypt)
#if !defined(__APPLE__)
.type FUNC(redoubt_aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_encrypt):
    mov x8, x2
    mov x9, x3
    mov x10, x4
    mov x11, x5
    mov x12, x6

    movi v22.16b, #0

    ld1 {v16.16b}, [x0]
    ld1 {v17.16b}, [x1]

    AEGIS_LOAD_CONSTANTS

    eor v0.16b, v16.16b, v17.16b
    mov v1.16b, v19.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    eor v4.16b, v16.16b, v17.16b
    eor v5.16b, v16.16b, v18.16b
    eor v6.16b, v16.16b, v19.16b
    eor v7.16b, v16.16b, v18.16b

    .rept 10
        AEGIS_UPDATE v17, v16
    .endr

    mov x0, x8
    mov x1, x9

.Lenc_aad_whole:
    cmp x1, #32
    b.lt .Lenc_aad_tail

    ld1 {v16.16b}, [x0], #16
    ld1 {v17.16b}, [x0], #16
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Lenc_aad_whole

.Lenc_aad_tail:
    cbz x1, .Lenc_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the AAD, padded here because
// ║ the caller's buffer has no room to pad in.
// ║
// ║ Frame is zeroized before the tail is written and again before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    AEGIS_CLEAR_FRAME

    add x2, sp, #PARTIAL
    mov x3, x1
.Lenc_aad_copy:
    cbz x3, .Lenc_aad_copied
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Lenc_aad_copy
.Lenc_aad_copied:
    ld1 {v16.16b, v17.16b}, [sp]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

.Lenc_aad_done:
    mov x0, x10
    mov x1, x11

.Lenc_whole:
    cmp x1, #32
    b.lt .Lenc_tail

    ld1 {v16.16b, v17.16b}, [x0]

    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

    eor v18.16b, v18.16b, v16.16b
    eor v19.16b, v19.16b, v17.16b

    st1 {v18.16b, v19.16b}, [x0]
    add x0, x0, #32

    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Lenc_whole

.Lenc_tail:
    cbz x1, .Lenc_finalize

    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the message in the clear,
// ║ then the ciphertext it becomes, with keystream past the tail.
// ║
// ║ Frame is zeroized before the tail is written and again before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    AEGIS_CLEAR_FRAME

    add x2, sp, #PARTIAL
    mov x3, x1
.Lenc_plaintext_copy:
    cbz x3, .Lenc_plaintext_copied
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Lenc_plaintext_copy
.Lenc_plaintext_copied:

    ld1 {v16.16b, v17.16b}, [sp]

    eor v18.16b, v18.16b, v16.16b
    eor v19.16b, v19.16b, v17.16b

    st1 {v18.16b, v19.16b}, [sp]

    sub x0, x0, x1
    add x2, sp, #PARTIAL
    mov x3, x1
.Lenc_ciphertext_copy:
    cbz x3, .Lenc_ciphertext_copied
    ldrb w4, [x2], #1
    strb w4, [x0], #1
    sub x3, x3, #1
    b .Lenc_ciphertext_copy
.Lenc_ciphertext_copied:

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

.Lenc_finalize:
    // The lengths in bits, le64(aad) || le64(message), folded into S2.
    lsl x0, x9, #3
    lsl x1, x11, #3

    fmov d16, x0
    mov  v16.d[1], x1
    eor  v16.16b, v16.16b, v2.16b

    .rept 7
        AEGIS_UPDATE v16, v16
    .endr

    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    st1 {v16.16b}, [x12]

    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_aegis128l_encrypt), .-FUNC(redoubt_aegis128l_encrypt)
#endif

// ============================================================================
// aegis128l_decrypt
// ============================================================================
//
// C signature:
//   void redoubt_aegis128l_decrypt(
//       const uint8_t key[16],
//       const uint8_t nonce[16],
//       const uint8_t *aad,
//       size_t         aad_len,
//       uint8_t       *data,
//       size_t         data_len,
//       uint8_t        tag[16]
//   );
//
// Parameters (AAPCS):
//   x0: key, x1: nonce, x2: aad, x3: aad_len, x4: data, x5: data_len, x6: tag.
//
// `data` is deciphered where it lies, and `tag` is written with the tag it
// deserves. Until the caller has compared, `data` is a plaintext nothing has
// vouched for.
.global FUNC(redoubt_aegis128l_decrypt)
HIDDEN_FUNC(redoubt_aegis128l_decrypt)
#if !defined(__APPLE__)
.type FUNC(redoubt_aegis128l_decrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_decrypt):
    mov x8,  x2
    mov x9,  x3
    mov x10, x4
    mov x11, x5
    mov x13, x6

    movi v22.16b, #0

    ld1 {v16.16b}, [x0]
    ld1 {v17.16b}, [x1]

    AEGIS_LOAD_CONSTANTS

    eor v0.16b, v16.16b, v17.16b
    mov v1.16b, v19.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    eor v4.16b, v16.16b, v17.16b
    eor v5.16b, v16.16b, v18.16b
    eor v6.16b, v16.16b, v19.16b
    eor v7.16b, v16.16b, v18.16b

    .rept 10
        AEGIS_UPDATE v17, v16
    .endr

    mov x0, x8
    mov x1, x9

.Ldec_aad_whole:
    cmp x1, #32
    b.lt .Ldec_aad_tail

    ld1 {v16.16b}, [x0], #16
    ld1 {v17.16b}, [x0], #16
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Ldec_aad_whole

.Ldec_aad_tail:
    cbz x1, .Ldec_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the AAD, padded here because
// ║ the caller's buffer has no room to pad in.
// ║
// ║ Frame is zeroized before the tail is written and again before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    AEGIS_CLEAR_FRAME

    add x2, sp, #PARTIAL
    mov x3, x1
.Ldec_aad_copy:
    cbz x3, .Ldec_aad_copied
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Ldec_aad_copy
.Ldec_aad_copied:

    ld1 {v16.16b, v17.16b}, [sp]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

.Ldec_aad_done:
    mov x0, x10
    mov x1, x11

.Ldec_whole:
    cmp x1, #32
    b.lt .Ldec_tail

    ld1 {v16.16b, v17.16b}, [x0]

    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

    eor v16.16b, v16.16b, v18.16b
    eor v17.16b, v17.16b, v19.16b

    st1 {v16.16b, v17.16b}, [x0]
    add x0, x0, #32

    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Ldec_whole

.Ldec_tail:
    cbz x1, .Ldec_finalize

    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the ciphertext, then the
// ║ plaintext it deciphers into — a plaintext the caller has not
// ║ authenticated yet.
// ║
// ║ Frame is zeroized before the tail is written and again before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub sp, sp, #FRAME
    AEGIS_CLEAR_FRAME

    add x2, sp, #PARTIAL
    mov x3, x1
.Ldec_ciphertext_copy:
    cbz x3, .Ldec_ciphertext_copied
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Ldec_ciphertext_copy
.Ldec_ciphertext_copied:

    ld1 {v16.16b, v17.16b}, [sp]

    eor v16.16b, v16.16b, v18.16b
    eor v17.16b, v17.16b, v19.16b

    st1 {v16.16b, v17.16b}, [sp]

    // Past the tail the xor left keystream, and the state absorbs the plaintext
    // padded with zeros.
    add x2, sp, x1
    mov x3, #32
    sub x3, x3, x1
.Ldec_padding_empty:
    cbz x3, .Ldec_padding_emptied
    strb wzr, [x2], #1
    sub x3, x3, #1
    b .Ldec_padding_empty
.Ldec_padding_emptied:

    sub x0, x0, x1
    add x2, sp, #PARTIAL
    mov x3, x1
.Ldec_plaintext_copy:
    cbz x3, .Ldec_plaintext_copied
    ldrb w4, [x2], #1
    strb w4, [x0], #1
    sub x3, x3, #1
    b .Ldec_plaintext_copy
.Ldec_plaintext_copied:

    ld1 {v16.16b, v17.16b}, [sp]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

.Ldec_finalize:
    // The lengths in bits, le64(aad) || le64(message), folded into S2.
    lsl x0, x9, #3
    lsl x1, x11, #3

    fmov d16, x0
    mov  v16.d[1], x1
    eor  v16.16b, v16.16b, v2.16b

    .rept 7
        AEGIS_UPDATE v16, v16
    .endr

    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    st1 {v16.16b}, [x13]

    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_aegis128l_decrypt), .-FUNC(redoubt_aegis128l_decrypt)
#endif

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_aegis128l_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because x0 is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
//
// The generals are gathered first, so x0 is read before it carries the answer.
// The lanes of the vector fold are or-ed together into the one word that
// leaves: which lane a bit came from is lost, whether there was one is not.
.p2align 4
.global FUNC(redoubt_aegis128l_registers_are_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_registers_are_zeroized)
FUNC(redoubt_aegis128l_registers_are_zeroized):
    AEGIS_EACH_GENERAL AEGIS_GATHER_GENERAL
    AEGIS_EACH_VECTOR AEGIS_GATHER_VECTOR

    mov x0, v0.d[0]
    mov x2, v0.d[1]
    orr x0, x0, x2
    orr x0, x0, x1
    ret

// Every register in the budget filled with a pattern, and left that way. Both
// lanes of each vector, so a verifier that read only one still finds it.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_registers)
HIDDEN_FUNC(redoubt_aegis128l_dirty_registers)
FUNC(redoubt_aegis128l_dirty_registers):
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    dup v0.2d, x0
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    AEGIS_EACH_GENERAL AEGIS_FILL_GENERAL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_aegis128l_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `bl`
//   keeps the return address in x30 and leaves sp where the previous callee
//   found it, so `[sp - \size, sp)` is the frame that callee took. Asked after
//   the registers, never before: reading the frame takes registers.
//
// void redoubt_aegis128l_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in x0, marked and left.
//
// void redoubt_aegis128l_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro AEGIS_FRAME_PROBE name, size
.p2align 4
.global FUNC(redoubt_aegis128l_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_aegis128l_frame_is_zeroized_\name)
FUNC(redoubt_aegis128l_frame_is_zeroized_\name):
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
.global FUNC(redoubt_aegis128l_dirty_frame_\name)
HIDDEN_FUNC(redoubt_aegis128l_dirty_frame_\name)
FUNC(redoubt_aegis128l_dirty_frame_\name):
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
.global FUNC(redoubt_aegis128l_clean_frame_\name)
HIDDEN_FUNC(redoubt_aegis128l_clean_frame_\name)
FUNC(redoubt_aegis128l_clean_frame_\name):
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
    AEGIS_EMPTY_FRAME
    AEGIS_ZEROIZE_ALL
    ret
.endm

AEGIS_FRAME_PROBE aegis128l, FRAME

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
