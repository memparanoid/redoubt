// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// SHA-256, HMAC-SHA256 and HKDF-SHA256 - AArch64 (AAPCS) Implementation
//
// Armv8-A baseline: `ld1`, `st1`, `rev32`, `umov`, `ins` and `ext` over the `v`
// registers, and none of the SHA-256 extension. Nothing is detected at runtime.
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, Mach-O naming)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// lengths, which are public. Nothing is returned.
//
// Nothing branches on a secret: the block loop and the padding branch on
// lengths only.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context to a frame on the user stack that nothing in user space wipes. The
//   same for a core dump, a page that reached swap, and anything ptrace can
//   read.
//
// References:
// - FIPS 180-4, section 6.2
// - RFC 2104 (HMAC), RFC 5869 (HKDF)

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
    #define RODATA_SECTION .const_data
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
    #define RODATA_SECTION .section .rodata
#endif

.arch armv8-a

// ============================================================================
// Shared constants
// ============================================================================

RODATA_SECTION
.p2align 6

.LK256:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.LH256_INIT:
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

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
// The compression writes v16-v24, and the other routines v0 and v1. The rest are
// written by nothing and listed anyway, so the verifier still asks about them
// the day somebody reaches for a spare.
.macro HKDF_EACH_GPR op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro HKDF_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        \op v\reg
    .endr
.endm

.macro HKDF_CLEAR_GPR reg
    mov \reg, xzr
.endm

.macro HKDF_CLEAR_VECTOR reg
    movi \reg\().16b, #0
.endm

// Copies what x0 and v0 already hold into each, themselves included. Used by
// the probe.
.macro HKDF_FILL_GPR reg
    mov \reg, x0
.endm

.macro HKDF_FILL_VECTOR reg
    mov \reg\().16b, v0.16b
.endm

// Folds each half into x1 and v0, which are in their lists and so contribute
// their own values. Used by the probe.
.macro HKDF_GATHER_GPR reg
    orr x1, x1, \reg
.endm

.macro HKDF_GATHER_VECTOR reg
    orr v0.16b, v0.16b, \reg\().16b
.endm

.macro HKDF_SHA256_ZEROIZE_ALL
    HKDF_EACH_GPR HKDF_CLEAR_GPR
    HKDF_EACH_VECTOR HKDF_CLEAR_VECTOR
.endm

// ============================================================================
// The frames
// ============================================================================
//
// One table per routine, with its size last; that size is the only place the
// number is written. Not one shared size: the compression runs once per block
// of every message, and a shared width would make it pay the HKDF frame.
//
// Every size is a multiple of sixteen, which AAPCS requires of sp at all times.
// `bl` writes no stack, so a routine's frame is exactly `[sp - FRAME, sp)` as
// its caller left sp.
//
// A routine that calls another keeps the caller's x30 in its `_LR` slot, and
// loads it back before the frame is emptied.

// sha256_compress_block: the message schedule. It calls nothing and keeps its
// arguments in the registers they arrived in.
.set COMPRESS_W, 0
.set FRAME_COMPRESS, 64

// sha256_hash: the chaining state, the padded tail, and the arguments that
// have to outlive a call to the compression.
.set HASH_H, 0
.set HASH_BLOCK1, 32
.set HASH_BLOCK2, 96
.set HASH_MSG, 160
.set HASH_LEFT, 168
.set HASH_TOTAL, 176
.set HASH_DIGEST, 184
.set HASH_LR, 192
.set FRAME_HASH, 208

// sha256_update_finalize: the same, over a state the caller hands in.
.set UPDATE_H, 0
.set UPDATE_BLOCK1, 32
.set UPDATE_BLOCK2, 96
.set UPDATE_MSG, 160
.set UPDATE_LEFT, 168
.set UPDATE_TOTAL, 176
.set UPDATE_DIGEST, 184
.set UPDATE_LR, 192
.set FRAME_UPDATE, 208

// sha256_absorb: the arguments, which have to outlive the compression.
.set ABSORB_H, 0
.set ABSORB_SRC, 8
.set ABSORB_LEFT, 16
.set ABSORB_BLOCK, 24
.set ABSORB_FILL, 32
.set ABSORB_LR, 40
.set FRAME_ABSORB, 48

// hmac_sha256: the key padded to a block, the inner and outer pads, the inner
// digest, the key hashed down when it is longer than a block, the chaining
// state, and the arguments.
.set HMAC_KPAD, 0
.set HMAC_IPAD, 64
.set HMAC_OPAD, 128
.set HMAC_INNER, 192
.set HMAC_KHASH, 224
.set HMAC_H, 256
.set HMAC_KEY, 288
.set HMAC_KEYLEN, 296
.set HMAC_MSG, 304
.set HMAC_MSGLEN, 312
.set HMAC_MAC, 320
.set HMAC_LR, 328
.set FRAME_HMAC, 336

// hkdf_sha256: the extracted key, the inner and outer pads built from it once,
// the block being filled, the chaining state, the inner digest, the block of
// output being made, the counters, and the arguments.
.set HKDF_PRK, 0
.set HKDF_IPAD, 32
.set HKDF_OPAD, 96
.set HKDF_BLOCK, 160
.set HKDF_H, 224
.set HKDF_INNER, 256
.set HKDF_T, 288
.set HKDF_FILL, 320
.set HKDF_TLEN, 328
.set HKDF_COUNTER, 336
.set HKDF_INFO, 344
.set HKDF_INFOLEN, 352
.set HKDF_OKM, 360
.set HKDF_OKMLEN, 368
.set HKDF_LR, 376
.set FRAME_HKDF, 384

// ============================================================================
// Frame wipe
// ============================================================================

// Every byte of a frame of `size` bytes, then the frame given back. Every call
// site names the same constant its `sub sp` did.
.macro HKDF_EMPTY_FRAME size
    .set _empty_at, 0
    .rept \size / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
    add sp, sp, #\size
.endm

// ============================================================================
// sha256_compress_block
// ============================================================================
//
// C signature:
//   void redoubt_sha256_compress_block(uint32_t H[8], const uint8_t block[64]);
//
// Parameters (AAPCS):
//   x0: H (read and written), x1: block (read only, big-endian)
//
// H := H + SHA256_COMPRESS(block). The working words live in v18 and v19, the
// last sixteen schedule words in v20-v23.
.global FUNC(redoubt_sha256_compress_block)
HIDDEN_FUNC(redoubt_sha256_compress_block)
.p2align 4
FUNC(redoubt_sha256_compress_block):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: COMPRESS_W holds the block byte-swapped — for a key,
// ║ the key in the clear.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_COMPRESS

    ld1     {v16.4s, v17.4s}, [x0]

    ld1     {v20.4s, v21.4s, v22.4s, v23.4s}, [x1]
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b

    st1     {v20.4s, v21.4s, v22.4s, v23.4s}, [sp]

    mov     v18.16b, v16.16b
    mov     v19.16b, v17.16b

#if defined(__APPLE__)
    adrp    x3, .LK256@PAGE
    add     x3, x3, .LK256@PAGEOFF
#else
    adrp    x3, .LK256
    add     x3, x3, :lo12:.LK256
#endif

    mov     x2, #0
.Lround_0_15:
    ldr     w4, [sp, x2, lsl #2]
    ldr     w5, [x3, x2, lsl #2]

    umov    w6, v19.s[3]
    umov    w7, v19.s[0]
    umov    w8, v19.s[1]
    umov    w9, v19.s[2]

    mov     w10, w6

    ror     w6, w7, #6
    ror     w17, w7, #11
    eor     w6, w6, w17
    ror     w17, w7, #25
    eor     w6, w6, w17
    add     w10, w10, w6

    bic     w6, w9, w7
    and     w17, w7, w8
    eor     w6, w6, w17
    add     w10, w10, w6

    add     w10, w10, w5
    add     w10, w10, w4

    umov    w6, v18.s[0]
    umov    w7, v18.s[1]
    umov    w8, v18.s[2]

    ror     w9, w6, #2
    ror     w17, w6, #13
    eor     w9, w9, w17
    ror     w17, w6, #22
    eor     w9, w9, w17

    and     w4, w6, w7
    and     w17, w6, w8
    eor     w4, w4, w17
    and     w17, w7, w8
    eor     w4, w4, w17

    add     w9, w9, w4

    umov    w4, v18.s[3]
    add     w5, w4, w10
    add     w6, w10, w9

    mov     v19.s[3], v19.s[2]
    mov     v19.s[2], v19.s[1]
    mov     v19.s[1], v19.s[0]
    ins     v19.s[0], w5

    mov     v18.s[3], v18.s[2]
    mov     v18.s[2], v18.s[1]
    mov     v18.s[1], v18.s[0]
    ins     v18.s[0], w6

    add     x2, x2, #1
    cmp     x2, #16
    b.lt    .Lround_0_15

.Lround_16_63:
    umov    w4, v20.s[0]
    umov    w5, v20.s[1]
    umov    w6, v22.s[1]
    umov    w7, v23.s[2]

    ror     w8, w5, #7
    ror     w17, w5, #18
    eor     w8, w8, w17
    lsr     w17, w5, #3
    eor     w8, w8, w17

    ror     w9, w7, #17
    ror     w17, w7, #19
    eor     w9, w9, w17
    lsr     w17, w7, #10
    eor     w9, w9, w17

    add     w4, w4, w8
    add     w4, w4, w6
    add     w4, w4, w9

    ins     v24.s[0], w4

    ldr     w5, [x3, x2, lsl #2]

    umov    w6, v19.s[3]
    umov    w7, v19.s[0]
    umov    w8, v19.s[1]
    umov    w9, v19.s[2]

    mov     w10, w6

    ror     w6, w7, #6
    ror     w17, w7, #11
    eor     w6, w6, w17
    ror     w17, w7, #25
    eor     w6, w6, w17
    add     w10, w10, w6

    bic     w6, w9, w7
    and     w17, w7, w8
    eor     w6, w6, w17
    add     w10, w10, w6

    add     w10, w10, w5
    add     w10, w10, w4

    umov    w6, v18.s[0]
    umov    w7, v18.s[1]
    umov    w8, v18.s[2]

    ror     w9, w6, #2
    ror     w17, w6, #13
    eor     w9, w9, w17
    ror     w17, w6, #22
    eor     w9, w9, w17

    and     w4, w6, w7
    and     w17, w6, w8
    eor     w4, w4, w17
    and     w17, w7, w8
    eor     w4, w4, w17

    add     w9, w9, w4

    umov    w4, v18.s[3]
    add     w5, w4, w10
    add     w6, w10, w9

    mov     v19.s[3], v19.s[2]
    mov     v19.s[2], v19.s[1]
    mov     v19.s[1], v19.s[0]
    ins     v19.s[0], w5

    mov     v18.s[3], v18.s[2]
    mov     v18.s[2], v18.s[1]
    mov     v18.s[1], v18.s[0]
    ins     v18.s[0], w6

    ext     v20.16b, v20.16b, v21.16b, #4
    ext     v21.16b, v21.16b, v22.16b, #4
    ext     v22.16b, v22.16b, v23.16b, #4
    ext     v23.16b, v23.16b, v24.16b, #4

    add     x2, x2, #1
    cmp     x2, #64
    b.lt    .Lround_16_63

    add     v16.4s, v16.4s, v18.4s
    add     v17.4s, v17.4s, v19.4s

    st1     {v16.4s, v17.4s}, [x0]

    HKDF_EMPTY_FRAME FRAME_COMPRESS
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// sha256_hash
// ============================================================================
//
// C signature:
//   void redoubt_sha256_hash(const uint8_t *msg, size_t msg_len,
//                            uint8_t digest[32]);
//
// Parameters (AAPCS):
//   x0: msg, x1: msg_len, x2: digest (big-endian)
.global FUNC(redoubt_sha256_hash)
HIDDEN_FUNC(redoubt_sha256_hash)
.p2align 4
FUNC(redoubt_sha256_hash):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HASH_BLOCK1 and HASH_BLOCK2 hold the tail of the
// ║ message with its padding, in the clear, because the caller's buffer has
// ║ no room to pad in. HASH_H holds the chaining state.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HASH

    str     x30, [sp, #HASH_LR]
    str     x0, [sp, #HASH_MSG]
    str     x1, [sp, #HASH_LEFT]
    str     x1, [sp, #HASH_TOTAL]
    str     x2, [sp, #HASH_DIGEST]

#if defined(__APPLE__)
    adrp    x0, .LH256_INIT@PAGE
    add     x0, x0, .LH256_INIT@PAGEOFF
#else
    adrp    x0, .LH256_INIT
    add     x0, x0, :lo12:.LH256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    add     x1, sp, #HASH_H
    st1     {v0.4s, v1.4s}, [x1]

.Lhash_block_loop:
    ldr     x2, [sp, #HASH_LEFT]
    cmp     x2, #64
    b.lt    .Lhash_final_block

    add     x0, sp, #HASH_H
    ldr     x1, [sp, #HASH_MSG]
    bl      FUNC(redoubt_sha256_compress_block)

    ldr     x0, [sp, #HASH_MSG]
    add     x0, x0, #64
    str     x0, [sp, #HASH_MSG]
    ldr     x0, [sp, #HASH_LEFT]
    sub     x0, x0, #64
    str     x0, [sp, #HASH_LEFT]
    b       .Lhash_block_loop

.Lhash_final_block:
    ldr     x13, [sp, #HASH_LEFT]
    ldr     x12, [sp, #HASH_MSG]

    add     x16, sp, #HASH_BLOCK1
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    mov     x17, #0
.Lhash_copy_remainder:
    cmp     x17, x13
    b.ge    .Lhash_remainder_done
    ldrb    w0, [x12, x17]
    strb    w0, [x16, x17]
    add     x17, x17, #1
    b       .Lhash_copy_remainder

.Lhash_remainder_done:
    mov     w0, #0x80
    strb    w0, [x16, x13]

    cmp     x13, #56
    b.ge    .Lhash_two_blocks

    ldr     x14, [sp, #HASH_TOTAL]
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK1

    bl      FUNC(redoubt_sha256_compress_block)

    b       .Lhash_finish

.Lhash_two_blocks:
    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK1

    bl      FUNC(redoubt_sha256_compress_block)

    add     x16, sp, #HASH_BLOCK2
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    ldr     x14, [sp, #HASH_TOTAL]
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK2

    bl      FUNC(redoubt_sha256_compress_block)

.Lhash_finish:
    add     x0, sp, #HASH_H
    ld1     {v0.4s, v1.4s}, [x0]

    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b

    ldr     x15, [sp, #HASH_DIGEST]
    st1     {v0.4s, v1.4s}, [x15]

    ldr     x30, [sp, #HASH_LR]

    HKDF_EMPTY_FRAME FRAME_HASH
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// sha256_update_finalize
// ============================================================================
//
// C signature:
//   void sha256_update_finalize(const uint32_t H[8], const uint8_t *msg,
//                               size_t msg_len, size_t total_len,
//                               uint8_t digest[32]);
//
// Parameters (AAPCS):
//   x0: H (read once), x1: msg, x2: msg_len, x3: total_len (every byte already
//   folded into H plus msg_len, for the padding), x4: digest
//
// No name outside this file: a symbol a linked library could collide with is
// resolved by the linker without a word. The probe reaches it by trampoline.
.p2align 4
.Lsha256_update_finalize:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: UPDATE_H holds the caller's state — for HMAC, a pad
// ║ already folded in, which is key material. UPDATE_BLOCK1 and UPDATE_BLOCK2
// ║ hold the tail of the message with its padding, in the clear.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_UPDATE

    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #UPDATE_H
    st1     {v0.4s, v1.4s}, [x0]

    str     x30, [sp, #UPDATE_LR]
    str     x1, [sp, #UPDATE_MSG]
    str     x2, [sp, #UPDATE_LEFT]
    str     x3, [sp, #UPDATE_TOTAL]
    str     x4, [sp, #UPDATE_DIGEST]

.Lupdate_block_loop:
    ldr     x2, [sp, #UPDATE_LEFT]
    cmp     x2, #64
    b.lt    .Lupdate_final_block

    add     x0, sp, #UPDATE_H
    ldr     x1, [sp, #UPDATE_MSG]
    bl      FUNC(redoubt_sha256_compress_block)

    ldr     x0, [sp, #UPDATE_MSG]
    add     x0, x0, #64
    str     x0, [sp, #UPDATE_MSG]
    ldr     x0, [sp, #UPDATE_LEFT]
    sub     x0, x0, #64
    str     x0, [sp, #UPDATE_LEFT]
    b       .Lupdate_block_loop

.Lupdate_final_block:
    ldr     x13, [sp, #UPDATE_LEFT]
    ldr     x12, [sp, #UPDATE_MSG]

    add     x16, sp, #UPDATE_BLOCK1
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    mov     x17, #0
.Lupdate_copy_remainder:
    cmp     x17, x13
    b.ge    .Lupdate_remainder_done
    ldrb    w0, [x12, x17]
    strb    w0, [x16, x17]
    add     x17, x17, #1
    b       .Lupdate_copy_remainder

.Lupdate_remainder_done:
    mov     w0, #0x80
    strb    w0, [x16, x13]

    cmp     x13, #56
    b.ge    .Lupdate_two_blocks

    ldr     x14, [sp, #UPDATE_TOTAL]
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    add     x0, sp, #UPDATE_H
    add     x1, sp, #UPDATE_BLOCK1
    bl      FUNC(redoubt_sha256_compress_block)

    b       .Lupdate_finish

.Lupdate_two_blocks:
    add     x0, sp, #UPDATE_H
    add     x1, sp, #UPDATE_BLOCK1
    bl      FUNC(redoubt_sha256_compress_block)

    add     x16, sp, #UPDATE_BLOCK2
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    ldr     x14, [sp, #UPDATE_TOTAL]
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    add     x0, sp, #UPDATE_H
    add     x1, sp, #UPDATE_BLOCK2
    bl      FUNC(redoubt_sha256_compress_block)

.Lupdate_finish:
    add     x0, sp, #UPDATE_H
    ld1     {v0.4s, v1.4s}, [x0]
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b
    ldr     x15, [sp, #UPDATE_DIGEST]
    st1     {v0.4s, v1.4s}, [x15]

    ldr     x30, [sp, #UPDATE_LR]

    HKDF_EMPTY_FRAME FRAME_UPDATE
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// hmac_sha256
// ============================================================================
//
// C signature:
//   void redoubt_hmac_sha256(const uint8_t *key, size_t key_len,
//                            const uint8_t *msg, size_t msg_len,
//                            uint8_t mac[32]);
//
// Parameters (AAPCS):
//   x0: key, x1: key_len, x2: msg, x3: msg_len, x4: mac
//
// HMAC(K, M) = H(K ^ opad || H(K ^ ipad || M)), RFC 2104. A key longer than a
// block is hashed down first.
.globl FUNC(redoubt_hmac_sha256)
HIDDEN_FUNC(redoubt_hmac_sha256)
.p2align 4
FUNC(redoubt_hmac_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HMAC_KPAD holds the key padded to a block, and
// ║ HMAC_IPAD and HMAC_OPAD the key xored with public constants — each is the
// ║ key. HMAC_KHASH holds the key hashed down, HMAC_H a state with a pad
// ║ folded in, and HMAC_INNER the inner digest.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HMAC

    str     x30, [sp, #HMAC_LR]
    str     x0, [sp, #HMAC_KEY]
    str     x1, [sp, #HMAC_KEYLEN]
    str     x2, [sp, #HMAC_MSG]
    str     x3, [sp, #HMAC_MSGLEN]
    str     x4, [sp, #HMAC_MAC]

    cmp     x1, #64
    b.le    .Lhmac_key_short

    add     x2, sp, #HMAC_KHASH
    bl      FUNC(redoubt_sha256_hash)

    add     x0, sp, #HMAC_KHASH
    add     x1, sp, #HMAC_KPAD
    ldp     x2, x3, [x0]
    stp     x2, x3, [x1]
    ldp     x2, x3, [x0, #16]
    stp     x2, x3, [x1, #16]

    stp     xzr, xzr, [x1, #32]
    stp     xzr, xzr, [x1, #48]

    b       .Lhmac_key_ready

.Lhmac_key_short:
    add     x1, sp, #HMAC_KPAD
    stp     xzr, xzr, [x1]
    stp     xzr, xzr, [x1, #16]
    stp     xzr, xzr, [x1, #32]
    stp     xzr, xzr, [x1, #48]

    ldr     x4, [sp, #HMAC_KEY]
    ldr     x5, [sp, #HMAC_KEYLEN]
    mov     x16, #0
.Lhmac_copy_key:
    cmp     x16, x5
    b.ge    .Lhmac_key_ready
    ldrb    w17, [x4, x16]
    strb    w17, [x1, x16]
    add     x16, x16, #1
    b       .Lhmac_copy_key

.Lhmac_key_ready:
    mov     w0, #0x36
    mov     w1, #0x5c
    add     x6, sp, #HMAC_KPAD
    add     x7, sp, #HMAC_IPAD
    add     x8, sp, #HMAC_OPAD
    mov     x16, #0
.Lhmac_xor_loop:
    cmp     x16, #64
    b.ge    .Lhmac_xor_done

    ldrb    w17, [x6, x16]

    eor     w2, w17, w0
    strb    w2, [x7, x16]

    eor     w2, w17, w1
    strb    w2, [x8, x16]

    add     x16, x16, #1
    b       .Lhmac_xor_loop

.Lhmac_xor_done:

#if defined(__APPLE__)
    adrp    x0, .LH256_INIT@PAGE
    add     x0, x0, .LH256_INIT@PAGEOFF
#else
    adrp    x0, .LH256_INIT
    add     x0, x0, :lo12:.LH256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #HMAC_H
    st1     {v0.4s, v1.4s}, [x0]

    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_IPAD
    bl      FUNC(redoubt_sha256_compress_block)

    add     x0, sp, #HMAC_H
    ldr     x1, [sp, #HMAC_MSG]
    ldr     x2, [sp, #HMAC_MSGLEN]
    add     x3, x2, #64
    add     x4, sp, #HMAC_INNER
    bl      .Lsha256_update_finalize

#if defined(__APPLE__)
    adrp    x0, .LH256_INIT@PAGE
    add     x0, x0, .LH256_INIT@PAGEOFF
#else
    adrp    x0, .LH256_INIT
    add     x0, x0, :lo12:.LH256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #HMAC_H
    st1     {v0.4s, v1.4s}, [x0]

    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_OPAD
    bl      FUNC(redoubt_sha256_compress_block)

    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_INNER
    mov     x2, #32
    mov     x3, #96
    ldr     x4, [sp, #HMAC_MAC]
    bl      .Lsha256_update_finalize

    ldr     x30, [sp, #HMAC_LR]

    HKDF_EMPTY_FRAME FRAME_HMAC
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// sha256_absorb
// ============================================================================
//
// C signature:
//   void sha256_absorb(uint32_t H[8], const uint8_t *src, size_t len,
//                      uint8_t block[64], size_t *fill);
//
// Parameters (AAPCS):
//   x0: H, x1: src, x2: len, x3: block (filled across calls),
//   x4: fill (how much of block is used; read and written)
//
// Appends the run to the block and folds it into H each time it fills. The
// block and its count are the caller's and are not emptied here: the next call
// continues them.
//
// No name outside this file: a symbol a linked library could collide with is
// resolved by the linker without a word. The probe reaches it by trampoline.
.p2align 4
.Lsha256_absorb:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: no message bytes, only the arguments — but ABSORB_H
// ║ and ABSORB_SRC point into the caller's secrets.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_ABSORB

    str     x30, [sp, #ABSORB_LR]
    str     x0, [sp, #ABSORB_H]
    str     x1, [sp, #ABSORB_SRC]
    str     x2, [sp, #ABSORB_LEFT]
    str     x3, [sp, #ABSORB_BLOCK]
    str     x4, [sp, #ABSORB_FILL]

.Labsorb_loop:
    ldr     x2, [sp, #ABSORB_LEFT]
    cbz     x2, .Labsorb_done

    ldr     x4, [sp, #ABSORB_FILL]
    ldr     x5, [x4]
    ldr     x3, [sp, #ABSORB_BLOCK]
    ldr     x1, [sp, #ABSORB_SRC]

    ldrb    w6, [x1]
    strb    w6, [x3, x5]

    add     x1, x1, #1
    sub     x2, x2, #1
    add     x5, x5, #1
    str     x1, [sp, #ABSORB_SRC]
    str     x2, [sp, #ABSORB_LEFT]
    str     x5, [x4]

    cmp     x5, #64
    b.lo    .Labsorb_loop

    ldr     x0, [sp, #ABSORB_H]
    ldr     x1, [sp, #ABSORB_BLOCK]
    bl      FUNC(redoubt_sha256_compress_block)

    ldr     x4, [sp, #ABSORB_FILL]
    str     xzr, [x4]
    b       .Labsorb_loop

.Labsorb_done:
    ldr     x30, [sp, #ABSORB_LR]

    HKDF_EMPTY_FRAME FRAME_ABSORB
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// hkdf_sha256
// ============================================================================
//
// C signature:
//   void redoubt_hkdf_sha256(const uint8_t *salt, size_t salt_len,
//                            const uint8_t *ikm, size_t ikm_len,
//                            const uint8_t *info, size_t info_len,
//                            uint8_t *okm, size_t okm_len);
//
// Parameters (AAPCS):
//   x0: salt, x1: salt_len, x2: ikm, x3: ikm_len, x4: info, x5: info_len,
//   x6: okm, x7: okm_len
//
// PRK = HMAC(salt, IKM), then T(i) = HMAC(PRK, T(i-1) || info || i), RFC 5869.
// The expansion feeds T(i-1), info and the counter to the hash where they lie
// rather than calling hmac_sha256, which would want them in one buffer sized
// from info_len — and a frame whose size is not a constant cannot be measured.
// The counter is written as one byte and never checked: the caller refuses a
// length past 255 blocks, where it would wrap.
.globl FUNC(redoubt_hkdf_sha256)
HIDDEN_FUNC(redoubt_hkdf_sha256)
.p2align 4
FUNC(redoubt_hkdf_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HKDF_PRK holds the extracted key every byte of output
// ║ comes from, and HKDF_IPAD and HKDF_OPAD that key xored with public
// ║ constants. HKDF_H holds a state with a pad folded in, HKDF_INNER the
// ║ inner digest, HKDF_T a block of the output, and HKDF_BLOCK the tail of
// ║ the message being hashed.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HKDF

    // The salt and the IKM stay where the caller put them: the extraction below
    // reads them straight from x0-x3, and nothing reads them again.
    str     x30, [sp, #HKDF_LR]
    str     x4, [sp, #HKDF_INFO]
    str     x5, [sp, #HKDF_INFOLEN]
    str     x6, [sp, #HKDF_OKM]
    str     x7, [sp, #HKDF_OKMLEN]

    add     x4, sp, #HKDF_PRK
    bl      FUNC(redoubt_hmac_sha256)

    // PRK is thirty-two bytes, inside a block, so it needs no hashing down and
    // the bytes past it pad with zeros, as RFC 2104 asks.
    add     x6, sp, #HKDF_PRK
    add     x7, sp, #HKDF_IPAD
    add     x8, sp, #HKDF_OPAD
    mov     w0, #0x36
    mov     w1, #0x5c
    mov     x16, #0
.Lhkdf_pad_loop:
    cmp     x16, #64
    b.ge    .Lhkdf_pad_done

    mov     w17, wzr
    cmp     x16, #32
    b.ge    .Lhkdf_pad_byte
    ldrb    w17, [x6, x16]

.Lhkdf_pad_byte:
    eor     w2, w17, w0
    strb    w2, [x7, x16]

    eor     w2, w17, w1
    strb    w2, [x8, x16]

    add     x16, x16, #1
    b       .Lhkdf_pad_loop

.Lhkdf_pad_done:
    mov     x0, #1
    str     x0, [sp, #HKDF_COUNTER]
    str     xzr, [sp, #HKDF_TLEN]

.Lhkdf_expand_loop:
    ldr     x0, [sp, #HKDF_OKMLEN]
    cbz     x0, .Lhkdf_done

#if defined(__APPLE__)
    adrp    x0, .LH256_INIT@PAGE
    add     x0, x0, .LH256_INIT@PAGEOFF
#else
    adrp    x0, .LH256_INIT
    add     x0, x0, :lo12:.LH256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #HKDF_H
    st1     {v0.4s, v1.4s}, [x0]

    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_IPAD
    bl      FUNC(redoubt_sha256_compress_block)

    str     xzr, [sp, #HKDF_FILL]

    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_T
    ldr     x2, [sp, #HKDF_TLEN]
    add     x3, sp, #HKDF_BLOCK
    add     x4, sp, #HKDF_FILL
    bl      .Lsha256_absorb

    add     x0, sp, #HKDF_H
    ldr     x1, [sp, #HKDF_INFO]
    ldr     x2, [sp, #HKDF_INFOLEN]
    add     x3, sp, #HKDF_BLOCK
    add     x4, sp, #HKDF_FILL
    bl      .Lsha256_absorb

    // The counter closes the message, so it goes into the block rather than
    // through the absorb: what is left is one partial block for the padding.
    ldr     x5, [sp, #HKDF_FILL]
    ldr     x6, [sp, #HKDF_COUNTER]
    add     x7, sp, #HKDF_BLOCK
    strb    w6, [x7, x5]
    add     x5, x5, #1

    ldr     x9, [sp, #HKDF_TLEN]
    ldr     x10, [sp, #HKDF_INFOLEN]
    add     x9, x9, x10
    add     x9, x9, #65

    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_BLOCK
    mov     x2, x5
    mov     x3, x9
    add     x4, sp, #HKDF_INNER
    bl      .Lsha256_update_finalize

#if defined(__APPLE__)
    adrp    x0, .LH256_INIT@PAGE
    add     x0, x0, .LH256_INIT@PAGEOFF
#else
    adrp    x0, .LH256_INIT
    add     x0, x0, :lo12:.LH256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #HKDF_H
    st1     {v0.4s, v1.4s}, [x0]

    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_OPAD
    bl      FUNC(redoubt_sha256_compress_block)

    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_INNER
    mov     x2, #32
    mov     x3, #96
    add     x4, sp, #HKDF_T
    bl      .Lsha256_update_finalize

    ldr     x10, [sp, #HKDF_OKMLEN]
    mov     x11, #32
    cmp     x10, #32
    csel    x11, x10, x11, lo

    ldr     x12, [sp, #HKDF_OKM]
    add     x13, sp, #HKDF_T
    mov     x16, #0
.Lhkdf_emit_loop:
    cmp     x16, x11
    b.ge    .Lhkdf_emitted
    ldrb    w17, [x13, x16]
    strb    w17, [x12, x16]
    add     x16, x16, #1
    b       .Lhkdf_emit_loop

.Lhkdf_emitted:
    add     x12, x12, x11
    str     x12, [sp, #HKDF_OKM]
    sub     x10, x10, x11
    str     x10, [sp, #HKDF_OKMLEN]

    ldr     x0, [sp, #HKDF_COUNTER]
    add     x0, x0, #1
    str     x0, [sp, #HKDF_COUNTER]
    mov     x0, #32
    str     x0, [sp, #HKDF_TLEN]
    b       .Lhkdf_expand_loop

.Lhkdf_done:
    ldr     x30, [sp, #HKDF_LR]

    HKDF_EMPTY_FRAME FRAME_HKDF
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// A 64-bit pattern built in place a quarter at a time: no single instruction
// holds it, and a literal pool would put it in memory.
.macro HKDF_PROBE_PATTERN reg, half
    movz    \reg, #\half
    movk    \reg, #\half, lsl #16
    movk    \reg, #\half, lsl #32
    movk    \reg, #\half, lsl #48
.endm

// uint64_t redoubt_hkdf_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because x0 is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
//
// The vectors gather first, and `orr` over `.16b` touches no general register,
// so x0 is still the caller's when the general gather reads it. Both lanes of
// the vector fold reach the answer: which lane a bit came from is lost, whether
// there was one is not.
.p2align 4
.globl FUNC(redoubt_hkdf_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hkdf_registers_are_zeroized)
FUNC(redoubt_hkdf_registers_are_zeroized):
    HKDF_EACH_VECTOR HKDF_GATHER_VECTOR

    HKDF_EACH_GPR HKDF_GATHER_GPR

    umov    x2, v0.d[0]
    orr     x1, x1, x2
    umov    x3, v0.d[1]
    orr     x1, x1, x3

    mov     x0, x1
    ret

// Every register in the budget filled with a pattern, both lanes of each
// vector, and left that way.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_registers)
HIDDEN_FUNC(redoubt_hkdf_dirty_registers)
FUNC(redoubt_hkdf_dirty_registers):
    HKDF_PROBE_PATTERN x0, 0xa5a5
    dup     v0.2d, x0
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    HKDF_EACH_GPR HKDF_FILL_GPR
    ret

// The low lane of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only be those lanes.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_vector_low)
HIDDEN_FUNC(redoubt_hkdf_dirty_vector_low)
FUNC(redoubt_hkdf_dirty_vector_low):
    HKDF_SHA256_ZEROIZE_ALL
    HKDF_PROBE_PATTERN x0, 0xa5a5
    mov     v0.d[0], x0
    mov     x0, xzr
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    ret

// The high lane of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only come through its
// fold.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_vector_high)
HIDDEN_FUNC(redoubt_hkdf_dirty_vector_high)
FUNC(redoubt_hkdf_dirty_vector_high):
    HKDF_SHA256_ZEROIZE_ALL
    HKDF_PROBE_PATTERN x0, 0xa5a5
    mov     v0.d[1], x0
    mov     x0, xzr
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    ret

// The frame instruments for a routine whose frame is \size bytes.
//
// uint64_t redoubt_hkdf_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `bl`
//   keeps the return address in x30 and leaves sp where the previous callee
//   found it, so `[sp - \size, sp)` is the frame that callee took. Asked after
//   the registers, never before: reading the frame takes registers.
//
// void redoubt_hkdf_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in x0, marked and left.
//
// void redoubt_hkdf_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro HKDF_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_hkdf_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_hkdf_frame_is_zeroized_\name)
FUNC(redoubt_hkdf_frame_is_zeroized_\name):
    mov     x0, xzr
    sub     x1, sp, #\size
    mov     x2, sp
1:
    ldr     x3, [x1], #8
    orr     x0, x0, x3
    cmp     x1, x2
    b.lo    1b
    ret

.p2align 4
.globl FUNC(redoubt_hkdf_dirty_frame_\name)
HIDDEN_FUNC(redoubt_hkdf_dirty_frame_\name)
FUNC(redoubt_hkdf_dirty_frame_\name):
    sub     sp, sp, #\size
    // The frame is emptied before the byte goes in, so that what a verifier
    // finds is this byte and not a previous call's residue.
    mov     x1, xzr
2:
    str     xzr, [sp, x1]
    add     x1, x1, #8
    cmp     x1, #\size
    b.lo    2b
    mov     w2, #0x5c
    strb    w2, [sp, x0]
    add     sp, sp, #\size
    ret

.p2align 4
.globl FUNC(redoubt_hkdf_clean_frame_\name)
HIDDEN_FUNC(redoubt_hkdf_clean_frame_\name)
FUNC(redoubt_hkdf_clean_frame_\name):
    sub     sp, sp, #\size
    HKDF_PROBE_PATTERN x0, 0x5c5c
    mov     x1, xzr
3:
    str     x0, [sp, x1]
    add     x1, x1, #8
    cmp     x1, #\size
    b.lo    3b
    HKDF_EMPTY_FRAME \size
    HKDF_SHA256_ZEROIZE_ALL
    ret
.endm

// The routines with no name outside this file, given one for a measurement. A
// `b` and not a `bl`: it leaves sp and x30 as they arrived, so the routine
// takes its frame where the verifier will read it and returns to the test.
.p2align 4
.globl FUNC(redoubt_hkdf_probe_update_finalize)
HIDDEN_FUNC(redoubt_hkdf_probe_update_finalize)
FUNC(redoubt_hkdf_probe_update_finalize):
    b       .Lsha256_update_finalize

.p2align 4
.globl FUNC(redoubt_hkdf_probe_absorb)
HIDDEN_FUNC(redoubt_hkdf_probe_absorb)
FUNC(redoubt_hkdf_probe_absorb):
    b       .Lsha256_absorb

HKDF_FRAME_PROBE compress_block, FRAME_COMPRESS
HKDF_FRAME_PROBE hash, FRAME_HASH
HKDF_FRAME_PROBE update_finalize, FRAME_UPDATE
HKDF_FRAME_PROBE hmac, FRAME_HMAC
HKDF_FRAME_PROBE absorb, FRAME_ABSORB
HKDF_FRAME_PROBE hkdf, FRAME_HKDF

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
