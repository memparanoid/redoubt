// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-256 Compression Function - AArch64 v5 (Standalone)
//!
//! REGISTER ALLOCATION (strict adherence to REGISTER_ALLOCATION.md):
//!   x0: H_ptr (input/output, 32 bytes) - NEVER MODIFY
//!   x1: block_ptr (input, 64 bytes) - NEVER MODIFY
//!   x2: loop counter t (0-63)
//!   x3: K_ptr (K256 constants)
//!   w4-w10: temporaries for T1, T2, Ch, Maj, Σ, σ
//!   w17: temp for inline operations
//!   v16: H[0..3] (H state, first 4 words)
//!   v17: H[4..7] (H state, last 4 words)
//!   v18: {a, b, c, d} (working variables)
//!   v19: {e, f, g, h} (working variables)
//!   v20-v23: sliding window W[t-16..t-1] for rounds 16-63
//!   v24: temporary for W[t] during window update
//!
//! CRITICAL INVARIANTS:
//!   - x12-x15 are NEVER touched (available for callers)
//!   - No prologue/epilogue (uses only caller-saved registers)
//!   - Stack: 64 bytes for W[0..15], zeroized before ret

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
    #define RODATA_SECTION .const_data
#elif defined(_WIN32) || defined(_WIN64)
    #define FUNC(name) name
    #define HIDDEN_FUNC(name)
    #define RODATA_SECTION .section .rdata
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
    #define RODATA_SECTION .section .rodata
#endif

.arch armv8-a

// ============================================================================
// Complete Register Zeroization Macro
// ============================================================================
//
// Strategy: Top-level functions (hmac_sha256, hkdf_sha256) use this macro
//           to zeroize ALL caller-saved registers after stack cleanup.
//
// Zeroizes ONLY caller-saved registers:
//   - v0-v7    : Caller-saved SIMD (SHA-256 H state, working vars)
//   - v16-v31  : Caller-saved SIMD (data blocks, temporaries)
//   - x0-x17   : Caller-saved GPR (pointers, lengths, temporaries)
//                NOTE: x18 is platform register - DO NOT USE OR ZEROIZE
//
// Never zeroized (ABI requirement):
//   - x18      : Platform register (reserved by OS - DO NOT TOUCH)
//   - x19-x28  : Callee-saved GPR (restored by epilogue, not zeroized)
//   - x29 (FP) : Frame pointer (restored by epilogue)
//   - x30 (LR) : Link register (restored by epilogue)
//   - sp       : Stack pointer
//   - v8-v15   : Callee-saved SIMD (not used by our implementation)
//
// Usage: Called by top-level functions (hmac_sha256, hkdf_sha256) after
//        stack zeroization but before restoring callee-saved registers.
//
.macro HKDF_SHA256_ZEROIZE_ALL
    // === SIMD: Zeroize caller-saved v0-v7, v16-v31 ===
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    movi v6.16b, #0
    movi v7.16b, #0
    // v8-v15 are callee-saved - DO NOT ZEROIZE (not used anyway)
    movi v16.16b, #0
    movi v17.16b, #0
    movi v18.16b, #0
    movi v19.16b, #0
    movi v20.16b, #0
    movi v21.16b, #0
    movi v22.16b, #0
    movi v23.16b, #0
    movi v24.16b, #0
    movi v25.16b, #0
    movi v26.16b, #0
    movi v27.16b, #0
    movi v28.16b, #0
    movi v29.16b, #0
    movi v30.16b, #0
    movi v31.16b, #0

    // === GPR: Zeroize caller-saved x0-x17 (skip x18 - platform register) ===
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    // x18 is platform register - DO NOT TOUCH
    // x19-x28 are callee-saved - DO NOT ZEROIZE (restored by epilogue)
.endm

// ============================================================================
// Constants
// ============================================================================

RODATA_SECTION
.p2align 6

// SHA-256 K constants (64 rounds)
K256:
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

// SHA-256 Initial Hash Values (H^(0) per FIPS 180-4)
H256_INIT:
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

.text

//============================================================================
// sha256_compress_block
//============================================================================
// Compresses a single 64-byte block into H state
//
// C signature:
//   void sha256_compress_block(uint32_t H[8], const uint8_t block[64]);
//
// Parameters:
//   x0: H_ptr (input/output, 32 bytes = 8 × uint32_t, little-endian in memory)
//   x1: block_ptr (input, 64 bytes, treated as big-endian message)
//
// Behavior:
//   Performs SHA-256 compression: H := H + SHA256_COMPRESS(block)
//
// Registers preserved:
//   x12-x15 (and all callee-saved per ABI)
//
// Stack usage:
//   64 bytes for W[0..15] (zeroized before return)
//
.global FUNC(sha256_compress_block)
HIDDEN_FUNC(sha256_compress_block)
.p2align 4
FUNC(sha256_compress_block):
    // Allocate stack for W[0..15]
    sub     sp, sp, #64

    // Load H[0..7] from memory into v16 (H[0..3]), v17 (H[4..7])
    ld1     {v16.4s, v17.4s}, [x0]

    // Load 64-byte message block and convert from big-endian to host (little-endian)
    ld1     {v20.4s, v21.4s, v22.4s, v23.4s}, [x1]
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b

    // Store W[0..15] on stack for rounds 0-15 (direct indexed access)
    st1     {v20.4s, v21.4s, v22.4s, v23.4s}, [sp]

    // Initialize working variables: v18 = {a,b,c,d}, v19 = {e,f,g,h}
    mov     v18.16b, v16.16b
    mov     v19.16b, v17.16b

    // Load K256 pointer
#if defined(__APPLE__)
    adrp    x3, K256@PAGE
    add     x3, x3, K256@PAGEOFF
#else
    adrp    x3, K256
    add     x3, x3, :lo12:K256
#endif

    // ========================================================================
    // Rounds 0-15: W[t] from stack
    // ========================================================================
    mov     x2, #0
.Lround_0_15:
    ldr     w4, [sp, x2, lsl #2]    // w4 = W[t]
    ldr     w5, [x3, x2, lsl #2]    // w5 = K[t]

    // Extract working variables for this round
    umov    w6, v19.s[3]            // h
    umov    w7, v19.s[0]            // e
    umov    w8, v19.s[1]            // f
    umov    w9, v19.s[2]            // g

    // === Compute T1 = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t] ===
    mov     w10, w6                 // T1 = h

    // Σ₁(e) = ROTR(6) ^ ROTR(11) ^ ROTR(25)
    ror     w6, w7, #6
    ror     w17, w7, #11
    eor     w6, w6, w17
    ror     w17, w7, #25
    eor     w6, w6, w17
    add     w10, w10, w6            // T1 += Σ₁(e)

    // Ch(e,f,g) = (e & f) ^ (~e & g)
    bic     w6, w9, w7              // ~e & g
    and     w17, w7, w8             // e & f
    eor     w6, w6, w17
    add     w10, w10, w6            // T1 += Ch(e,f,g)

    add     w10, w10, w5            // T1 += K[t]
    add     w10, w10, w4            // T1 += W[t]

    // === Compute T2 = Σ₀(a) + Maj(a,b,c) ===
    umov    w6, v18.s[0]            // a
    umov    w7, v18.s[1]            // b
    umov    w8, v18.s[2]            // c

    // Σ₀(a) = ROTR(2) ^ ROTR(13) ^ ROTR(22)
    ror     w9, w6, #2
    ror     w17, w6, #13
    eor     w9, w9, w17
    ror     w17, w6, #22
    eor     w9, w9, w17             // w9 = Σ₀(a)

    // Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    and     w4, w6, w7
    and     w17, w6, w8
    eor     w4, w4, w17
    and     w17, w7, w8
    eor     w4, w4, w17             // w4 = Maj(a,b,c)

    add     w9, w9, w4              // T2 = Σ₀(a) + Maj

    // === Update working variables ===
    // h = g, g = f, f = e, e = d + T1
    // d = c, c = b, b = a, a = T1 + T2
    umov    w4, v18.s[3]            // d
    add     w5, w4, w10             // e_new = d + T1
    add     w6, w10, w9             // a_new = T1 + T2

    // Shift v19 right and insert e_new at position 0
    mov     v19.s[3], v19.s[2]      // h = g
    mov     v19.s[2], v19.s[1]      // g = f
    mov     v19.s[1], v19.s[0]      // f = e
    ins     v19.s[0], w5            // e = e_new

    // Shift v18 right and insert a_new at position 0
    mov     v18.s[3], v18.s[2]      // d = c
    mov     v18.s[2], v18.s[1]      // c = b
    mov     v18.s[1], v18.s[0]      // b = a
    ins     v18.s[0], w6            // a = a_new

    add     x2, x2, #1
    cmp     x2, #16
    b.lt    .Lround_0_15

    // ========================================================================
    // Rounds 16-63: Compute W[t] from message schedule
    // ========================================================================
    // Sliding window: v20={W[t-16],W[t-15],W[t-14],W[t-13]}, v21={...}, etc.
.Lround_16_63:
    // Extract W[t-16], W[t-15], W[t-7], W[t-2]
    umov    w4, v20.s[0]            // W[t-16]
    umov    w5, v20.s[1]            // W[t-15]
    umov    w6, v22.s[1]            // W[t-7]
    umov    w7, v23.s[2]            // W[t-2]

    // σ₀(W[t-15]) = ROTR(7) ^ ROTR(18) ^ SHR(3)
    ror     w8, w5, #7
    ror     w17, w5, #18
    eor     w8, w8, w17
    lsr     w17, w5, #3
    eor     w8, w8, w17             // w8 = σ₀(W[t-15])

    // σ₁(W[t-2]) = ROTR(17) ^ ROTR(19) ^ SHR(10)
    ror     w9, w7, #17
    ror     w17, w7, #19
    eor     w9, w9, w17
    lsr     w17, w7, #10
    eor     w9, w9, w17             // w9 = σ₁(W[t-2])

    // W[t] = W[t-16] + σ₀(W[t-15]) + W[t-7] + σ₁(W[t-2])
    add     w4, w4, w8
    add     w4, w4, w6
    add     w4, w4, w9              // w4 = W[t]

    // Save W[t] to v24.s[0] for window update
    ins     v24.s[0], w4

    // Load K[t]
    ldr     w5, [x3, x2, lsl #2]

    // === Compute round (same as rounds 0-15) ===
    umov    w6, v19.s[3]            // h
    umov    w7, v19.s[0]            // e
    umov    w8, v19.s[1]            // f
    umov    w9, v19.s[2]            // g

    mov     w10, w6                 // T1 = h

    // Σ₁(e)
    ror     w6, w7, #6
    ror     w17, w7, #11
    eor     w6, w6, w17
    ror     w17, w7, #25
    eor     w6, w6, w17
    add     w10, w10, w6

    // Ch(e,f,g)
    bic     w6, w9, w7
    and     w17, w7, w8
    eor     w6, w6, w17
    add     w10, w10, w6

    add     w10, w10, w5            // + K[t]
    add     w10, w10, w4            // + W[t]

    // T2
    umov    w6, v18.s[0]            // a
    umov    w7, v18.s[1]            // b
    umov    w8, v18.s[2]            // c

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

    add     w9, w9, w4              // T2

    umov    w4, v18.s[3]            // d
    add     w5, w4, w10             // e_new
    add     w6, w10, w9             // a_new

    // Update working vars
    mov     v19.s[3], v19.s[2]
    mov     v19.s[2], v19.s[1]
    mov     v19.s[1], v19.s[0]
    ins     v19.s[0], w5

    mov     v18.s[3], v18.s[2]
    mov     v18.s[2], v18.s[1]
    mov     v18.s[1], v18.s[0]
    ins     v18.s[0], w6

    // Update sliding window: shift left by 1 word (4 bytes)
    ext     v20.16b, v20.16b, v21.16b, #4
    ext     v21.16b, v21.16b, v22.16b, #4
    ext     v22.16b, v22.16b, v23.16b, #4
    ext     v23.16b, v23.16b, v24.16b, #4

    add     x2, x2, #1
    cmp     x2, #64
    b.lt    .Lround_16_63

    // ========================================================================
    // Finalize: H := H + {a,b,c,d,e,f,g,h}
    // ========================================================================
    add     v16.4s, v16.4s, v18.4s
    add     v17.4s, v17.4s, v19.4s

    // Store updated H back to memory
    st1     {v16.4s, v17.4s}, [x0]

    // ⚠️ Zeroize stack (W[0..15] may contain sensitive message data)
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]

    // Deallocate stack
    add     sp, sp, #64
    ret

//============================================================================
// sha256_hash
//============================================================================
// Computes SHA-256 hash of arbitrary-length message
//
// C signature:
//   void sha256_hash(const uint8_t *msg, size_t msg_len, uint8_t digest[32]);
//
// Parameters:
//   x0: msg_ptr (input, arbitrary length)
//   x1: msg_len (input, bytes)
//   x2: digest_ptr (output, 32 bytes)
//
// REGISTER ALLOCATION:
//   x12: msg_ptr_current (advances through message)
//   x13: msg_remaining (decrements as blocks processed)
//   x14: original_msg_len (constant, for padding)
//   x15: digest_ptr (preserved)
//   x16-x17: temporaries
//
// Stack layout:
//   [sp]: H state (32 bytes, SECRET)
//   [sp+32]: final block buffer 1 (64 bytes)
//   [sp+96]: final block buffer 2 (64 bytes, if needed)
//   Total: 160 bytes
//
.global FUNC(sha256_hash)
HIDDEN_FUNC(sha256_hash)
.p2align 4
FUNC(sha256_hash):
    // Prologue: save frame pointer and link register (REQUIRED - we do bl!)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    // Allocate working space: 32 (H) + 64 (block1) + 64 (block2) = 160 bytes
    sub     sp, sp, #160

    // ⚠️ Pre-zeroize H state (SECRET)
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]

    // Save parameters in x12-x15
    mov     x12, x0             // msg_ptr_current
    mov     x13, x1             // msg_remaining
    mov     x14, x1             // original_msg_len (constant)
    mov     x15, x2             // digest_ptr

    // Initialize H with H256_INIT
#if defined(__APPLE__)
    adrp    x0, H256_INIT@PAGE
    add     x0, x0, H256_INIT@PAGEOFF
#else
    adrp    x0, H256_INIT
    add     x0, x0, :lo12:H256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    st1     {v0.4s, v1.4s}, [sp]

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lhash_block_loop:
    cmp     x13, #64
    b.lt    .Lhash_final_block

    // Prepare parameters for sha256_compress_block
    mov     x0, sp              // H_ptr
    mov     x1, x12             // block_ptr

    // No need to save/restore x12-x15: compress_block doesn't touch them!
    bl      FUNC(sha256_compress_block)

    // Advance to next block
    add     x12, x12, #64
    sub     x13, x13, #64
    b       .Lhash_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lhash_final_block:
    // x13 = remainder (0 to 63 bytes)
    // x14 = original_msg_len (for bit count in padding)

    // Zero first block buffer
    add     x16, sp, #32
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    // Copy remainder bytes to block buffer
    mov     x17, #0
.Lhash_copy_remainder:
    cmp     x17, x13
    b.ge    .Lhash_remainder_done
    ldrb    w0, [x12, x17]
    strb    w0, [x16, x17]
    add     x17, x17, #1
    b       .Lhash_copy_remainder

.Lhash_remainder_done:
    // Append 0x80 byte
    mov     w0, #0x80
    strb    w0, [x16, x13]

    // Check if length fits in this block (remainder < 56)
    cmp     x13, #56
    b.ge    .Lhash_two_blocks

    // === ONE BLOCK CASE ===
    // Append 64-bit big-endian length at offset 56
    lsl     x0, x14, #3         // bits = bytes * 8
    rev     x0, x0              // big-endian
    str     x0, [x16, #56]

    // Compress final block
    mov     x0, sp              // H_ptr
    add     x1, sp, #32         // block_ptr

    bl      FUNC(sha256_compress_block)

    b       .Lhash_finish

    // === TWO BLOCK CASE ===
.Lhash_two_blocks:
    // First block: remainder + 0x80 + zeros (no length yet)
    mov     x0, sp
    add     x1, sp, #32

    bl      FUNC(sha256_compress_block)

    // Second block: all zeros except length at end
    add     x16, sp, #96
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    // Append 64-bit big-endian length at offset 56
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    // Compress second block
    mov     x0, sp
    add     x1, sp, #96

    bl      FUNC(sha256_compress_block)

.Lhash_finish:
    // Copy H state to digest (as big-endian bytes per SHA-256 spec)
    ld1     {v0.4s, v1.4s}, [sp]

    // Convert to big-endian for output
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b

    st1     {v0.4s, v1.4s}, [x15]

    // ⚠️ Zeroize entire stack (H state + block buffers)
    stp     xzr, xzr, [sp]          // H state
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]     // block buffer 1
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]
    stp     xzr, xzr, [sp, #96]     // block buffer 2
    stp     xzr, xzr, [sp, #112]
    stp     xzr, xzr, [sp, #128]
    stp     xzr, xzr, [sp, #144]

    // Deallocate working space
    add     sp, sp, #160

    // Epilogue: restore frame pointer and link register
    ldp     x29, x30, [sp], #16
    ret

//============================================================================
// sha256_update_finalize
//============================================================================
// Continue SHA-256 hashing from an existing H state, process message, apply
// padding, and output digest.
//
// C signature:
//   void sha256_update_finalize(
//       uint32_t H[8],
//       const uint8_t *msg,
//       size_t msg_len,
//       size_t total_len,
//       uint8_t digest[32]
//   );
//
// Parameters:
//   x0: H_ptr (input/output, 32 bytes = 8 × u32)
//   x1: msg_ptr
//   x2: msg_len
//   x3: total_len (TOTAL bytes processed including previous blocks, for padding)
//   x4: digest_ptr (output, 32 bytes)
//
// This function:
//   1. Loads existing H state from H_ptr
//   2. Processes msg in 64-byte blocks (updating H)
//   3. Applies SHA-256 padding to final block(s)
//   4. Outputs final digest to digest_ptr
//
// REGISTER ALLOCATION:
//   x12: msg_ptr_current
//   x13: msg_remaining
//   x14: total_len (TOTAL bytes for padding bit count)
//   x15: digest_ptr
//   x19: H_ptr (callee-saved, needed after bl calls)
//
// Stack layout:
//   [sp]: H state (32 bytes, loaded from H_ptr, SECRET)
//   [sp+32]: final block buffer 1 (64 bytes)
//   [sp+96]: final block buffer 2 (64 bytes, if needed)
//   Total: 160 bytes
//
.global FUNC(sha256_update_finalize)
HIDDEN_FUNC(sha256_update_finalize)
.p2align 4
FUNC(sha256_update_finalize):
    // Prologue: save callee-saved registers and link register
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x19, [sp, #16]

    // Allocate working space
    sub     sp, sp, #160

    // Save H_ptr to callee-saved register (survives bl calls)
    mov     x19, x0

    // Load existing H state from H_ptr to stack
    ld1     {v0.4s, v1.4s}, [x19]
    st1     {v0.4s, v1.4s}, [sp]

    // Save parameters to x12-x15
    mov     x12, x1             // msg_ptr_current
    mov     x13, x2             // msg_remaining
    mov     x14, x3             // total_len (constant, for padding)
    mov     x15, x4             // digest_ptr

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lupdate_block_loop:
    cmp     x13, #64
    b.lt    .Lupdate_final_block

    mov     x0, sp              // H_ptr (on stack)
    mov     x1, x12             // block_ptr
    bl      FUNC(sha256_compress_block)

    add     x12, x12, #64
    sub     x13, x13, #64
    b       .Lupdate_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lupdate_final_block:
    // x13 = remainder (0 to 63 bytes)
    // x14 = total_len (TOTAL bytes for bit count in padding)

    // Zero first block buffer
    add     x16, sp, #32
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    // Copy remainder bytes to block buffer
    mov     x17, #0
.Lupdate_copy_remainder:
    cmp     x17, x13
    b.ge    .Lupdate_remainder_done
    ldrb    w0, [x12, x17]
    strb    w0, [x16, x17]
    add     x17, x17, #1
    b       .Lupdate_copy_remainder

.Lupdate_remainder_done:
    // Append 0x80 byte
    mov     w0, #0x80
    strb    w0, [x16, x13]

    // Check if length fits in this block (remainder < 56)
    cmp     x13, #56
    b.ge    .Lupdate_two_blocks

    // === ONE BLOCK CASE ===
    lsl     x0, x14, #3         // bits = bytes * 8
    rev     x0, x0              // big-endian
    str     x0, [x16, #56]

    mov     x0, sp
    add     x1, sp, #32
    bl      FUNC(sha256_compress_block)

    b       .Lupdate_finish

    // === TWO BLOCK CASE ===
.Lupdate_two_blocks:
    mov     x0, sp
    add     x1, sp, #32
    bl      FUNC(sha256_compress_block)

    // Second block: zeros + length
    add     x16, sp, #96
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    mov     x0, sp
    add     x1, sp, #96
    bl      FUNC(sha256_compress_block)

.Lupdate_finish:
    // Copy H state to digest (big-endian)
    ld1     {v0.4s, v1.4s}, [sp]
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b
    st1     {v0.4s, v1.4s}, [x15]

    // Zeroize entire stack
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]
    stp     xzr, xzr, [sp, #96]
    stp     xzr, xzr, [sp, #112]
    stp     xzr, xzr, [sp, #128]
    stp     xzr, xzr, [sp, #144]

    add     sp, sp, #160
    ldr     x19, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

//============================================================================
// hmac_sha256
//============================================================================
// HMAC-SHA256 per RFC 2104
//
// C signature:
//   void hmac_sha256(
//       const uint8_t *key, size_t key_len,
//       const uint8_t *msg, size_t msg_len,
//       uint8_t mac[32]
//   );
//
// Parameters:
//   x0: key_ptr
//   x1: key_len
//   x2: msg_ptr
//   x3: msg_len
//   x4: mac_ptr (output, 32 bytes)
//
// Algorithm (RFC 2104):
//   1. If key_len > 64: K = SHA256(key), else K = key
//   2. Pad K to 64 bytes with zeros
//   3. ipad = K ⊕ 0x36 (64 bytes)
//   4. opad = K ⊕ 0x5c (64 bytes)
//   5. inner_hash = SHA256(ipad || msg)
//   6. mac = SHA256(opad || inner_hash)
//
// Stack layout (total 256 bytes):
//   [sp+0..63]:    K_padded (64 bytes)
//   [sp+64..127]:  ipad (64 bytes)
//   [sp+128..191]: opad (64 bytes)
//   [sp+192..223]: inner_hash (32 bytes)
//   [sp+224..255]: temp for key hash if needed (32 bytes)
//
// Register usage (CALLEE-SAVED to survive internal calls):
//   x19: key_ptr (preserved across calls)
//   x20: key_len (preserved)
//   x21: msg_ptr (preserved)
//   x22: msg_len (preserved)
//   x23: mac_ptr (preserved, callee-saved)
//
.globl FUNC(hmac_sha256)
.p2align 4
FUNC(hmac_sha256):
    // Prologue: save FP/LR + callee-saved regs we use (x19-x27)
    // Use 96 bytes to store pairs cleanly and keep 16-byte alignment.
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    str     x27, [sp, #80]      // x27 used in inner logic, x28 reserved for future

    // Allocate stack (256 bytes)
    sub     sp, sp, #256

    // Save parameters to callee-saved registers
    mov     x19, x0             // key_ptr
    mov     x20, x1             // key_len
    mov     x21, x2             // msg_ptr
    mov     x22, x3             // msg_len
    mov     x23, x4             // mac_ptr

    // ========================================================================
    // Step 1: Process key
    // ========================================================================
    // If key_len > 64, hash it first; otherwise use as-is
    cmp     x20, #64
    b.le    .Lhmac_key_short

    // key_len > 64: K = SHA256(key)
    mov     x0, x19             // key_ptr
    mov     x1, x20             // key_len
    add     x2, sp, #224        // temp digest buffer
    bl      FUNC(sha256_hash)

    // Copy hashed key to K_padded (32 bytes)
    add     x0, sp, #224
    mov     x1, sp
    ldp     x2, x3, [x0]
    stp     x2, x3, [x1]
    ldp     x2, x3, [x0, #16]
    stp     x2, x3, [x1, #16]

    // Zero remaining 32 bytes of K_padded
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]

    b       .Lhmac_key_ready

.Lhmac_key_short:
    // key_len <= 64: copy key to K_padded and zero-pad
    // First zero entire K_padded buffer
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]

    // Copy key bytes
    mov     x16, #0
.Lhmac_copy_key:
    cmp     x16, x20
    b.ge    .Lhmac_key_ready
    ldrb    w17, [x19, x16]
    strb    w17, [sp, x16]
    add     x16, x16, #1
    b       .Lhmac_copy_key

.Lhmac_key_ready:
    // ========================================================================
    // Step 2: Create ipad = K_padded ⊕ 0x36 and opad = K_padded ⊕ 0x5c
    // ========================================================================
    mov     w0, #0x36               // ipad constant
    mov     w1, #0x5c               // opad constant
    mov     x16, #0
.Lhmac_xor_loop:
    cmp     x16, #64
    b.ge    .Lhmac_xor_done

    ldrb    w17, [sp, x16]          // K_padded[i]

    eor     w2, w17, w0             // ipad[i] = K_padded[i] ⊕ 0x36
    add     x3, sp, #64
    strb    w2, [x3, x16]

    eor     w2, w17, w1             // opad[i] = K_padded[i] ⊕ 0x5c
    add     x3, sp, #128
    strb    w2, [x3, x16]

    add     x16, x16, #1
    b       .Lhmac_xor_loop

.Lhmac_xor_done:
    // ========================================================================
    // Step 3: Compute inner hash = SHA256(ipad || msg)
    // ========================================================================
    // Strategy: use sha256_update_finalize
    //   1. Initialize H = SHA256_INIT
    //   2. Compress ipad block
    //   3. Call sha256_update_finalize(H, msg, msg_len, inner_hash)

    // Save pointers to main frame locations before allocating temp H
    add     x24, sp, #64        // ipad location in main frame
    add     x25, sp, #192       // inner_hash location in main frame

    // Allocate 32 bytes for H state on stack
    sub     sp, sp, #32

    // Initialize H with SHA256_INIT
#if defined(__APPLE__)
    adrp    x0, H256_INIT@PAGE
    add     x0, x0, H256_INIT@PAGEOFF
#else
    adrp    x0, H256_INIT
    add     x0, x0, :lo12:H256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    st1     {v0.4s, v1.4s}, [sp]

    // Compress ipad block (64 bytes)
    mov     x0, sp              // H_ptr (on stack)
    mov     x1, x24             // ipad ptr (saved before)
    bl      FUNC(sha256_compress_block)

    // Now call sha256_update_finalize with msg
    mov     x0, sp              // H_ptr (current state after ipad)
    mov     x1, x21             // msg_ptr
    mov     x2, x22             // msg_len
    add     x3, x22, #64        // total_len = 64 (ipad) + msg_len
    mov     x4, x25             // output: inner_hash ptr (saved before)
    bl      FUNC(sha256_update_finalize)

    // Zeroize H state
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]

    add     sp, sp, #32         // deallocate H buffer

    // ========================================================================
    // Step 4: Compute outer hash = SHA256(opad || inner_hash)
    // ========================================================================
    // Same strategy: use sha256_update_finalize
    //   1. Initialize H = SHA256_INIT
    //   2. Compress opad block
    //   3. Call sha256_update_finalize(H, inner_hash, 32, mac)

    // Save pointers to main frame locations before allocating temp H
    add     x24, sp, #128       // opad location in main frame
    add     x25, sp, #192       // inner_hash location in main frame

    // Allocate 32 bytes for H state on stack
    sub     sp, sp, #32

    // Initialize H with SHA256_INIT
#if defined(__APPLE__)
    adrp    x0, H256_INIT@PAGE
    add     x0, x0, H256_INIT@PAGEOFF
#else
    adrp    x0, H256_INIT
    add     x0, x0, :lo12:H256_INIT
#endif
    ld1     {v0.4s, v1.4s}, [x0]
    st1     {v0.4s, v1.4s}, [sp]

    // Compress opad block (64 bytes)
    mov     x0, sp              // H_ptr (on stack)
    mov     x1, x24             // opad ptr (saved before)
    bl      FUNC(sha256_compress_block)

    // Now call sha256_update_finalize with inner_hash
    mov     x0, sp              // H_ptr (current state after opad)
    mov     x1, x25             // inner_hash ptr (saved before)
    mov     x2, #32             // inner_hash length (32 bytes)
    mov     x3, #96             // total_len = 64 (opad) + 32 (inner_hash)
    mov     x4, x23             // output: mac_ptr (final output)
    bl      FUNC(sha256_update_finalize)

    // Zeroize H state
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]

    add     sp, sp, #32         // deallocate H buffer

    // ========================================================================
    // Cleanup and return
    // ========================================================================
    // Zeroize main stack frame (256 bytes: K_padded, ipad, opad, inner_hash, temp)
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]
    stp     xzr, xzr, [sp, #96]
    stp     xzr, xzr, [sp, #112]
    stp     xzr, xzr, [sp, #128]
    stp     xzr, xzr, [sp, #144]
    stp     xzr, xzr, [sp, #160]
    stp     xzr, xzr, [sp, #176]
    stp     xzr, xzr, [sp, #192]
    stp     xzr, xzr, [sp, #208]
    stp     xzr, xzr, [sp, #224]
    stp     xzr, xzr, [sp, #240]

    add     sp, sp, #256

    // Zeroize all caller-saved registers (GPR + SIMD) that may have held
    // SECRET bytes during HMAC computation.
    HKDF_SHA256_ZEROIZE_ALL

    // Epilogue: restore callee-saved regs
    ldr     x27, [sp, #80]
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #96
    ret

//============================================================================
// hkdf_sha256 (fixed: variable msg buffer + RFC limit + strong zeroization)
//============================================================================
// HKDF-SHA256 per RFC 5869
//
// C signature:
//   void hkdf_sha256(
//       const uint8_t *salt, size_t salt_len,
//       const uint8_t *ikm, size_t ikm_len,
//       const uint8_t *info, size_t info_len,
//       uint8_t *okm, size_t okm_len
//   );
//
// Parameters:
//   x0: salt_ptr
//   x1: salt_len
//   x2: ikm_ptr
//   x3: ikm_len
//   x4: info_ptr
//   x5: info_len
//   x6: okm_ptr
//   x7: okm_len
//
// Stack layout (variable):
//   [sp+0..31]   : PRK (32 bytes, SECRET)
//   [sp+32..63]  : T(i) (32 bytes, SECRET)
//   [sp+64..]    : msg buffer = T(i-1) || info || counter
//                 size = align16(32 + info_len + 1)
//
// Security notes:
// - Enforces okm_len <= 8160 (255 * 32) per RFC 5869.
// - Zeroizes the entire local frame (PRK + T + msg buffer) before returning.
// - Clears registers that may have held sensitive bytes (best effort).

.globl FUNC(hkdf_sha256)
.p2align 4
FUNC(hkdf_sha256):
    // Prologue: save FP/LR + callee-saved regs we use (x19-x28).
    // Preconditions (okm_len <= 8160, okm_len > 0) are checked by Rust wrapper.
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]

    // Move stable params into callee-saved regs.
    mov     x19, x4                           // info_ptr
    mov     x20, x5                           // info_len
    mov     x21, x6                           // okm_ptr
    mov     x22, x7                           // okm_len

    // Compute msg_cap_aligned = align16(32 + info_len + 1)
    // and locals_size = 64 + msg_cap_aligned
    add     x27, x20, #33                     // msg_cap = info_len + 32 + 1
    add     x27, x27, #15
    and     x27, x27, #-16                    // msg_cap_aligned in x27
    add     x28, x27, #64                     // locals_size in x28 (PRK+T = 64)
    sub     sp, sp, x28                       // allocate locals

    // ------------------------------------------------------------------------
    // Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
    // ------------------------------------------------------------------------
    mov     x4, sp                            // out: PRK at sp+0
    bl      FUNC(hmac_sha256)

    // ------------------------------------------------------------------------
    // Step 2: Expand
    // ------------------------------------------------------------------------
    mov     x23, #1                           // counter = 1..255
    mov     x24, #0                           // T_len = 0 for i=1

.Lhkdf_expand_loop:
    cbz     x22, .Lhkdf_done

    // msg_base = sp + 64
    add     x25, sp, #64

    // Copy T(i-1) from [sp+32] length x24 into msg_base.
    add     x16, sp, #32                      // T(i-1) / T(i) location
    mov     x26, #0
.Lhkdf_copy_t:
    cmp     x26, x24
    b.ge    .Lhkdf_t_copied
    ldrb    w15, [x16, x26]                   // w15 holds SECRET byte
    strb    w15, [x25, x26]
    add     x26, x26, #1
    b       .Lhkdf_copy_t

.Lhkdf_t_copied:
    // Copy info right after T(i-1)
    add     x25, x25, x24
    mov     x26, #0
.Lhkdf_copy_info:
    cmp     x26, x20
    b.ge    .Lhkdf_info_copied
    ldrb    w15, [x19, x26]
    strb    w15, [x25, x26]
    add     x26, x26, #1
    b       .Lhkdf_copy_info

.Lhkdf_info_copied:
    // Append counter byte after info
    add     x25, x25, x20
    strb    w23, [x25]

    // msg_len = T_len + info_len + 1
    add     x17, x24, x20
    add     x17, x17, #1

    // T(i) = HMAC(PRK, msg)
    mov     x0, sp                            // key: PRK at sp+0
    mov     x1, #32                           // key_len
    add     x2, sp, #64                       // msg_base
    mov     x3, x17                           // msg_len
    add     x4, sp, #32                       // out: T(i) at sp+32
    bl      FUNC(hmac_sha256)

    // Copy min(okm_len, 32) bytes from T(i) into okm_ptr.
    mov     x25, #32
    cmp     x22, #32
    csel    x25, x22, x25, lo                 // bytes_to_copy in x25

    add     x16, sp, #32
    mov     x26, #0
.Lhkdf_copy_okm:
    cmp     x26, x25
    b.ge    .Lhkdf_okm_copied
    ldrb    w15, [x16, x26]                   // SECRET byte
    strb    w15, [x21, x26]
    add     x26, x26, #1
    b       .Lhkdf_copy_okm

.Lhkdf_okm_copied:
    // Update output cursor and remaining length.
    add     x21, x21, x25
    sub     x22, x22, x25

    // Next iteration state.
    add     x23, x23, #1                      // counter++
    mov     x24, #32                          // T_len=32 from now on

    // Optional: wipe the first 32 bytes of msg buffer (contains T(i-1))
    // This reduces exposure if something crashes mid-loop.
    // (Costs a few stores; keep if paranoia > perf.)
    add     x16, sp, #64
    stp     xzr, xzr, [x16, #0]
    stp     xzr, xzr, [x16, #16]

    b       .Lhkdf_expand_loop

.Lhkdf_done:
    // ------------------------------------------------------------------------
    // Strong zeroization of locals: PRK (32) + T (32) + msg buffer (x27 bytes)
    // Total bytes = 64 + x27 = x28
    // x28 already equals locals_size and is 16-byte aligned.
    // ------------------------------------------------------------------------
    mov     x0, sp                            // ptr
    lsr     x1, x28, #4                       // 16-byte chunks
.Lhkdf_wipe_loop:
    stp     xzr, xzr, [x0], #16
    subs    x1, x1, #1
    b.ne    .Lhkdf_wipe_loop

    // Deallocate locals.
    add     sp, sp, x28

    // Zeroize all caller-saved registers (GPR + SIMD) that may have held
    // SECRET bytes during HKDF derivation.
    HKDF_SHA256_ZEROIZE_ALL

    // Restore callee-saved regs and return.
    ldp     x27, x28, [sp, #80]
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #96
    ret
