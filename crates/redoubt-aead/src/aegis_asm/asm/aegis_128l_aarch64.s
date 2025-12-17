// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L AEAD Cipher - ARM64/AArch64 Implementation
//
// This implementation uses ARM NEON Crypto Extensions for AES operations.
// The AEGIS-128L state consists of 8 blocks of 128 bits each (1024 bits total).
//
// This version uses inline macros to eliminate stack spilling of sensitive data.
// All state, key, and nonce remain in SIMD registers during initialization.
//
// Partial block handling uses a 32-byte stack buffer that is:
//   1. Pre-zeroized before any sensitive data is written
//   2. Immediately zeroized after use (before any other code runs)
//
// Platform Support: Linux, macOS, Windows (ARM64)
//
// References:
// - AEGIS: A Fast Authenticated Encryption Algorithm (v1.1)
// - ARM Architecture Reference Manual (NEON Crypto Extensions)
// - RFC: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-17

// ============================================================================
// Platform-specific symbol naming and directives
// ============================================================================

#if defined(__APPLE__)
    // macOS uses Mach-O format with underscore prefix
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
#elif defined(_WIN32) || defined(_WIN64)
    // Windows ARM64 uses PE format
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) // No hidden directive needed on Windows
#else
    // Linux/BSD use ELF format
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// Catastrophic Register Zeroization Macro
// ============================================================================
//
// Strategy: Implementation uses ONLY caller-saved registers (x0-x17, v0-v7, v16-v31)
//           This allows zeroization of ALL used registers without restoration.
//
// Zeroizes ONLY caller-saved registers:
//   - v0-v7    : Caller-saved SIMD (AEGIS state)
//   - v16-v31  : Caller-saved SIMD (key, nonce, temporaries)
//   - x0-x17   : Caller-saved GPR (pointers, lengths, temporaries)
//                NOTE: x18 is platform register - DO NOT USE OR ZEROIZE
//
// Never zeroized (ABI requirement):
//   - x18      : Platform register (reserved by OS - DO NOT TOUCH)
//   - x19-x28  : Callee-saved GPR
//   - x29 (FP) : Frame pointer
//   - x30 (LR) : Link register
//   - sp       : Stack pointer
//   - v8-v15   : Callee-saved SIMD
//
.macro AEGIS_ZEROIZE_ALL
    // === SIMD: Zeroize caller-saved v0-v7, v16-v31 ===
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    movi v6.16b, #0
    movi v7.16b, #0
    // v8-v15 are callee-saved - DO NOT ZEROIZE
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
    // x19-x28 are callee-saved - DO NOT ZEROIZE
.endm

// ============================================================================
// AEGIS-128L Update Macro (Inline - no stack spilling)
// ============================================================================
//
// Performs one AEGIS-128L state update round completely in registers.
//
// Inputs (registers):
//   v0-v7   = Current state S0-S7
//   \m0_reg = First message block (M0)
//   \m1_reg = Second message block (M1)
//
// Outputs:
//   v0-v7   = Updated state S'0-S'7 (modified in-place)
//
// Temporaries used: v20-v27, v31
//
// Update algorithm (RFC Section 2.3):
//   S'0 = AESRound(S7, S0 ^ M0)
//   S'1 = AESRound(S0, S1)
//   S'2 = AESRound(S1, S2)
//   S'3 = AESRound(S2, S3)
//   S'4 = AESRound(S3, S4 ^ M1)
//   S'5 = AESRound(S4, S5)
//   S'6 = AESRound(S5, S6)
//   S'7 = AESRound(S6, S7)
//
// AES Round Order:
//   AEGIS spec requires: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
//   ARM aese does:       AddRoundKey -> SubBytes -> ShiftRows
//   Solution: Use aese with zero (no-op XOR), then manual eor for AddRoundKey
//
.macro AEGIS_UPDATE m0_reg, m1_reg
    // Create zero vector for aese instruction
    movi v31.16b, #0

    // Compute new state in v20-v27 (preserves v0-v7 for all computations)

    // S'0 = AESRound(S7, S0 ^ M0)
    mov v20.16b, v7.16b              // v20 = S7
    aese v20.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v20.16b, v20.16b           // MixColumns
    eor v28.16b, v0.16b, \m0_reg\().16b  // v28 = S0 ^ M0
    eor v20.16b, v20.16b, v28.16b    // AddRoundKey

    // S'1 = AESRound(S0, S1)
    mov v21.16b, v0.16b
    aese v21.16b, v31.16b
    aesmc v21.16b, v21.16b
    eor v21.16b, v21.16b, v1.16b

    // S'2 = AESRound(S1, S2)
    mov v22.16b, v1.16b
    aese v22.16b, v31.16b
    aesmc v22.16b, v22.16b
    eor v22.16b, v22.16b, v2.16b

    // S'3 = AESRound(S2, S3)
    mov v23.16b, v2.16b
    aese v23.16b, v31.16b
    aesmc v23.16b, v23.16b
    eor v23.16b, v23.16b, v3.16b

    // S'4 = AESRound(S3, S4 ^ M1)
    mov v24.16b, v3.16b
    aese v24.16b, v31.16b
    aesmc v24.16b, v24.16b
    eor v29.16b, v4.16b, \m1_reg\().16b  // v29 = S4 ^ M1
    eor v24.16b, v24.16b, v29.16b

    // S'5 = AESRound(S4, S5)
    mov v25.16b, v4.16b
    aese v25.16b, v31.16b
    aesmc v25.16b, v25.16b
    eor v25.16b, v25.16b, v5.16b

    // S'6 = AESRound(S5, S6)
    mov v26.16b, v5.16b
    aese v26.16b, v31.16b
    aesmc v26.16b, v26.16b
    eor v26.16b, v26.16b, v6.16b

    // S'7 = AESRound(S6, S7)
    mov v27.16b, v6.16b
    aese v27.16b, v31.16b
    aesmc v27.16b, v27.16b
    eor v27.16b, v27.16b, v7.16b

    // Move new state to v0-v7
    mov v0.16b, v20.16b
    mov v1.16b, v21.16b
    mov v2.16b, v22.16b
    mov v3.16b, v23.16b
    mov v4.16b, v24.16b
    mov v5.16b, v25.16b
    mov v6.16b, v26.16b
    mov v7.16b, v27.16b
.endm

// ============================================================================
// Constants
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
// AEGIS-128L State Initialization Function
// ============================================================================
//
// Initializes the AEGIS-128L state with key and nonce.
//
// Initial state (RFC Section 2.2):
//   S0 = key ^ nonce
//   S1 = C1
//   S2 = C0
//   S3 = C1
//   S4 = key ^ nonce
//   S5 = key ^ C0
//   S6 = key ^ C1
//   S7 = key ^ C0
//
// Then performs 10 update rounds with (nonce, key) to mix the state.
//
// Parameters:
//   x0 = pointer to state output (128 bytes, must be 16-byte aligned)
//   x1 = pointer to key (16 bytes)
//   x2 = pointer to nonce (16 bytes)
//
// Register allocation:
//   v0-v7   = S0-S7 (state blocks)
//   v16     = key (caller-saved)
//   v17     = nonce (caller-saved)
//   v18     = C0 constant (caller-saved)
//   v19     = C1 constant (caller-saved)
//   v20-v29 = temporaries for update macro
//   v31     = zero vector
//   x3      = state pointer (preserved)
//
// Returns: void (state is written to memory)
//
.global FUNC(aegis128l_init)
HIDDEN_FUNC(aegis128l_init)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_init), @function
#endif
.p2align 4
FUNC(aegis128l_init):
    // Save state pointer (x0 will be reused)
    mov x3, x0

    // Load key and nonce into caller-saved SIMD registers
    ld1 {v16.16b}, [x1]              // v16 = key
    ld1 {v17.16b}, [x2]              // v17 = nonce

    // Load constants C0 and C1 (reuse x0 as temp)
#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1@PAGE
    add x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]              // v19 = C1
#else
    adrp x0, AEGIS_C0
    add x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1
    add x0, x0, :lo12:AEGIS_C1
    ld1 {v19.16b}, [x0]              // v19 = C1
#endif

    // Initialize state in registers
    eor v0.16b, v16.16b, v17.16b     // S0 = key ^ nonce
    mov v1.16b, v19.16b              // S1 = C1
    mov v2.16b, v18.16b              // S2 = C0
    mov v3.16b, v19.16b              // S3 = C1
    eor v4.16b, v16.16b, v17.16b     // S4 = key ^ nonce
    eor v5.16b, v16.16b, v18.16b     // S5 = key ^ C0
    eor v6.16b, v16.16b, v19.16b     // S6 = key ^ C1
    eor v7.16b, v16.16b, v18.16b     // S7 = key ^ C0

    // Perform 10 update rounds with (nonce, key)
    AEGIS_UPDATE v17, v16            // Round 1
    AEGIS_UPDATE v17, v16            // Round 2
    AEGIS_UPDATE v17, v16            // Round 3
    AEGIS_UPDATE v17, v16            // Round 4
    AEGIS_UPDATE v17, v16            // Round 5
    AEGIS_UPDATE v17, v16            // Round 6
    AEGIS_UPDATE v17, v16            // Round 7
    AEGIS_UPDATE v17, v16            // Round 8
    AEGIS_UPDATE v17, v16            // Round 9
    AEGIS_UPDATE v17, v16            // Round 10

    // Write final state to memory
    st1 {v0.16b-v3.16b}, [x3], #64
    st1 {v4.16b-v7.16b}, [x3]

    // Zeroize all caller-saved registers
    AEGIS_ZEROIZE_ALL

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_init), .-FUNC(aegis128l_init)
#endif

// ============================================================================
// AEGIS-128L Update Function (pointer-based interface for external use)
// ============================================================================
//
// Performs one AEGIS-128L state update round with message absorption.
//
// Parameters:
//   x0 = pointer to state (128 bytes, modified in-place)
//   x1 = pointer to first message block M0 (16 bytes)
//   x2 = pointer to second message block M1 (16 bytes)
//
// Returns: void (state is modified in-place)
//
.global FUNC(aegis128l_update)
HIDDEN_FUNC(aegis128l_update)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_update), @function
#endif
.p2align 4
FUNC(aegis128l_update):
    // Save state pointer
    mov x3, x0

    // Load state from memory
    ld1 {v0.16b-v3.16b}, [x0], #64
    ld1 {v4.16b-v7.16b}, [x0]

    // Load M0, M1 into temporary registers
    ld1 {v16.16b}, [x1]              // v16 = M0
    ld1 {v17.16b}, [x2]              // v17 = M1

    // Perform update using inline macro
    AEGIS_UPDATE v16, v17

    // Store updated state back to memory
    st1 {v0.16b-v3.16b}, [x3], #64
    st1 {v4.16b-v7.16b}, [x3]

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_update), .-FUNC(aegis128l_update)
#endif

// ============================================================================
// AEGIS-128L Encryption Function (Full support including partial blocks)
// ============================================================================
//
// Performs complete AEGIS-128L encryption with authentication.
//
// Uses ONLY caller-saved registers - no stack frame needed for register saves.
// Partial blocks require a temporary 32-byte stack buffer (pre/post zeroized).
//
// Parameters:
//   x0 = pointer to key (16 bytes)
//   x1 = pointer to nonce (16 bytes)
//   x2 = pointer to AAD (additional authenticated data)
//   x3 = AAD length in bytes
//   x4 = pointer to plaintext
//   x5 = plaintext length in bytes
//   x6 = pointer to ciphertext output buffer
//   x7 = pointer to tag output (16 bytes)
//
// Register allocation (ALL caller-saved):
//   v0-v7   = AEGIS state S0-S7
//   v16     = key (zeroized before return)
//   v17     = nonce (zeroized before return)
//   v18     = C0 constant
//   v19     = C1 constant
//   v20-v31 = temporaries for update, keystream, data
//   x8      = AAD pointer
//   x9      = AAD length (preserved for finalization)
//   x10     = plaintext pointer
//   x11     = plaintext length (preserved for finalization)
//   x12     = ciphertext pointer
//   x13     = tag pointer
//   x0-x7   = temporaries (loop counters, pointers)
//
// Returns: void (ciphertext and tag are written to output buffers)
//
.global FUNC(aegis128l_encrypt)
HIDDEN_FUNC(aegis128l_encrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(aegis128l_encrypt):
    // No prologue needed - using only caller-saved registers

    // Save parameters to caller-saved registers
    // x0=key, x1=nonce used immediately then become temps
    // x8-x13 hold values needed throughout
    mov x8, x2                       // x8 = AAD pointer
    mov x9, x3                       // x9 = AAD length (keep for finalization)
    mov x10, x4                      // x10 = plaintext pointer
    mov x11, x5                      // x11 = plaintext length (keep for finalization)
    mov x12, x6                      // x12 = ciphertext pointer
    mov x13, x7                      // x13 = tag pointer

    // === Phase 1: Initialization ===
    // Load key and nonce
    ld1 {v16.16b}, [x0]              // v16 = key
    ld1 {v17.16b}, [x1]              // v17 = nonce

    // Load constants (reuse x0 as temp - no longer needed)
#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1@PAGE
    add x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]              // v19 = C1
#else
    adrp x0, AEGIS_C0
    add x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1
    add x0, x0, :lo12:AEGIS_C1
    ld1 {v19.16b}, [x0]              // v19 = C1
#endif

    // Initialize state
    eor v0.16b, v16.16b, v17.16b     // S0 = key ^ nonce
    mov v1.16b, v19.16b              // S1 = C1
    mov v2.16b, v18.16b              // S2 = C0
    mov v3.16b, v19.16b              // S3 = C1
    eor v4.16b, v16.16b, v17.16b     // S4 = key ^ nonce
    eor v5.16b, v16.16b, v18.16b     // S5 = key ^ C0
    eor v6.16b, v16.16b, v19.16b     // S6 = key ^ C1
    eor v7.16b, v16.16b, v18.16b     // S7 = key ^ C0

    // 10 initialization rounds
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16

    // === Phase 2: Process AAD ===
    // Use x0, x1 as loop variables (AAD pointer copy, remaining bytes)
    mov x0, x8                       // x0 = AAD pointer
    mov x1, x9                       // x1 = AAD remaining

.Laad_full_blocks:
    cmp x1, #32
    b.lt .Laad_partial

    // Load full 32-byte AAD block into v16, v17 (reuse - key/nonce no longer needed)
    ld1 {v16.16b}, [x0], #16         // M0
    ld1 {v17.16b}, [x0], #16         // M1
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Laad_full_blocks

.Laad_partial:
    cbz x1, .Laad_done

    // Partial AAD: allocate and pre-zeroize 32-byte stack buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial AAD bytes (x2, x3 as temps)
    mov x2, sp
    mov x3, x1
.Laad_copy_loop:
    cbz x3, .Laad_copy_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Laad_copy_loop
.Laad_copy_done:

    // Load padded AAD
    ld1 {v16.16b, v17.16b}, [sp]

    // Zeroize and deallocate buffer
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32

    AEGIS_UPDATE v16, v17

.Laad_done:

    // === Phase 3: Encrypt plaintext ===
    // x0, x1 as loop variables (plaintext pointer copy, remaining bytes)
    mov x0, x10                      // x0 = plaintext pointer
    mov x1, x11                      // x1 = plaintext remaining

.Lenc_full_blocks:
    cmp x1, #32
    b.lt .Lenc_partial

    // Generate keystream (RFC Section 2.4)
    // z0 = S1 ^ S6 ^ (S2 & S3)
    and v16.16b, v2.16b, v3.16b
    eor v16.16b, v16.16b, v1.16b
    eor v16.16b, v16.16b, v6.16b

    // z1 = S2 ^ S5 ^ (S6 & S7)
    and v17.16b, v6.16b, v7.16b
    eor v17.16b, v17.16b, v2.16b
    eor v17.16b, v17.16b, v5.16b

    // Load plaintext
    ld1 {v18.16b}, [x0], #16         // plaintext block 0
    ld1 {v19.16b}, [x0], #16         // plaintext block 1

    // XOR to produce ciphertext
    eor v30.16b, v18.16b, v16.16b    // ciphertext0
    eor v31.16b, v19.16b, v17.16b    // ciphertext1

    // Store ciphertext
    st1 {v30.16b}, [x12], #16
    st1 {v31.16b}, [x12], #16

    // Update state with plaintext (not ciphertext!)
    AEGIS_UPDATE v18, v19

    sub x1, x1, #32
    b .Lenc_full_blocks

.Lenc_partial:
    cbz x1, .Lfinalize

    // Generate keystream BEFORE stack allocation
    // z0 = S1 ^ S6 ^ (S2 & S3)
    and v16.16b, v2.16b, v3.16b
    eor v16.16b, v16.16b, v1.16b
    eor v16.16b, v16.16b, v6.16b

    // z1 = S2 ^ S5 ^ (S6 & S7)
    and v17.16b, v6.16b, v7.16b
    eor v17.16b, v17.16b, v2.16b
    eor v17.16b, v17.16b, v5.16b

    // Partial plaintext: allocate and pre-zeroize buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial plaintext (x2, x3, x4 as temps)
    mov x2, sp
    mov x3, x1
.Lenc_copy_pt_loop:
    cbz x3, .Lenc_copy_pt_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Lenc_copy_pt_loop
.Lenc_copy_pt_done:

    // Load padded plaintext
    ld1 {v18.16b, v19.16b}, [sp]

    // XOR with keystream
    eor v30.16b, v18.16b, v16.16b
    eor v31.16b, v19.16b, v17.16b

    // Store ciphertext to buffer
    st1 {v30.16b, v31.16b}, [sp]

    // Copy only valid ciphertext bytes (x2, x3, x4 as temps)
    mov x2, sp
    mov x3, x1
.Lenc_copy_ct_loop:
    cbz x3, .Lenc_copy_ct_done
    ldrb w4, [x2], #1
    strb w4, [x12], #1
    sub x3, x3, #1
    b .Lenc_copy_ct_loop
.Lenc_copy_ct_done:

    // Zeroize and deallocate buffer
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32

    // Update state with padded plaintext (v18, v19 still valid)
    AEGIS_UPDATE v18, v19

.Lfinalize:
    // === Phase 4: Finalization and Tag Generation ===
    // RFC Section 2.5:
    //   tmp = S2 ^ (le64(ad_len_bits) || le64(msg_len_bits))
    //   Update(tmp, tmp) × 7
    //   tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

    // Convert lengths to bits (x9 = AAD len, x11 = msg len)
    lsl x0, x9, #3                   // x0 = aad_bits
    lsl x1, x11, #3                  // x1 = msg_bits

    // Build 128-bit block in v16
    fmov d16, x0                     // lower 64 bits = aad_bits
    mov v16.d[1], x1                 // upper 64 bits = msg_bits

    // tmp = S2 ^ (lengths block)
    eor v16.16b, v16.16b, v2.16b

    // 7 finalization rounds
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16

    // Generate tag: S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    // Write tag
    st1 {v16.16b}, [x13]

    // Zeroize all caller-saved registers
    AEGIS_ZEROIZE_ALL

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_encrypt), .-FUNC(aegis128l_encrypt)
#endif

// ============================================================================
// AEGIS-128L Decryption Function (Full support including partial blocks)
// ============================================================================
//
// Performs complete AEGIS-128L decryption with authentication verification.
//
// IMPORTANT: This function does NOT perform constant-time tag comparison.
// The caller MUST compare tags in constant time and handle authentication
// failure appropriately (e.g., zeroize plaintext output on failure).
//
// Parameters:
//   x0 = pointer to key (16 bytes)
//   x1 = pointer to nonce (16 bytes)
//   x2 = pointer to AAD
//   x3 = AAD length in bytes
//   x4 = pointer to ciphertext
//   x5 = ciphertext length in bytes
//   x6 = pointer to plaintext output buffer
//   x7 = pointer to computed tag output (16 bytes)
//
// Returns: void (plaintext and computed tag are written to output buffers)
//
.global FUNC(aegis128l_decrypt)
HIDDEN_FUNC(aegis128l_decrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_decrypt), @function
#endif
.p2align 4
FUNC(aegis128l_decrypt):
    // No prologue needed - using only caller-saved registers

    // Save parameters
    mov x8, x2                       // x8 = AAD pointer
    mov x9, x3                       // x9 = AAD length
    mov x10, x4                      // x10 = ciphertext pointer
    mov x11, x5                      // x11 = ciphertext length
    mov x12, x6                      // x12 = plaintext pointer
    mov x13, x7                      // x13 = tag pointer

    // === Phase 1: Initialization ===
    ld1 {v16.16b}, [x0]              // v16 = key
    ld1 {v17.16b}, [x1]              // v17 = nonce

#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]
    adrp x0, AEGIS_C1@PAGE
    add x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]
#else
    adrp x0, AEGIS_C0
    add x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]
    adrp x0, AEGIS_C1
    add x0, x0, :lo12:AEGIS_C1
    ld1 {v19.16b}, [x0]
#endif

    // Initialize state
    eor v0.16b, v16.16b, v17.16b
    mov v1.16b, v19.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    eor v4.16b, v16.16b, v17.16b
    eor v5.16b, v16.16b, v18.16b
    eor v6.16b, v16.16b, v19.16b
    eor v7.16b, v16.16b, v18.16b

    // 10 init rounds
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16
    AEGIS_UPDATE v17, v16

    // === Phase 2: Process AAD ===
    mov x0, x8
    mov x1, x9

.Ldec_aad_full_blocks:
    cmp x1, #32
    b.lt .Ldec_aad_partial

    ld1 {v16.16b}, [x0], #16
    ld1 {v17.16b}, [x0], #16
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b .Ldec_aad_full_blocks

.Ldec_aad_partial:
    cbz x1, .Ldec_aad_done

    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    mov x2, sp
    mov x3, x1
.Ldec_aad_copy_loop:
    cbz x3, .Ldec_aad_copy_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Ldec_aad_copy_loop
.Ldec_aad_copy_done:

    ld1 {v16.16b, v17.16b}, [sp]

    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32

    AEGIS_UPDATE v16, v17

.Ldec_aad_done:

    // === Phase 3: Decrypt ciphertext ===
    mov x0, x10                      // ciphertext pointer
    mov x1, x11                      // ciphertext remaining

.Ldec_full_blocks:
    cmp x1, #32
    b.lt .Ldec_partial

    // Generate keystream
    // z0 = S1 ^ S6 ^ (S2 & S3)
    and v16.16b, v2.16b, v3.16b
    eor v16.16b, v16.16b, v1.16b
    eor v16.16b, v16.16b, v6.16b

    // z1 = S2 ^ S5 ^ (S6 & S7)
    and v17.16b, v6.16b, v7.16b
    eor v17.16b, v17.16b, v2.16b
    eor v17.16b, v17.16b, v5.16b

    // Load ciphertext
    ld1 {v30.16b}, [x0], #16
    ld1 {v31.16b}, [x0], #16

    // XOR to get plaintext
    eor v18.16b, v30.16b, v16.16b    // plaintext0
    eor v19.16b, v31.16b, v17.16b    // plaintext1

    // Store plaintext
    st1 {v18.16b}, [x12], #16
    st1 {v19.16b}, [x12], #16

    // Update state with PLAINTEXT
    AEGIS_UPDATE v18, v19

    sub x1, x1, #32
    b .Ldec_full_blocks

.Ldec_partial:
    cbz x1, .Ldec_finalize

    // Generate keystream
    and v16.16b, v2.16b, v3.16b
    eor v16.16b, v16.16b, v1.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b

    and v17.16b, v3.16b, v4.16b
    eor v17.16b, v17.16b, v2.16b
    eor v17.16b, v17.16b, v5.16b
    eor v17.16b, v17.16b, v6.16b

    // Allocate buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial ciphertext
    mov x2, sp
    mov x3, x1
.Ldec_copy_ct_loop:
    cbz x3, .Ldec_copy_ct_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Ldec_copy_ct_loop
.Ldec_copy_ct_done:

    // Load padded ciphertext
    ld1 {v30.16b, v31.16b}, [sp]

    // XOR to get plaintext
    eor v18.16b, v30.16b, v16.16b
    eor v19.16b, v31.16b, v17.16b

    // Store plaintext to buffer, then zero padding
    st1 {v18.16b, v19.16b}, [sp]

    // Zero bytes beyond valid length
    add x2, sp, x1
    mov x3, #32
    sub x3, x3, x1
.Ldec_zero_padding_loop:
    cbz x3, .Ldec_zero_padding_done
    strb wzr, [x2], #1
    sub x3, x3, #1
    b .Ldec_zero_padding_loop
.Ldec_zero_padding_done:

    // Copy valid plaintext bytes to output
    mov x2, sp
    mov x3, x1
.Ldec_copy_pt_loop:
    cbz x3, .Ldec_copy_pt_done
    ldrb w4, [x2], #1
    strb w4, [x12], #1
    sub x3, x3, #1
    b .Ldec_copy_pt_loop
.Ldec_copy_pt_done:

    // Reload padded plaintext for state update
    ld1 {v18.16b, v19.16b}, [sp]

    // Zeroize buffer
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32

    // Update state
    AEGIS_UPDATE v18, v19

.Ldec_finalize:
    // === Phase 4: Finalization ===
    lsl x0, x9, #3                   // aad_bits
    lsl x1, x11, #3                  // msg_bits

    fmov d16, x0
    mov v16.d[1], x1
    eor v16.16b, v16.16b, v2.16b

    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16

    // Generate tag
    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    // Write tag
    st1 {v16.16b}, [x13]

    // Zeroize all caller-saved registers
    AEGIS_ZEROIZE_ALL

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_decrypt), .-FUNC(aegis128l_decrypt)
#endif
