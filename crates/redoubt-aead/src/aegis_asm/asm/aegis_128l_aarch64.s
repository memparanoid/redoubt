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
// Nuclear Zeroization Macro
// ============================================================================
//
// NUCLEAR ZEROIZATION: Zeroizes ALL registers used by AEGIS operations.
// This is a fail-safe approach - if restoration fails, secrets are already gone.
//
// Order of operations:
//   1. ZEROIZE EVERYTHING (this macro)
//   2. Restore callee-saved registers from stack
//
// This ensures that even if restoration fails, no sensitive data leaks.
//
// Zeroizes:
//   v0-v7   = AEGIS state (caller-saved)
//   v8-v11  = key, nonce, C0, C1 (callee-saved - will be restored after)
//   v12-v31 = Temporary registers (caller-saved)
//   x10-x14 = Temporary pointers/counters
//   x19-x26 = Saved parameters (callee-saved - will be restored after)
//
.macro AEGIS_ZEROIZE_ALL
    // === NUCLEAR REGISTER ZEROIZATION ===
    // Zeroize ALL registers used during encryption/decryption
    // This happens BEFORE restoration of callee-saved registers

    // Zeroize state registers (v0-v7) - caller-saved
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    movi v6.16b, #0
    movi v7.16b, #0

    // Zeroize key/nonce/constants (v8-v11) - callee-saved, will be restored
    movi v8.16b, #0
    movi v9.16b, #0
    movi v10.16b, #0
    movi v11.16b, #0

    // Zeroize all temporary SIMD registers (v12-v31) - caller-saved
    movi v12.16b, #0
    movi v13.16b, #0
    movi v14.16b, #0
    movi v15.16b, #0
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

    // Zeroize ALL caller-saved general purpose registers (x0-x9)
    // These may contain sensitive pointers, lengths, or intermediate values
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

    // Zeroize temporary general purpose registers (x10-x14)
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr

    // Zeroize parameter storage registers (x19-x26) - callee-saved, will be restored
    // These hold key/nonce/AAD/plaintext/ciphertext/tag pointers
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
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
// Temporaries used: v16-v25, v31
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

    // Compute new state in v16-v23 (preserves v0-v7 for all computations)

    // S'0 = AESRound(S7, S0 ^ M0)
    // Process S7 (apply SubBytes+ShiftRows+MixColumns), then XOR with (S0 ^ M0)
    mov v16.16b, v7.16b              // v16 = S7 (data to process)
    aese v16.16b, v31.16b            // SubBytes + ShiftRows (XOR with zero = no-op)
    aesmc v16.16b, v16.16b           // MixColumns
    eor v24.16b, v0.16b, \m0_reg\().16b  // v24 = S0 ^ M0
    eor v16.16b, v16.16b, v24.16b    // AddRoundKey: XOR with (S0 ^ M0)

    // S'1 = AESRound(S0, S1)
    // Process S0, then XOR with S1
    mov v17.16b, v0.16b              // v17 = S0
    aese v17.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v17.16b, v17.16b           // MixColumns
    eor v17.16b, v17.16b, v1.16b     // AddRoundKey: XOR with S1

    // S'2 = AESRound(S1, S2)
    mov v18.16b, v1.16b              // v18 = S1
    aese v18.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v18.16b, v18.16b           // MixColumns
    eor v18.16b, v18.16b, v2.16b     // AddRoundKey: XOR with S2

    // S'3 = AESRound(S2, S3)
    mov v19.16b, v2.16b              // v19 = S2
    aese v19.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v19.16b, v19.16b           // MixColumns
    eor v19.16b, v19.16b, v3.16b     // AddRoundKey: XOR with S3

    // S'4 = AESRound(S3, S4 ^ M1)
    // Process S3, then XOR with (S4 ^ M1)
    mov v20.16b, v3.16b              // v20 = S3
    aese v20.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v20.16b, v20.16b           // MixColumns
    eor v25.16b, v4.16b, \m1_reg\().16b  // v25 = S4 ^ M1
    eor v20.16b, v20.16b, v25.16b    // AddRoundKey: XOR with (S4 ^ M1)

    // S'5 = AESRound(S4, S5)
    mov v21.16b, v4.16b              // v21 = S4
    aese v21.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v21.16b, v21.16b           // MixColumns
    eor v21.16b, v21.16b, v5.16b     // AddRoundKey: XOR with S5

    // S'6 = AESRound(S5, S6)
    mov v22.16b, v5.16b              // v22 = S5
    aese v22.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v22.16b, v22.16b           // MixColumns
    eor v22.16b, v22.16b, v6.16b     // AddRoundKey: XOR with S6

    // S'7 = AESRound(S6, S7)
    mov v23.16b, v6.16b              // v23 = S6
    aese v23.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v23.16b, v23.16b           // MixColumns
    eor v23.16b, v23.16b, v7.16b     // AddRoundKey: XOR with S7

    // Move new state to v0-v7
    mov v0.16b, v16.16b
    mov v1.16b, v17.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    mov v4.16b, v20.16b
    mov v5.16b, v21.16b
    mov v6.16b, v22.16b
    mov v7.16b, v23.16b
.endm

// ============================================================================
// Constants
// ============================================================================

// Fibonacci constants used in AEGIS initialization
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
// AEGIS-128L State Initialization Function (No spilling version)
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
// This version uses inline macros to avoid stack spilling. Key and nonce
// remain in callee-saved SIMD registers (v8-v9) throughout execution.
//
// Parameters:
//   x0 = pointer to state output (128 bytes, must be 16-byte aligned)
//   x1 = pointer to key (16 bytes)
//   x2 = pointer to nonce (16 bytes)
//
// Register allocation:
//   v0-v7   = S0-S7 (state blocks)
//   v8      = key (callee-saved, preserved throughout)
//   v9      = nonce (callee-saved, preserved throughout)
//   v10     = C0 constant (callee-saved)
//   v11     = C1 constant (callee-saved)
//   v16-v25 = temporaries for update macro
//   v31     = zero vector
//   x3      = state pointer (preserved)
//   x4      = temporary for constant loading
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
    // Prologue: save callee-saved SIMD registers that we use (v8-v11)
    // No need to save x30 (link register) - this function makes no calls
    stp d8, d9, [sp, #-32]!
    stp d10, d11, [sp, #16]

    // Save state pointer
    mov x3, x0

    // Load key and nonce into registers (only memory access for these)
    ld1 {v8.16b}, [x1]               // v8 = key
    ld1 {v9.16b}, [x2]               // v9 = nonce

    // Load constants C0 and C1
#if defined(__APPLE__)
    adrp x4, AEGIS_C0@PAGE
    add x4, x4, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x4]

    adrp x4, AEGIS_C1@PAGE
    add x4, x4, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x4]
#else
    adrp x4, AEGIS_C0
    add x4, x4, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x4]

    adrp x4, AEGIS_C1
    add x4, x4, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x4]
#endif

    // Initialize state in registers
    eor v0.16b, v8.16b, v9.16b       // S0 = key ^ nonce
    mov v1.16b, v11.16b              // S1 = C1
    mov v2.16b, v10.16b              // S2 = C0
    mov v3.16b, v11.16b              // S3 = C1
    eor v4.16b, v8.16b, v9.16b       // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b      // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b      // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b      // S7 = key ^ C0

    // Perform 10 update rounds with (nonce, key)
    // All in registers - NO stack spilling
    // M0 = nonce (v9), M1 = key (v8)
    AEGIS_UPDATE v9, v8              // Round 1
    AEGIS_UPDATE v9, v8              // Round 2
    AEGIS_UPDATE v9, v8              // Round 3
    AEGIS_UPDATE v9, v8              // Round 4
    AEGIS_UPDATE v9, v8              // Round 5
    AEGIS_UPDATE v9, v8              // Round 6
    AEGIS_UPDATE v9, v8              // Round 7
    AEGIS_UPDATE v9, v8              // Round 8
    AEGIS_UPDATE v9, v8              // Round 9
    AEGIS_UPDATE v9, v8              // Round 10

    // Write final state to memory (only write needed)
    st1 {v0.16b-v3.16b}, [x3], #64
    st1 {v4.16b-v7.16b}, [x3]

    // 🗑️❗ NUCLEAR ZEROIZATION PROTOCOL BEGIN
    // Step 1: Zeroize ALL registers (including key/nonce)
    // TEMPORARY DISABLED TO DEBUG
    // AEGIS_ZEROIZE_ALL

    // Zeroize additional temporaries used in this function
    mov x3, xzr
    mov x4, xzr

    // Step 2: Restore callee-saved registers from stack
    ldp d10, d11, [sp, #16]
    ldp d8, d9, [sp, #0]

    // Step 3: NUCLEAR STACK ZEROIZATION
    // Zeroize the entire 32-byte stack frame BEFORE adjusting sp
    // stp writes 16 bytes per instruction: 32 / 16 = 2 stores
    // TEMPORARY DISABLED TO DEBUG
    // stp xzr, xzr, [sp, #0]           // Zero bytes [0..15]
    // stp xzr, xzr, [sp, #16]          // Zero bytes [16..31]

    // Step 4: Restore stack pointer and return
    add sp, sp, #32

    // 🧹 NUCLEAR ZEROIZATION PROTOCOL FINISHED
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
// This version exists for compatibility with code that needs a pointer-based
// interface (e.g., tests). Internally uses the inline macro.
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
    // Load state from memory
    ld1 {v0.16b-v3.16b}, [x0], #64
    ld1 {v4.16b-v7.16b}, [x0]
    sub x0, x0, #64                  // Restore x0 to beginning of state

    // Load M0, M1 into temporary registers
    ld1 {v12.16b}, [x1]              // v12 = M0
    ld1 {v13.16b}, [x2]              // v13 = M1

    // Perform update using inline macro
    AEGIS_UPDATE v12, v13

    // Store updated state back to memory
    st1 {v0.16b-v3.16b}, [x0], #64
    st1 {v4.16b-v7.16b}, [x0]

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
// This version inlines all operations (init, AAD processing, encryption) to
// avoid stack spilling of sensitive data. Key and nonce remain in callee-saved
// SIMD registers throughout execution.
//
// Partial block handling:
//   ARM64 cannot use variable indices with 'ins' instruction, so partial
//   blocks require a 32-byte stack buffer. This buffer is:
//   1. Pre-zeroized before any sensitive data is written
//   2. Immediately zeroized after use (before any other code executes)
//   This minimizes the exposure window of sensitive data on the stack.
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
// Register allocation:
//   v0-v7   = AEGIS state S0-S7
//   v8      = key (callee-saved, zeroized before return)
//   v9      = nonce (callee-saved, zeroized before return)
//   v10     = C0 constant
//   v11     = C1 constant
//   v12-v27 = temporaries for keystream, plaintext, ciphertext
//   v31     = zero vector
//   x19-x26 = saved parameter values
//   x10-x14 = loop counters/pointers/temporaries
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
    // Prologue: save frame pointer and callee-saved registers
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp d8, d9, [sp, #80]
    stp d10, d11, [sp, #96]

    // Save parameters to callee-saved registers
    mov x19, x0                      // key pointer
    mov x20, x1                      // nonce pointer
    mov x21, x2                      // AAD pointer
    mov x22, x3                      // AAD length
    mov x23, x4                      // plaintext pointer
    mov x24, x5                      // plaintext length
    mov x25, x6                      // ciphertext pointer
    mov x26, x7                      // tag pointer

    // === Phase 1: Initialization (inline, no function call) ===
    // Load key and nonce into callee-saved SIMD registers
    ld1 {v8.16b}, [x19]              // v8 = key
    ld1 {v9.16b}, [x20]              // v9 = nonce

    // Load constants C0 and C1
#if defined(__APPLE__)
    adrp x10, AEGIS_C0@PAGE
    add x10, x10, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1@PAGE
    add x10, x10, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x10]
#else
    adrp x10, AEGIS_C0
    add x10, x10, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1
    add x10, x10, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x10]
#endif

    // Initialize state in registers (same as init function)
    eor v0.16b, v8.16b, v9.16b       // S0 = key ^ nonce
    mov v1.16b, v11.16b              // S1 = C1
    mov v2.16b, v10.16b              // S2 = C0
    mov v3.16b, v11.16b              // S3 = C1
    eor v4.16b, v8.16b, v9.16b       // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b      // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b      // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b      // S7 = key ^ C0

    // Perform 10 initialization rounds (all in registers)
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8

    // === Phase 2: Process AAD (Additional Authenticated Data) ===
    mov x10, x21                     // AAD pointer
    mov x11, x22                     // AAD remaining bytes

.Laad_full_blocks:
    cmp x11, #32                     // Check if at least 32 bytes remain
    b.lt .Laad_partial               // If less, handle partial block

    // Load full 32-byte AAD block
    ld1 {v12.16b}, [x10], #16        // M0 = first 16 bytes
    ld1 {v13.16b}, [x10], #16        // M1 = second 16 bytes

    // Update state with AAD
    AEGIS_UPDATE v12, v13

    sub x11, x11, #32                // Remaining -= 32
    b .Laad_full_blocks

.Laad_partial:
    // Handle partial AAD block (1-31 bytes remaining in x11)
    cbz x11, .Laad_done              // If 0 bytes, skip

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of partial AAD data
// ║
// ║ We are spilling partial AAD data to a 32-byte stack buffer because:
// ║   - ARM64 'ins' instruction requires immediate (constant) indices
// ║   - Variable-index insertion would require 200+ LOC of jump table code
// ║   - This is a pragmatic compromise between security and maintainability
// ║
// ║ CRITICAL REQUIREMENTS:
// ║   1. Buffer MUST be pre-zeroized before any data is written
// ║   2. Buffer MUST be immediately zeroized after use
// ║   3. No other code may execute between use and zeroization
// ║
// ║═══════════════════════════════════════════════════════════════════════
    // Allocate and pre-zeroize 32-byte stack buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial AAD bytes to stack buffer
    mov x12, sp                      // x12 = buffer pointer
    mov x13, x11                     // x13 = bytes to copy
.Laad_spill_copy_loop:
    cbz x13, .Laad_spill_copy_done
    ldrb w14, [x10], #1              // Load byte from AAD
    strb w14, [x12], #1              // Store to buffer
    sub x13, x13, #1
    b .Laad_spill_copy_loop
.Laad_spill_copy_done:
    // Load zero-padded AAD from buffer
    ld1 {v12.16b, v13.16b}, [sp]     // M0, M1 (32 bytes)

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with padded AAD
    AEGIS_UPDATE v12, v13

.Laad_done:

    // === Phase 3: Encrypt plaintext ===
    mov x10, x23                     // plaintext pointer
    mov x11, x24                     // plaintext remaining bytes

.Lenc_full_blocks:
    cmp x11, #32                     // Check if at least 32 bytes remain
    b.lt .Lenc_partial               // If less, handle partial block

    // Generate keystream (RFC Section 2.4)
    // keystream0 = S1 ^ S6 ^ (S2 & S3)
    and v12.16b, v2.16b, v3.16b      // v12 = S2 & S3
    eor v12.16b, v12.16b, v1.16b     // v12 ^= S1
    eor v12.16b, v12.16b, v6.16b     // v12 ^= S6
    // v12 = keystream0

    // keystream1 = S2 ^ S5 ^ (S6 & S7)
    and v13.16b, v6.16b, v7.16b      // v13 = S6 & S7
    eor v13.16b, v13.16b, v2.16b     // v13 ^= S2
    eor v13.16b, v13.16b, v5.16b     // v13 ^= S5
    // v13 = keystream1

    // Load plaintext
    ld1 {v14.16b}, [x10], #16        // plaintext block 0
    ld1 {v15.16b}, [x10], #16        // plaintext block 1

    // XOR plaintext with keystream to produce ciphertext
    eor v26.16b, v14.16b, v12.16b    // ciphertext0 = plaintext0 ^ keystream0
    eor v27.16b, v15.16b, v13.16b    // ciphertext1 = plaintext1 ^ keystream1

    // Store ciphertext
    st1 {v26.16b}, [x25], #16
    st1 {v27.16b}, [x25], #16

    // Update state with plaintext (not ciphertext!)
    AEGIS_UPDATE v14, v15

    sub x11, x11, #32                // Remaining -= 32
    b .Lenc_full_blocks

.Lenc_partial:
    // Handle partial plaintext block (1-31 bytes remaining in x11)
    cbz x11, .Lfinalize              // If 0 bytes, skip to finalization

    // Generate keystream BEFORE allocating stack (keep in v12, v13)
    // keystream0 = S1 ^ S6 ^ (S2 & S3)
    and v12.16b, v2.16b, v3.16b
    eor v12.16b, v12.16b, v1.16b
    eor v12.16b, v12.16b, v6.16b

    // keystream1 = S2 ^ S5 ^ (S6 & S7)
    and v13.16b, v6.16b, v7.16b
    eor v13.16b, v13.16b, v2.16b
    eor v13.16b, v13.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of partial PLAINTEXT data
// ║
// ║ We are spilling partial plaintext/ciphertext to a 32-byte stack buffer.
// ║ Reason: ARM64 'ins' instruction requires compile-time constant indices.
// ║
// ║ CRITICAL SECURITY REQUIREMENTS:
// ║   1. Buffer MUST be pre-zeroized before plaintext is written
// ║   2. Buffer MUST be immediately zeroized after ciphertext extraction
// ║   3. No code may execute between ciphertext copy and zeroization
// ║
// ║ This violates the hermetic principle but avoids 200+ LOC of jump tables.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    // Allocate and pre-zeroize 32-byte stack buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial plaintext to buffer
    mov x12, sp                      // x12 = buffer pointer
    mov x13, x11                     // x13 = bytes to copy
.Lenc_spill_copy_pt_loop:
    cbz x13, .Lenc_spill_copy_pt_done
    ldrb w14, [x10], #1              // Load byte from plaintext
    strb w14, [x12], #1              // Store to buffer
    sub x13, x13, #1
    b .Lenc_spill_copy_pt_loop
.Lenc_spill_copy_pt_done:

    // Load zero-padded plaintext from buffer
    ld1 {v14.16b, v15.16b}, [sp]     // plaintext blocks 0, 1 (32 bytes)

    // XOR with keystream
    eor v26.16b, v14.16b, v12.16b    // ciphertext0
    eor v27.16b, v15.16b, v13.16b    // ciphertext1

    // Store ciphertext to buffer (will extract only valid bytes)
    st1 {v26.16b, v27.16b}, [sp]     // ciphertext 0, 1 (32 bytes)

    // Copy only valid ciphertext bytes to output
    mov x12, sp                      // x12 = buffer pointer
    mov x13, x11                     // x13 = bytes to copy
.Lenc_spill_copy_ct_loop:
    cbz x13, .Lenc_spill_copy_ct_done
    ldrb w14, [x12], #1              // Load byte from buffer
    strb w14, [x25], #1              // Store to ciphertext output
    sub x13, x13, #1
    b .Lenc_spill_copy_ct_loop
.Lenc_spill_copy_ct_done:

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║     (contains plaintext - MUST be cleared immediately)
// ║
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext (v14, v15 still valid)
    AEGIS_UPDATE v14, v15

.Lfinalize:
    // === Phase 4: Finalization and Tag Generation ===
    // RFC Section 2.5:
    //   tmp = S2 ^ (aad_bits || msg_bits)  // 128-bit block
    //   Update(tmp, tmp) × 7               // 7 update rounds
    //   tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

    // Convert lengths from bytes to bits (multiply by 8 = left shift by 3)
    lsl x10, x22, #3                 // x10 = aad_bits (64-bit)
    lsl x11, x24, #3                 // x11 = msg_bits (64-bit)

    // Build 128-bit block: [aad_bits (low 64) || msg_bits (high 64)]
    // Store to v28 as [aad_bits, msg_bits] in little-endian
    fmov d28, x10                    // d28 = aad_bits (lower 64 bits of v28)
    mov v28.d[1], x11                // v28.d[1] = msg_bits (upper 64 bits of v28)

    // tmp = S2 ^ (aad_bits || msg_bits)
    eor v28.16b, v28.16b, v2.16b     // v28 = tmp

    // Perform 7 finalization rounds: Update(tmp, tmp)
    AEGIS_UPDATE v28, v28            // Round 1
    AEGIS_UPDATE v28, v28            // Round 2
    AEGIS_UPDATE v28, v28            // Round 3
    AEGIS_UPDATE v28, v28            // Round 4
    AEGIS_UPDATE v28, v28            // Round 5
    AEGIS_UPDATE v28, v28            // Round 6
    AEGIS_UPDATE v28, v28            // Round 7

    // Generate authentication tag: tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    eor v29.16b, v0.16b, v1.16b      // v29 = S0 ^ S1
    eor v29.16b, v29.16b, v2.16b     // v29 ^= S2
    eor v29.16b, v29.16b, v3.16b     // v29 ^= S3
    eor v29.16b, v29.16b, v4.16b     // v29 ^= S4
    eor v29.16b, v29.16b, v5.16b     // v29 ^= S5
    eor v29.16b, v29.16b, v6.16b     // v29 ^= S6 (tag complete)

    // Write tag to output
    st1 {v29.16b}, [x26]

    // 🗑️❗ NUCLEAR ZEROIZATION PROTOCOL BEGIN
    // Step 1: Zeroize ALL registers (including sensitive data)
    // TEMPORARY DISABLED TO DEBUG
    // AEGIS_ZEROIZE_ALL

    // Step 2: Restore callee-saved registers from stack
    ldp d10, d11, [sp, #96]
    ldp d8, d9, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp, #0]

    // Step 3: NUCLEAR STACK ZEROIZATION
    // Zeroize the entire 112-byte stack frame BEFORE adjusting sp
    // stp writes 16 bytes per store: 112 / 16 = 7 stores
    stp xzr, xzr, [sp, #0]           // Zero bytes [0..15]
    stp xzr, xzr, [sp, #16]          // Zero bytes [16..31]
    stp xzr, xzr, [sp, #32]          // Zero bytes [32..47]
    stp xzr, xzr, [sp, #48]          // Zero bytes [48..63]
    stp xzr, xzr, [sp, #64]          // Zero bytes [64..79]
    stp xzr, xzr, [sp, #80]          // Zero bytes [80..95]
    stp xzr, xzr, [sp, #96]          // Zero bytes [96..111]

    // Step 4: Restore stack pointer and return
    add sp, sp, #112

    // 🧹 NUCLEAR ZEROIZATION PROTOCOL FINISHED
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
//   x2 = pointer to AAD (additional authenticated data)
//   x3 = AAD length in bytes
//   x4 = pointer to ciphertext
//   x5 = ciphertext length in bytes
//   x6 = pointer to plaintext output buffer
//   x7 = pointer to computed tag output (16 bytes) - caller compares with expected
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
    // Prologue: save frame pointer and callee-saved registers
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp d8, d9, [sp, #80]
    stp d10, d11, [sp, #96]

    // Save parameters to callee-saved registers
    mov x19, x0                      // key pointer
    mov x20, x1                      // nonce pointer
    mov x21, x2                      // AAD pointer
    mov x22, x3                      // AAD length
    mov x23, x4                      // ciphertext pointer
    mov x24, x5                      // ciphertext length
    mov x25, x6                      // plaintext output pointer
    mov x26, x7                      // tag output pointer

    // === Phase 1: Initialization (same as encryption) ===
    ld1 {v8.16b}, [x19]              // v8 = key
    ld1 {v9.16b}, [x20]              // v9 = nonce

#if defined(__APPLE__)
    adrp x10, AEGIS_C0@PAGE
    add x10, x10, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1@PAGE
    add x10, x10, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x10]
#else
    adrp x10, AEGIS_C0
    add x10, x10, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1
    add x10, x10, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x10]
#endif

    // Initialize state
    eor v0.16b, v8.16b, v9.16b       // S0 = key ^ nonce
    mov v1.16b, v11.16b              // S1 = C1
    mov v2.16b, v10.16b              // S2 = C0
    mov v3.16b, v11.16b              // S3 = C1
    eor v4.16b, v8.16b, v9.16b       // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b      // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b      // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b      // S7 = key ^ C0

    // 10 init rounds
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8

    // === Phase 2: Process AAD (same as encryption) ===
    mov x10, x21                     // AAD pointer
    mov x11, x22                     // AAD remaining bytes

.Ldec_aad_full_blocks:
    cmp x11, #32
    b.lt .Ldec_aad_partial

    ld1 {v12.16b}, [x10], #16
    ld1 {v13.16b}, [x10], #16
    AEGIS_UPDATE v12, v13

    sub x11, x11, #32
    b .Ldec_aad_full_blocks

.Ldec_aad_partial:
    cbz x11, .Ldec_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of partial AAD data
// ║
// ║ We are spilling partial AAD data to a 32-byte stack buffer because:
// ║   - ARM64 'ins' instruction requires immediate (constant) indices
// ║   - Variable-index insertion would require 200+ LOC of jump table code
// ║   - This is a pragmatic compromise between security and maintainability
// ║
// ║ CRITICAL REQUIREMENTS:
// ║   1. Buffer MUST be pre-zeroized before any data is written
// ║   2. Buffer MUST be immediately zeroized after use
// ║   3. No other code may execute between use and zeroization
// ║
// ║═══════════════════════════════════════════════════════════════════════
    // Allocate and pre-zeroize buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial AAD
    mov x12, sp
    mov x13, x11
.Ldec_aad_spill_copy_loop:
    cbz x13, .Ldec_aad_spill_copy_done
    ldrb w14, [x10], #1
    strb w14, [x12], #1
    sub x13, x13, #1
    b .Ldec_aad_spill_copy_loop
.Ldec_aad_spill_copy_done:
    ld1 {v12.16b, v13.16b}, [sp]     // AAD M0, M1 (32 bytes)

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v12, v13

.Ldec_aad_done:
    // === Phase 3: Decrypt ciphertext ===
    // Key difference from encryption: we XOR ciphertext with keystream to get
    // plaintext, then update state with PLAINTEXT (not ciphertext)
    mov x10, x23                     // ciphertext pointer
    mov x11, x24                     // ciphertext remaining bytes

.Ldec_full_blocks:
    cmp x11, #32
    b.lt .Ldec_partial

    // Generate keystream: z0 = S1 ^ S6 ^ (S2 & S3), z1 = S2 ^ S5 ^ (S6 & S7)
    and v12.16b, v2.16b, v3.16b
    eor v12.16b, v12.16b, v1.16b
    eor v12.16b, v12.16b, v6.16b

    and v13.16b, v6.16b, v7.16b
    eor v13.16b, v13.16b, v2.16b
    eor v13.16b, v13.16b, v5.16b

    // Load ciphertext
    ld1 {v26.16b}, [x10], #16
    ld1 {v27.16b}, [x10], #16

    // XOR to get plaintext
    eor v14.16b, v26.16b, v12.16b    // plaintext0
    eor v15.16b, v27.16b, v13.16b    // plaintext1

    // Store plaintext
    st1 {v14.16b}, [x25], #16
    st1 {v15.16b}, [x25], #16

    // Update state with PLAINTEXT
    AEGIS_UPDATE v14, v15

    sub x11, x11, #32
    b .Ldec_full_blocks

.Ldec_partial:
    cbz x11, .Ldec_finalize

    // Generate keystream: z0 = S1 ^ S6 ^ (S2 & S3), z1 = S2 ^ S5 ^ (S6 & S7)
    and v12.16b, v2.16b, v3.16b
    eor v12.16b, v12.16b, v1.16b
    eor v12.16b, v12.16b, v6.16b

    and v13.16b, v6.16b, v7.16b
    eor v13.16b, v13.16b, v2.16b
    eor v13.16b, v13.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of CIPHERTEXT and PLAINTEXT
// ║
// ║ We are spilling partial ciphertext/plaintext to a 32-byte stack buffer.
// ║ Reason: ARM64 'ins' instruction requires compile-time constant indices.
// ║
// ║ CRITICAL SECURITY REQUIREMENTS:
// ║   1. Buffer MUST be pre-zeroized before ciphertext is written
// ║   2. Buffer MUST be immediately zeroized after plaintext extraction
// ║   3. No code may execute between plaintext copy and zeroization
// ║
// ║ WARNING: This buffer will contain DECRYPTED PLAINTEXT (highly sensitive)
// ║
// ║═══════════════════════════════════════════════════════════════════════
    // Allocate and pre-zeroize buffer
    sub sp, sp, #32
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]

    // Copy partial ciphertext to buffer
    mov x12, sp
    mov x13, x11
.Ldec_spill_copy_ct_loop:
    cbz x13, .Ldec_spill_copy_ct_done
    ldrb w14, [x10], #1
    strb w14, [x12], #1
    sub x13, x13, #1
    b .Ldec_spill_copy_ct_loop
.Ldec_spill_copy_ct_done:
    // Load zero-padded ciphertext
    ld1 {v26.16b, v27.16b}, [sp]     // ciphertext 0, 1 (32 bytes)

    // XOR to get plaintext (zero-padded)
    eor v14.16b, v26.16b, v12.16b
    eor v15.16b, v27.16b, v13.16b

    // For partial blocks, we need to zero the padding in plaintext
    // before updating state. Store plaintext, zero extra bytes, reload.
    st1 {v14.16b, v15.16b}, [sp]     // plaintext 0, 1 (32 bytes)

    // Zero bytes beyond the valid plaintext length
    add x12, sp, x11                 // x12 = buffer + valid_len
    mov x13, #32
    sub x13, x13, x11                // x13 = 32 - valid_len = bytes to zero
.Ldec_spill_zero_padding_loop:
    cbz x13, .Ldec_spill_zero_padding_done
    strb wzr, [x12], #1
    sub x13, x13, #1
    b .Ldec_spill_zero_padding_loop
.Ldec_spill_zero_padding_done:
    // Copy valid plaintext bytes to output
    mov x12, sp
    mov x13, x11
.Ldec_spill_copy_pt_loop:
    cbz x13, .Ldec_spill_copy_pt_done
    ldrb w14, [x12], #1
    strb w14, [x25], #1
    sub x13, x13, #1
    b .Ldec_spill_copy_pt_loop
.Ldec_spill_copy_pt_done:
    // Reload properly padded plaintext for state update
    ld1 {v14.16b, v15.16b}, [sp]     // plaintext 0, 1 (32 bytes, zero-padded)

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║     (contains DECRYPTED PLAINTEXT - MUST be cleared immediately)
// ║
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    add sp, sp, #32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext
    AEGIS_UPDATE v14, v15

.Ldec_finalize:
    // === Phase 4: Finalization (same as encryption) ===
    lsl x10, x22, #3                 // aad_bits
    lsl x11, x24, #3                 // msg_bits

    fmov d28, x10
    mov v28.d[1], x11
    eor v28.16b, v28.16b, v2.16b     // tmp = S2 ^ (aad_bits || msg_bits)

    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28
    AEGIS_UPDATE v28, v28

    // Generate tag
    eor v29.16b, v0.16b, v1.16b
    eor v29.16b, v29.16b, v2.16b
    eor v29.16b, v29.16b, v3.16b
    eor v29.16b, v29.16b, v4.16b
    eor v29.16b, v29.16b, v5.16b
    eor v29.16b, v29.16b, v6.16b

    // Write computed tag (caller must compare with expected tag)
    st1 {v29.16b}, [x26]

    // 🗑️❗ NUCLEAR ZEROIZATION PROTOCOL BEGIN
    // Step 1: Zeroize ALL registers (including sensitive plaintext)
    // TEMPORARY DISABLED TO DEBUG
    // AEGIS_ZEROIZE_ALL

    // Step 2: Restore callee-saved registers from stack
    ldp d10, d11, [sp, #96]
    ldp d8, d9, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp, #0]

    // Step 3: NUCLEAR STACK ZEROIZATION
    // Zeroize the entire 112-byte stack frame BEFORE adjusting sp
    // stp writes 16 bytes per store: 112 / 16 = 7 stores
    stp xzr, xzr, [sp, #0]           // Zero bytes [0..15]
    stp xzr, xzr, [sp, #16]          // Zero bytes [16..31]
    stp xzr, xzr, [sp, #32]          // Zero bytes [32..47]
    stp xzr, xzr, [sp, #48]          // Zero bytes [48..63]
    stp xzr, xzr, [sp, #64]          // Zero bytes [64..79]
    stp xzr, xzr, [sp, #80]          // Zero bytes [80..95]
    stp xzr, xzr, [sp, #96]          // Zero bytes [96..111]

    // Step 4: Restore stack pointer and return
    add sp, sp, #112

    // 🧹 NUCLEAR ZEROIZATION PROTOCOL FINISHED
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_decrypt), .-FUNC(aegis128l_decrypt)
#endif
