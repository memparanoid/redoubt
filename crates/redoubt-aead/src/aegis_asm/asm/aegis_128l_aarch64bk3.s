// AEGIS-128L AEAD Cipher - ARM64/AArch64 Implementation
//
// This implementation uses ARM NEON Crypto Extensions for AES operations.
// The AEGIS-128L state consists of 8 blocks of 128 bits each (1024 bits total).
//
// This version uses inline macros to eliminate stack spilling of sensitive data.
// All state, key, and nonce remain in SIMD registers during initialization.
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
//   x10-x11 = Temporary pointers/counters
//   x19-x26 = Saved parameters (callee-saved - will be restored after)
//
.macro AEGIS_ZEROIZE_ALL
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

    // Zeroize temporary general purpose registers
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

    // Nuclear zeroization: clear ALL registers (including callee-saved v8-v11)
    AEGIS_ZEROIZE_ALL

    // Zeroize additional temporaries used in this function
    mov x3, xzr
    mov x4, xzr

    // Epilogue: restore callee-saved registers (overwrites zeros with original values)
    ldp d10, d11, [sp, #16]
    ldp d8, d9, [sp], #32
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
// AEGIS-128L Encryption Function (Optimized - all inline, no calls)
// ============================================================================
//
// Performs complete AEGIS-128L encryption with authentication.
//
// This version inlines all operations (init, AAD processing, encryption) to
// avoid stack spilling of sensitive data. Key and nonce remain in callee-saved
// SIMD registers throughout execution.
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
//   x10-x11 = loop counters/pointers
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
    // Note: No need to save x30 (link register) - this function makes no calls
    stp x29, x19, [sp, #-96]!
    mov x29, sp
    stp x20, x21, [sp, #16]
    stp x22, x23, [sp, #32]
    stp x24, x25, [sp, #48]
    str x26, [sp, #64]
    stp d8, d9, [sp, #72]

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

.Laad_loop:
    cmp x11, #32                     // Check if at least 32 bytes remain
    b.lt .Laad_done                  // If less, done with full blocks

    // Load AAD block into temporary registers
    ld1 {v12.16b}, [x10], #16        // M0 = first 16 bytes
    ld1 {v13.16b}, [x10], #16        // M1 = second 16 bytes

    // Update state with AAD (inline)
    AEGIS_UPDATE v12, v13

    sub x11, x11, #32                // Remaining -= 32
    b .Laad_loop

.Laad_done:
    // TODO: Handle partial AAD blocks (< 32 bytes)

    // === Phase 3: Encrypt plaintext ===
    mov x10, x23                     // plaintext pointer
    mov x11, x24                     // plaintext remaining bytes

.Lenc_loop:
    cmp x11, #32                     // Check if at least 32 bytes remain
    b.lt .Lenc_done                  // If less, done with full blocks

    // Generate keystream (RFC Section 2.4)
    // keystream0 = S1 ^ S4 ^ S5 ^ (S2 & S3)
    and v12.16b, v2.16b, v3.16b      // v12 = S2 & S3
    eor v12.16b, v12.16b, v1.16b     // v12 ^= S1
    eor v12.16b, v12.16b, v4.16b     // v12 ^= S4
    eor v12.16b, v12.16b, v5.16b     // v12 = keystream0

    // keystream1 = S2 ^ S5 ^ S6 ^ (S3 & S4)
    and v13.16b, v3.16b, v4.16b      // v13 = S3 & S4
    eor v13.16b, v13.16b, v2.16b     // v13 ^= S2
    eor v13.16b, v13.16b, v5.16b     // v13 ^= S5
    eor v13.16b, v13.16b, v6.16b     // v13 = keystream1

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
    b .Lenc_loop

.Lenc_done:
    // TODO: Handle partial plaintext blocks (< 32 bytes)
    // For now, this implementation only supports plaintext lengths
    // that are multiples of 32 bytes. Partial blocks should be handled
    // in Rust wrapper or in a future assembly implementation.
    //
    // If x11 != 0 here, we have leftover bytes - this is unsupported

.Lfinalize:
    // === Phase 4: Finalization and Tag Generation ===
    // RFC Section 2.5:
    //   tmp = S3 ^ (aad_bits || msg_bits)  // 128-bit block
    //   Update(tmp, tmp) × 7               // 7 update rounds
    //   tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

    // Convert lengths from bytes to bits (multiply by 8 = left shift by 3)
    lsl x10, x22, #3                 // x10 = aad_bits (64-bit)
    lsl x11, x24, #3                 // x11 = msg_bits (64-bit)

    // Build 128-bit block: [aad_bits (low 64) || msg_bits (high 64)]
    // Store to v28 as [aad_bits, msg_bits] in little-endian
    fmov d28, x10                    // d28 = aad_bits (lower 64 bits of v28)
    mov v28.d[1], x11                // v28.d[1] = msg_bits (upper 64 bits of v28)

    // tmp = S3 ^ (aad_bits || msg_bits)
    eor v28.16b, v28.16b, v3.16b     // v28 = tmp

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

    // Nuclear zeroization: clear ALL registers (including callee-saved v8-v11)
    AEGIS_ZEROIZE_ALL

    // Epilogue: restore callee-saved registers (overwrites zeros with original values)
    ldp d8, d9, [sp, #72]
    ldr x26, [sp, #64]
    ldp x24, x25, [sp, #48]
    ldp x22, x23, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x29, x19, [sp], #96
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_encrypt), .-FUNC(aegis128l_encrypt)
#endif
