// AEGIS-128L AEAD Cipher - ARM64/AArch64 Implementation
//
// This implementation uses ARM NEON Crypto Extensions for AES operations.
// The AEGIS-128L state consists of 8 blocks of 128 bits each (1024 bits total).
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
// AEGIS-128L State Update Function
// ============================================================================
//
// Performs one round of AEGIS-128L state update with message absorption.
//
// The AEGIS-128L state consists of 8 blocks: state[0..7]
// Each block is 128 bits (16 bytes).
//
// Update algorithm (from RFC Section 2.4):
//   S'0 = AESRound(S7, S0 ^ M0)
//   S'1 = AESRound(S0, S1)
//   S'2 = AESRound(S1, S2)
//   S'3 = AESRound(S2, S3)
//   S'4 = AESRound(S3, S4 ^ M1)
//   S'5 = AESRound(S4, S5)
//   S'6 = AESRound(S5, S6)
//   S'7 = AESRound(S6, S7)
//
// Where AESRound(key, data) performs one AES encryption round:
//   - ARM implementation: aese data, key; aesmc data, data
//   - aese: SubBytes + ShiftRows + AddRoundKey (XOR with key)
//   - aesmc: MixColumns
//
// Parameters:
//   x0 = pointer to state (8 blocks = 128 bytes, must be 16-byte aligned)
//   x1 = pointer to M0 (16 bytes)
//   x2 = pointer to M1 (16 bytes)
//
// Register allocation:
//   v0-v7   = S0-S7 (current state)
//   v8      = M0 (first message block)
//   v9      = M1 (second message block)
//   v16-v23 = S'0-S'7 (new state, computed without overwriting old state)
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
    // Load current state S0-S7 into registers v0-v7
    ld1 {v0.16b}, [x0], #16      // v0 = S0
    ld1 {v1.16b}, [x0], #16      // v1 = S1
    ld1 {v2.16b}, [x0], #16      // v2 = S2
    ld1 {v3.16b}, [x0], #16      // v3 = S3
    ld1 {v4.16b}, [x0], #16      // v4 = S4
    ld1 {v5.16b}, [x0], #16      // v5 = S5
    ld1 {v6.16b}, [x0], #16      // v6 = S6
    ld1 {v7.16b}, [x0], #16      // v7 = S7

    // Load message blocks M0 and M1
    ld1 {v8.16b}, [x1]           // v8 = M0
    ld1 {v9.16b}, [x2]           // v9 = M1

    // Restore x0 to point to beginning of state
    sub x0, x0, #128

    // Create zero vector for aese instruction
    // AEGIS spec requires: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    // But ARM aese does: AddRoundKey -> SubBytes -> ShiftRows
    // Solution: use aese with zero (no-op XOR), then manual eor for AddRoundKey
    movi v31.16b, #0

    // Compute new state S'0-S'7 in registers v16-v23
    // This ensures old state values remain available for all computations

    // S'0 = AESRound(S7, S0 ^ M0)
    // Process S7 (apply SubBytes+ShiftRows+MixColumns), then XOR with (S0 ^ M0)
    mov v16.16b, v7.16b          // v16 = S7 (data to process)
    aese v16.16b, v31.16b        // SubBytes + ShiftRows (XOR with zero = no-op)
    aesmc v16.16b, v16.16b       // MixColumns
    eor v10.16b, v0.16b, v8.16b  // v10 = S0 ^ M0
    eor v16.16b, v16.16b, v10.16b // AddRoundKey: XOR with (S0 ^ M0)

    // S'1 = AESRound(S0, S1)
    // Process S0, then XOR with S1
    mov v17.16b, v0.16b          // v17 = S0
    aese v17.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v17.16b, v17.16b       // MixColumns
    eor v17.16b, v17.16b, v1.16b // AddRoundKey: XOR with S1

    // S'2 = AESRound(S1, S2)
    mov v18.16b, v1.16b          // v18 = S1
    aese v18.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v18.16b, v18.16b       // MixColumns
    eor v18.16b, v18.16b, v2.16b // AddRoundKey: XOR with S2

    // S'3 = AESRound(S2, S3)
    mov v19.16b, v2.16b          // v19 = S2
    aese v19.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v19.16b, v19.16b       // MixColumns
    eor v19.16b, v19.16b, v3.16b // AddRoundKey: XOR with S3

    // S'4 = AESRound(S3, S4 ^ M1)
    // Process S3, then XOR with (S4 ^ M1)
    mov v20.16b, v3.16b          // v20 = S3
    aese v20.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v20.16b, v20.16b       // MixColumns
    eor v10.16b, v4.16b, v9.16b  // v10 = S4 ^ M1
    eor v20.16b, v20.16b, v10.16b // AddRoundKey: XOR with (S4 ^ M1)

    // S'5 = AESRound(S4, S5)
    mov v21.16b, v4.16b          // v21 = S4
    aese v21.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v21.16b, v21.16b       // MixColumns
    eor v21.16b, v21.16b, v5.16b // AddRoundKey: XOR with S5

    // S'6 = AESRound(S5, S6)
    mov v22.16b, v5.16b          // v22 = S5
    aese v22.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v22.16b, v22.16b       // MixColumns
    eor v22.16b, v22.16b, v6.16b // AddRoundKey: XOR with S6

    // S'7 = AESRound(S6, S7)
    mov v23.16b, v6.16b          // v23 = S6
    aese v23.16b, v31.16b        // SubBytes + ShiftRows
    aesmc v23.16b, v23.16b       // MixColumns
    eor v23.16b, v23.16b, v7.16b // AddRoundKey: XOR with S7

    // Store new state S'0-S'7 back to memory
    st1 {v16.16b}, [x0], #16     // Store S'0
    st1 {v17.16b}, [x0], #16     // Store S'1
    st1 {v18.16b}, [x0], #16     // Store S'2
    st1 {v19.16b}, [x0], #16     // Store S'3
    st1 {v20.16b}, [x0], #16     // Store S'4
    st1 {v21.16b}, [x0], #16     // Store S'5
    st1 {v22.16b}, [x0], #16     // Store S'6
    st1 {v23.16b}, [x0], #16     // Store S'7

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_update), .-FUNC(aegis128l_update)
#endif
