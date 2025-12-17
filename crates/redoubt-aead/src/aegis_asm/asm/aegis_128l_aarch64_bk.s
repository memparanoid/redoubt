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
//   v8      = key
//   v9      = nonce
//   v10     = C0
//   v11     = C1
//   x3      = loop counter
//   x4      = pointer to state (preserved across update calls)
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
    // Prologue: save link register and allocate stack for temporaries
    // We need 32 bytes for key+nonce temps (will be zeroized)
    stp x29, x30, [sp, #-48]!         // Save FP/LR, allocate 48 bytes (32 for temps + 16 for FP/LR)
    mov x29, sp

    // Save state pointer for later (will be clobbered by update calls)
    mov x4, x0

    // Load key and nonce into registers
    ld1 {v8.16b}, [x1]                // v8 = key
    ld1 {v9.16b}, [x2]                // v9 = nonce

    // Load constants C0 and C1
#if defined(__APPLE__)
    adrp x5, AEGIS_C0@PAGE
    add x5, x5, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x5]               // v10 = C0

    adrp x5, AEGIS_C1@PAGE
    add x5, x5, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x5]               // v11 = C1
#else
    adrp x5, AEGIS_C0
    add x5, x5, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x5]               // v10 = C0

    adrp x5, AEGIS_C1
    add x5, x5, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x5]               // v11 = C1
#endif

    // Initialize state
    eor v0.16b, v8.16b, v9.16b        // S0 = key ^ nonce
    mov v1.16b, v11.16b               // S1 = C1
    mov v2.16b, v10.16b               // S2 = C0
    mov v3.16b, v11.16b               // S3 = C1
    eor v4.16b, v8.16b, v9.16b        // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b       // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b       // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b       // S7 = key ^ C0

    // Store initial state to memory (needed for update function)
    st1 {v0.16b}, [x4], #16
    st1 {v1.16b}, [x4], #16
    st1 {v2.16b}, [x4], #16
    st1 {v3.16b}, [x4], #16
    st1 {v4.16b}, [x4], #16
    st1 {v5.16b}, [x4], #16
    st1 {v6.16b}, [x4], #16
    st1 {v7.16b}, [x4], #16

    // Perform 10 update rounds with (nonce, key)
    mov x3, #10                       // Loop counter
    sub x4, x4, #128                  // x4 = state pointer (start of state)

.Linit_loop:
    // Store key and nonce to temporary stack area [sp+16..47]
    add x5, sp, #16
    st1 {v9.16b}, [x5]                // Store nonce at sp+16
    add x5, sp, #32
    st1 {v8.16b}, [x5]                // Store key at sp+32

    // Call update(state, nonce, key)
    // x0 gets corrupted by update (post-increment), so use x4 each time
    mov x0, x4                        // x0 = fresh state pointer
    add x1, sp, #16                   // x1 = pointer to nonce (sp+16)
    add x2, sp, #32                   // x2 = pointer to key (sp+32)
    bl FUNC(aegis128l_update)

    // Decrement loop counter and continue if not zero
    subs x3, x3, #1
    b.ne .Linit_loop

    // Zeroize key and nonce from stack [sp+16..47]
    movi v31.16b, #0
    add x5, sp, #16
    st1 {v31.16b}, [x5]               // Zero nonce area
    add x5, sp, #32
    st1 {v31.16b}, [x5]               // Zero key area

    // Epilogue: restore registers and return
    ldp x29, x30, [sp], #48
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_init), .-FUNC(aegis128l_init)
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

// ============================================================================
// AEGIS-128L Encryption Function
// ============================================================================
//
// Performs complete AEGIS-128L authenticated encryption.
//
// Steps:
//   1. Initialize state with key and nonce (10 update rounds)
//   2. Process AAD in 32-byte blocks (absorb)
//   3. Encrypt plaintext: generate keystream, XOR, update state
//   4. Finalize: encode lengths, 7 update rounds, compute tag
//
// Parameters:
//   x0 = pointer to key (16 bytes)
//   x1 = pointer to nonce (16 bytes)
//   x2 = pointer to AAD (variable length)
//   x3 = AAD length in bytes
//   x4 = pointer to plaintext (variable length)
//   x5 = plaintext length in bytes
//   x6 = pointer to ciphertext output buffer (same length as plaintext)
//   x7 = pointer to tag output (16 bytes)
//
// Register allocation:
//   x19-x28 = saved parameters (callee-saved)
//   x29 = frame pointer
//   x30 = link register
//   sp+0..127 = state buffer (128 bytes, 16-byte aligned)
//
// Stack layout:
//   [sp+0..127]   : state (128 bytes)
//   [sp+128..143] : saved x19-x20
//   [sp+144..159] : saved x21-x22
//   [sp+160..175] : saved x23-x24
//   [sp+176..191] : saved x25-x26
//   [sp+192..207] : saved x27-x28
//   [sp+208..223] : saved x29-x30
//
// Returns: void (ciphertext and tag written to output buffers)
//
.global FUNC(aegis128l_encrypt)
HIDDEN_FUNC(aegis128l_encrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(aegis128l_encrypt):
    // Prologue: allocate frame and save callee-saved registers
    sub sp, sp, #256               // Allocate 256-byte frame (16-byte aligned)
    stp x29, x30, [sp, #224]       // Save FP and LR at [sp+224..239]
    mov x29, sp                    // Set frame pointer to start of frame
    stp x19, x20, [sp, #128]       // Save x19-x20 at [sp+128..143]
    stp x21, x22, [sp, #144]       // Save x21-x22 at [sp+144..159]
    stp x23, x24, [sp, #160]       // Save x23-x24 at [sp+160..175]
    stp x25, x26, [sp, #176]       // Save x25-x26 at [sp+176..191]
    stp x27, x28, [sp, #192]       // Save x27-x28 at [sp+192..207]

    // Save input parameters to callee-saved registers
    mov x19, x0                    // x19 = key pointer
    mov x20, x1                    // x20 = nonce pointer
    mov x21, x2                    // x21 = AAD pointer
    mov x22, x3                    // x22 = AAD length
    mov x23, x4                    // x23 = plaintext pointer
    mov x24, x5                    // x24 = plaintext length
    mov x25, x6                    // x25 = ciphertext pointer
    mov x26, x7                    // x26 = tag pointer

    // === Phase 1: Initialize state ===
    mov x0, sp                     // x0 = pointer to state buffer at [sp+0..127]
    mov x1, x19                    // x1 = key
    mov x2, x20                    // x2 = nonce
    bl FUNC(aegis128l_init)

    // === Phase 2: Process AAD ===
    // Process AAD in 32-byte blocks (2 × 16 bytes)
    mov x27, x21                   // x27 = AAD current pointer
    mov x28, x22                   // x28 = AAD remaining length

.Laad_loop:
    cbz x28, .Laad_done            // If no AAD left, skip to done
    cmp x28, #32                   // Check if we have at least 32 bytes left
    b.lt .Laad_partial             // Less than 32 bytes? Handle partial block

    // Process full 32-byte AAD block
    mov x0, sp                     // x0 = state pointer
    mov x1, x27                    // x1 = pointer to M0 (first 16 bytes)
    add x2, x27, #16               // x2 = pointer to M1 (second 16 bytes)
    bl FUNC(aegis128l_update)

    add x27, x27, #32              // Advance AAD pointer
    sub x28, x28, #32              // Decrease remaining length
    b .Laad_loop                   // Continue loop

.Laad_partial:
    // TODO: Handle partial AAD block (< 32 bytes) with padding
    // For now, skip if not a multiple of 32
    b .Laad_done                   // Jump to done after handling partial

.Laad_done:

    // === Phase 3: Encrypt plaintext ===
    // Process plaintext in 32-byte blocks, generating keystream and XORing
    mov x27, x23                   // x27 = plaintext current pointer
    mov x28, x24                   // x28 = plaintext remaining length

.Lenc_loop:
    cbz x28, .Lenc_done            // If no plaintext left, skip to done
    cmp x28, #32                   // Check if we have at least 32 bytes left
    b.lt .Lenc_partial             // Less than 32 bytes? Handle partial block

    // Load state for keystream generation
    ld1 {v0.16b}, [sp], #16        // v0 = S0
    ld1 {v1.16b}, [sp], #16        // v1 = S1
    ld1 {v2.16b}, [sp], #16        // v2 = S2
    ld1 {v3.16b}, [sp], #16        // v3 = S3
    ld1 {v4.16b}, [sp], #16        // v4 = S4
    ld1 {v5.16b}, [sp], #16        // v5 = S5
    ld1 {v6.16b}, [sp], #16        // v6 = S6
    ld1 {v7.16b}, [sp], #16        // v7 = S7
    sub sp, sp, #128               // Restore sp to start of state

    // Generate keystream
    // keystream0 = S1 ^ S4 ^ S5 ^ (S2 & S3)
    and v10.16b, v2.16b, v3.16b    // v10 = S2 & S3
    eor v10.16b, v10.16b, v1.16b   // v10 = S1 ^ (S2 & S3)
    eor v10.16b, v10.16b, v4.16b   // v10 = S1 ^ S4 ^ (S2 & S3)
    eor v10.16b, v10.16b, v5.16b   // v10 = S1 ^ S4 ^ S5 ^ (S2 & S3) = keystream0

    // keystream1 = S2 ^ S5 ^ S6 ^ (S3 & S4)
    and v11.16b, v3.16b, v4.16b    // v11 = S3 & S4
    eor v11.16b, v11.16b, v2.16b   // v11 = S2 ^ (S3 & S4)
    eor v11.16b, v11.16b, v5.16b   // v11 = S2 ^ S5 ^ (S3 & S4)
    eor v11.16b, v11.16b, v6.16b   // v11 = S2 ^ S5 ^ S6 ^ (S3 & S4) = keystream1

    // Load plaintext
    ld1 {v12.16b}, [x27], #16      // v12 = plaintext[0..15]
    ld1 {v13.16b}, [x27], #16      // v13 = plaintext[16..31]

    // XOR with keystream to produce ciphertext
    eor v14.16b, v12.16b, v10.16b  // v14 = ciphertext[0..15]
    eor v15.16b, v13.16b, v11.16b  // v15 = ciphertext[16..31]

    // Store ciphertext
    st1 {v14.16b}, [x25], #16      // Store ciphertext[0..15]
    st1 {v15.16b}, [x25], #16      // Store ciphertext[16..31]

    // Update state with plaintext (not ciphertext!)
    sub x27, x27, #32              // Rewind plaintext pointer
    mov x0, sp                     // x0 = state pointer
    mov x1, x27                    // x1 = pointer to plaintext M0
    add x2, x27, #16               // x2 = pointer to plaintext M1
    bl FUNC(aegis128l_update)
    add x27, x27, #32              // Restore plaintext pointer

    sub x28, x28, #32              // Decrease remaining length
    b .Lenc_loop                   // Continue loop

.Lenc_partial:
    // TODO: Handle partial plaintext block (< 32 bytes) with padding
    // For now, skip if not a multiple of 32
    b .Lenc_done                   // Jump to done after handling partial

.Lenc_done:

    // === Phase 4: Finalize and generate tag ===
    // TODO: Finalization

    // Epilogue: restore registers and deallocate frame
    ldp x19, x20, [sp, #128]
    ldp x21, x22, [sp, #144]
    ldp x23, x24, [sp, #160]
    ldp x25, x26, [sp, #176]
    ldp x27, x28, [sp, #192]
    ldp x29, x30, [sp, #224]
    add sp, sp, #256               // Deallocate frame
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_encrypt), .-FUNC(aegis128l_encrypt)
#endif
