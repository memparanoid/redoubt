// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L AEAD Cipher - AArch64 (AAPCS) Implementation
//
// The state is eight blocks of a hundred and twenty-eight bits, and the round
// function is the AES one — `aese` and `aesmc`, taken as a permutation rather
// than as a cipher.
//
// What this file needs and does not ask for:
//   The AES extension. There is no detection here and no fallback, because a
//   fallback would be a different algorithm with the same name. A machine
//   without it does not answer wrong, it stops: the first `aese` is an illegal
//   instruction. The build script compiles this wherever the ABI fits, so the
//   symbols exist on every AAPCS AArch64 target — which makes asking whether
//   the machine has AES somebody's job, and that somebody is whatever chooses
//   this AEAD over another. One question, asked once, where the choice is made.
//
//   That asymmetry is worth knowing: on AArch64 the extensions are there on
//   every machine anybody ships to, and on x86-64 they are all but universal
//   and not universal.
//
// Register-budgeted design goal:
//   - The state never leaves the vector registers
//   - Any spill region is named and wiped here
//   - No callee-saved register is touched, so no prologue puts a copy of one
//     of the caller's values on the stack for an epilogue to have to remove
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, Mach-O naming)
//   - Windows aarch64 EXCLUDED: the build script leaves Windows out for both
//     architectures, so the one calling convention this file has to be right
//     about is the one it was written against.
//
// What crosses into here, and what does not:
//   Every argument is a pointer to storage the caller declared, and nothing is
//   returned. A returned value leaves in a register, and a register carrying
//   the answer out is a register the wipe below cannot touch. The two lengths
//   arrive by value because neither is a secret: anybody watching the call sees
//   how much went in.
//
//   What does not arrive is the tag the caller expected. `decrypt` computes a
//   tag and writes it where it was told; it does not compare. A pointer to
//   something this file never reads is a pointer the caller passes for nothing,
//   and the comparison belongs where it can be made in constant time, which is
//   `redoubt-aead-v2-core`.
//
// What must not branch:
//   Nothing here branches on a key, a nonce, a message or a tag. Every branch
//   in both routines is on a length — how many whole blocks there are, how many
//   bytes of a tail are left — and a length is public. The one comparison that
//   would have to be timing-safe is the tag one, and it is not here.
//
// What this cannot answer for:
//   The state is held in registers this file named and wiped, and in the frame
//   it named and wiped. That is a statement about this file, not about the
//   machine. When a signal is delivered the kernel writes the whole register
//   context — the vector registers included — to a frame on the user stack, and
//   nothing in user space wipes that frame on the way back. The same goes for a
//   core dump, for a page that reached swap, and for anything ptrace can read.
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
// The register budget
// ============================================================================
//
// AAPCS:
//   - Caller-saved GPR: x0-x17
//   - Caller-saved SIMD: v0-v7 and v16-v31
//   - Platform register: x18                             (DO NOT TOUCH)
//   - Callee-saved: x19-x28, x29 (FP), x30 (LR), v8-v15  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and
// every operation over the set goes through that one list. Emptying them and
// asking whether they are empty are the same registers by construction, not by
// two lists that happen to agree today.
//
// The SIMD half is here and not excluded, which is the one place this file
// parts company with the other primitives in this workspace. Theirs never write
// a vector register, so clearing one would be clearing a register they never
// touched; AEGIS is the AES round function used as a permutation, so the whole
// state lives there and nowhere else.
//
// v8-v15 are out of it because nothing here writes one — `grep` the file and
// find nothing. Writing one would mean saving the caller's low half first,
// which is a copy of somebody else's value on our stack.
//
// What each one holds. Both routines use the same allocation, and the peak live
// vector set is fourteen against a budget of twenty-four:
//
//   v0-v7        the state, S0 to S7, live from init to the tag
//   v16-v17      the pair of blocks being absorbed — AAD, plaintext, ciphertext
//   v18-v19      scratch and keystream; the two constants at init
//   v20          AEGIS_UPDATE: the old S7, which S'0 is made from
//   v22          the zero vector `aese` needs, written once and kept
//   v21, v23-v31 nothing writes them, and see above for why they are listed
//
//   x0-x7        the arguments on the way in, then temporaries
//   x8, x9       the AAD and how long it was, kept until the tag needs it
//   x10, x11     the message and its length, kept until the tag needs it
//   x12, x13     where the tag goes
//   x14-x17      nothing writes them, and see above
//
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

// Gathers into the first of each half, which is in its own list and therefore
// contributes its own value on its own line. Only the probe at the end uses
// these, and they are here rather than there so that the budget and everything
// done to it sit together.
.macro AEGIS_GATHER_VECTOR n
    orr v0.16b, v0.16b, v\n\().16b
.endm

.macro AEGIS_GATHER_GENERAL reg
    orr x1, x1, \reg
.endm

// Copies what x0 and v0 already hold into each of them, the two sources
// included and harmless.
.macro AEGIS_FILL_VECTOR n
    mov v\n\().16b, v0.16b
.endm

.macro AEGIS_FILL_GENERAL reg
    mov \reg, x0
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro AEGIS_ZEROIZE_ALL
    AEGIS_EACH_VECTOR AEGIS_CLEAR_VECTOR
    AEGIS_EACH_GENERAL AEGIS_CLEAR_GENERAL
.endm

// ============================================================================
// Frame layout — 32 bytes, entirely above sp
// ============================================================================
//
//   PARTIAL  0..31   one block of a message that did not fill one, padded here
//
// The frame is taken where it is needed and given back at once, rather than
// held for the length of the routine. What sits in it is a piece of the AAD or
// of the message in the clear, and the routine around it runs for as long as
// the message does — so the window it is exposed for is the thing worth keeping
// short, and the probe at the end of this file reads the same thirty-two bytes
// either way.
//
// Written before it is read, both times: the second use must not see what the
// first left, and the wipe below runs before the stack pointer moves back.
//
.set PARTIAL, 0
.set FRAME, 32

.macro AEGIS_EMPTY_FRAME
    stp xzr, xzr, [sp, #PARTIAL]
    stp xzr, xzr, [sp, #(PARTIAL + 16)]
.endm

// ============================================================================
// AEGIS-128L Update Macro (Inline - register-budgeted, no stack spilling)
// ============================================================================
//
// Performs one AEGIS-128L state update round completely in registers.
// This macro is carefully structured to keep the peak SIMD live set <= 15.
//
// Inputs (registers):
//   v0-v7      = Current state S0-S7
//   \m0_reg    = First message block (M0)
//   \m1_reg    = Second message block (M1)
//   v22        = MUST be zero vector (persistent) for aese
//
// Outputs:
//   v0-v7      = Updated state S'0-S'7 (modified in-place)
//
// Temporaries used (fixed):
//   v18        = AES round working register
//   v19        = Key/XOR temporary
//   v20        = Saved old S7 (required for S'0)
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
    // PRECONDITION: v22 must be initialized to zero (movi v22.16b, #0)
    //               before first invocation. Persistent across all calls.

    // Preserve old S7 for S'0 (S7 is overwritten early in the in-place schedule)
    mov v20.16b, v7.16b

    // ---- Compute S'7..S'1 in descending order (in-place safe) ----
    //
    // Schedule safety: Each S'i = AESRound(S_{i-1}, S_i)
    //   - Reads S_{i-1} and S_i BEFORE overwriting S_i
    //   - Descending order ensures S_{i-1} not yet overwritten when needed
    //   - Example: S'7 reads S6,S7 → overwrites S7 → S'6 reads S5,S6 (S6 intact)
    //
    // Exception: S'0 = AESRound(S7, S0^M0) needs OLD S7 → saved in v20 first

    // S'7 = AESRound(S6, S7)
    mov v18.16b, v6.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v7.16b, v18.16b, v7.16b

    // S'6 = AESRound(S5, S6)
    mov v18.16b, v5.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v6.16b, v18.16b, v6.16b

    // S'5 = AESRound(S4, S5)
    mov v18.16b, v4.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v5.16b, v18.16b, v5.16b

    // S'4 = AESRound(S3, S4 ^ M1)
    eor v19.16b, v4.16b, \m1_reg\().16b
    mov v18.16b, v3.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v4.16b, v18.16b, v19.16b

    // S'3 = AESRound(S2, S3)
    mov v18.16b, v2.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v3.16b, v18.16b, v3.16b

    // S'2 = AESRound(S1, S2)
    mov v18.16b, v1.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v2.16b, v18.16b, v2.16b

    // S'1 = AESRound(S0, S1)
    mov v18.16b, v0.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v1.16b, v18.16b, v1.16b

    // ---- Compute S'0 last (requires old S7 and old S0) ----

    // S'0 = AESRound(old S7, S0 ^ M0)
    eor v19.16b, v0.16b, \m0_reg\().16b
    mov v18.16b, v20.16b
    aese v18.16b, v22.16b
    aesmc v18.16b, v18.16b
    eor v0.16b, v18.16b, v19.16b
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
// AEGIS-128L Encryption Function (Full support including partial blocks)
// ============================================================================
//
// Performs complete AEGIS-128L encryption with authentication.
//
// Parameters:
//   x0 = pointer to key (16 bytes)
//   x1 = pointer to nonce (16 bytes)
//   x2 = pointer to AAD (additional authenticated data)
//   x3 = AAD length in bytes
//   x4 = pointer to plaintext (overwritten with ciphertext in-place)
//   x5 = plaintext length in bytes
//   x6 = pointer to tag output (16 bytes)
//
// Returns: void (plaintext buffer contains ciphertext, tag written)
//
.global FUNC(redoubt_aegis128l_encrypt)
HIDDEN_FUNC(redoubt_aegis128l_encrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(redoubt_aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_encrypt):
    // Save parameters to caller-saved registers
    mov x8, x2                       // x8  = AAD pointer
    mov x9, x3                       // x9  = AAD length (keep for finalization)
    mov x10, x4                      // x10 = plaintext pointer (in-place transform)
    mov x11, x5                      // x11 = plaintext length (keep for finalization)
    mov x12, x6                      // x12 = tag pointer

    // Persistent zero vector for aese (required by AEGIS_UPDATE)
    movi v22.16b, #0

    // === Phase 1: Initialization ===
    // Load key and nonce
    ld1 {v16.16b}, [x0]              // v16 = key
    ld1 {v17.16b}, [x1]              // v17 = nonce

    // Load constants (reuse x0 as temp)
#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add  x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1@PAGE
    add  x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]              // v19 = C1
#else
    adrp x0, AEGIS_C0
    add  x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1
    add  x0, x0, :lo12:AEGIS_C1
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

    // 10 initialization rounds (absorb nonce/key)
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
    mov x0, x8                       // x0 = AAD pointer
    mov x1, x9                       // x1 = AAD remaining

Laad_full_blocks:
    cmp x1, #32
    b.lt Laad_partial

    ld1 {v16.16b}, [x0], #16         // M0
    ld1 {v17.16b}, [x0], #16         // M1
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b Laad_full_blocks

Laad_partial:
    cbz x1, Laad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the AAD, the bytes that did
// ║ not fill a block, padded here because the caller's buffer has no room to
// ║ pad in.
// ║
// ║ It goes through memory and not through a lane at a time because `ins`
// ║ takes a constant index, and a tail is as long as it is. Reaching a
// ║ variable lane would mean a jump table with one arm per length, which is
// ║ more code than this and a branch on the length in every one of them.
// ║
// ║ Frame is emptied before it is written and emptied again before sp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════

    sub sp, sp, #FRAME
    AEGIS_EMPTY_FRAME

    mov x2, sp
    mov x3, x1
Laad_copy_loop:
    cbz x3, Laad_copy_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b Laad_copy_loop
Laad_copy_done:
    ld1 {v16.16b, v17.16b}, [sp]

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║
    AEGIS_EMPTY_FRAME
    add sp, sp, #FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

Laad_done:

    // === Phase 3: Encrypt plaintext ===
    mov x0, x10                      // x0 = plaintext pointer
    mov x1, x11                      // x1 = plaintext remaining

Lenc_full_blocks:
    cmp x1, #32
    b.lt Lenc_partial

    // Load plaintext into v16/v17 (kept intact for state update)
    ld1 {v16.16b, v17.16b}, [x0]

    // Generate keystream (RFC Section 2.4)
    // z0 = S1 ^ S6 ^ (S2 & S3)
    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    // z1 = S2 ^ S5 ^ (S6 & S7)
    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

    // ciphertext = plaintext ^ keystream (store in v18/v19; plaintext stays in v16/v17)
    eor v18.16b, v18.16b, v16.16b
    eor v19.16b, v19.16b, v17.16b

    // Write ciphertext in-place
    st1 {v18.16b, v19.16b}, [x0]
    add x0, x0, #32

    // Update state with plaintext (not ciphertext)
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b Lenc_full_blocks

Lenc_partial:
    cbz x1, Lfinalize

    // Generate keystream BEFORE stack allocation (keep in v18/v19)
    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the message in the clear —
// ║ plaintext on the way in, and the ciphertext it becomes on the way out.
// ║
// ║ It goes through memory and not through a lane at a time because `ins`
// ║ takes a constant index, and a tail is as long as it is.
// ║
// ║ Frame is emptied before it is written and emptied again before sp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════

    sub sp, sp, #FRAME
    AEGIS_EMPTY_FRAME

    // Copy partial plaintext to buffer
    mov x2, sp
    mov x3, x1
Lenc_copy_pt_loop:
    cbz x3, Lenc_copy_pt_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b Lenc_copy_pt_loop
Lenc_copy_pt_done:

    // Load zero-padded plaintext into v16/v17
    ld1 {v16.16b, v17.16b}, [sp]

    // ciphertext = plaintext ^ keystream (write into v18/v19)
    eor v18.16b, v18.16b, v16.16b
    eor v19.16b, v19.16b, v17.16b

    // Store ciphertext to buffer
    st1 {v18.16b, v19.16b}, [sp]

    // Copy ciphertext in-place to plaintext buffer
    sub x0, x0, x1
    mov x2, sp
    mov x3, x1
Lenc_copy_ct_inplace_loop:
    cbz x3, Lenc_copy_ct_inplace_done
    ldrb w4, [x2], #1
    strb w4, [x0], #1
    sub x3, x3, #1
    b Lenc_copy_ct_inplace_loop
Lenc_copy_ct_inplace_done:

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║     (contains plaintext - MUST be cleared immediately)
// ║
    AEGIS_EMPTY_FRAME
    add sp, sp, #FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext
    AEGIS_UPDATE v16, v17

Lfinalize:
    // === Phase 4: Finalization and Tag Generation ===
    // RFC Section 2.5:
    //   tmp = S2 ^ (le64(ad_len_bits) || le64(msg_len_bits))
    //   Update(tmp, tmp) × 7
    //   tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

    lsl x0, x9, #3                   // aad_bits
    lsl x1, x11, #3                  // msg_bits

    fmov d16, x0
    mov  v16.d[1], x1
    eor  v16.16b, v16.16b, v2.16b

    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16

    // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    st1 {v16.16b}, [x12]

    // Zeroize all caller-saved registers
    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(redoubt_aegis128l_encrypt), .-FUNC(redoubt_aegis128l_encrypt)
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
//   x4 = pointer to ciphertext (overwritten with plaintext in-place)
//   x5 = ciphertext length in bytes
//   x6 = pointer to computed tag output (16 bytes)
//
// The tag the caller expected does not arrive here. It would be a pointer this
// routine loads and never reads — and the comparison it exists for is not ours
// to make, for the reason above.
//
// Returns: void (ciphertext buffer contains plaintext, computed tag written)
//
.global FUNC(redoubt_aegis128l_decrypt)
HIDDEN_FUNC(redoubt_aegis128l_decrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(redoubt_aegis128l_decrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_decrypt):
    // Save parameters
    mov x8,  x2                      // x8  = AAD pointer
    mov x9,  x3                      // x9  = AAD length
    mov x10, x4                      // x10 = ciphertext pointer (in-place transform)
    mov x11, x5                      // x11 = ciphertext length
    mov x13, x6                      // x13 = computed_tag pointer

    // Persistent zero vector for aese (required by AEGIS_UPDATE)
    movi v22.16b, #0

    // === Phase 1: Initialization ===
    ld1 {v16.16b}, [x0]              // v16 = key
    ld1 {v17.16b}, [x1]              // v17 = nonce

#if defined(__APPLE__)
    adrp x0, AEGIS_C0@PAGE
    add  x0, x0, AEGIS_C0@PAGEOFF
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1@PAGE
    add  x0, x0, AEGIS_C1@PAGEOFF
    ld1 {v19.16b}, [x0]              // v19 = C1
#else
    adrp x0, AEGIS_C0
    add  x0, x0, :lo12:AEGIS_C0
    ld1 {v18.16b}, [x0]              // v18 = C0
    adrp x0, AEGIS_C1
    add  x0, x0, :lo12:AEGIS_C1
    ld1 {v19.16b}, [x0]              // v19 = C1
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

Ldec_aad_full_blocks:
    cmp x1, #32
    b.lt Ldec_aad_partial

    ld1 {v16.16b}, [x0], #16
    ld1 {v17.16b}, [x0], #16
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b Ldec_aad_full_blocks

Ldec_aad_partial:
    cbz x1, Ldec_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the AAD, the bytes that did
// ║ not fill a block, padded here because the caller's buffer has no room to
// ║ pad in.
// ║
// ║ It goes through memory and not through a lane at a time because `ins`
// ║ takes a constant index, and a tail is as long as it is. Reaching a
// ║ variable lane would mean a jump table with one arm per length, which is
// ║ more code than this and a branch on the length in every one of them.
// ║
// ║ Frame is emptied before it is written and emptied again before sp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════

    sub sp, sp, #FRAME
    AEGIS_EMPTY_FRAME

    mov x2, sp
    mov x3, x1
Ldec_aad_copy_loop:
    cbz x3, Ldec_aad_copy_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b Ldec_aad_copy_loop
Ldec_aad_copy_done:

    ld1 {v16.16b, v17.16b}, [sp]

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║
    AEGIS_EMPTY_FRAME
    add sp, sp, #FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE v16, v17

Ldec_aad_done:

    // === Phase 3: Decrypt ciphertext ===
    mov x0, x10
    mov x1, x11

Ldec_full_blocks:
    cmp x1, #32
    b.lt Ldec_partial

    // Load ciphertext
    ld1 {v16.16b, v17.16b}, [x0]

    // Generate keystream
    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

    // plaintext = ciphertext ^ keystream (in-place in v16/v17)
    eor v16.16b, v16.16b, v18.16b
    eor v17.16b, v17.16b, v19.16b

    // Store plaintext in-place
    st1 {v16.16b, v17.16b}, [x0]
    add x0, x0, #32

    // Update state with PLAINTEXT
    AEGIS_UPDATE v16, v17

    sub x1, x1, #32
    b Ldec_full_blocks

Ldec_partial:
    cbz x1, Ldec_finalize

    // Generate keystream (v18/v19) BEFORE stack allocation
    and v18.16b, v2.16b, v3.16b
    eor v18.16b, v18.16b, v1.16b
    eor v18.16b, v18.16b, v6.16b

    and v19.16b, v6.16b, v7.16b
    eor v19.16b, v19.16b, v2.16b
    eor v19.16b, v19.16b, v5.16b

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the message — the ciphertext
// ║ on the way in, and the plaintext it is deciphered into on the way out. This
// ║ is the one region in either routine that holds a plaintext the caller has
// ║ not authenticated yet.
// ║
// ║ It goes through memory and not through a lane at a time because `ins`
// ║ takes a constant index, and a tail is as long as it is.
// ║
// ║ Frame is emptied before it is written and emptied again before sp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════

    sub sp, sp, #FRAME
    AEGIS_EMPTY_FRAME

    // Copy partial ciphertext
    mov x2, sp
    mov x3, x1
Ldec_copy_ct_loop:
    cbz x3, Ldec_copy_ct_done
    ldrb w4, [x0], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b Ldec_copy_ct_loop
Ldec_copy_ct_done:

    // Load zero-padded ciphertext into v16/v17
    ld1 {v16.16b, v17.16b}, [sp]

    // plaintext = ciphertext ^ keystream (in-place v16/v17)
    eor v16.16b, v16.16b, v18.16b
    eor v17.16b, v17.16b, v19.16b

    // Store plaintext to buffer (still padded)
    st1 {v16.16b, v17.16b}, [sp]

    // Zero bytes beyond valid length (padding must not be absorbed as real bytes)
    add x2, sp, x1
    mov x3, #32
    sub x3, x3, x1
Ldec_zero_padding_loop:
    cbz x3, Ldec_zero_padding_done
    strb wzr, [x2], #1
    sub x3, x3, #1
    b Ldec_zero_padding_loop
Ldec_zero_padding_done:

    // Copy plaintext in-place to ciphertext buffer
    sub x0, x0, x1
    mov x2, sp
    mov x3, x1
Ldec_copy_pt_inplace_loop:
    cbz x3, Ldec_copy_pt_inplace_done
    ldrb w4, [x2], #1
    strb w4, [x0], #1
    sub x3, x3, #1
    b Ldec_copy_pt_inplace_loop
Ldec_copy_pt_inplace_done:

    // Reload padded plaintext for state update
    ld1 {v16.16b, v17.16b}, [sp]

// ║
// ║ >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
// ║     (contains DECRYPTED PLAINTEXT - MUST be cleared immediately)
// ║
    AEGIS_EMPTY_FRAME
    add sp, sp, #FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext
    AEGIS_UPDATE v16, v17

Ldec_finalize:
    // === Phase 4: Finalization ===
    lsl x0, x9, #3                   // aad_bits
    lsl x1, x11, #3                  // msg_bits

    fmov d16, x0
    mov  v16.d[1], x1
    eor  v16.16b, v16.16b, v2.16b

    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16
    AEGIS_UPDATE v16, v16

    // Generate computed tag
    eor v16.16b, v0.16b, v1.16b
    eor v16.16b, v16.16b, v2.16b
    eor v16.16b, v16.16b, v3.16b
    eor v16.16b, v16.16b, v4.16b
    eor v16.16b, v16.16b, v5.16b
    eor v16.16b, v16.16b, v6.16b

    st1 {v16.16b}, [x13]

    // Zeroize all caller-saved registers
    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(redoubt_aegis128l_decrypt), .-FUNC(redoubt_aegis128l_decrypt)
#endif

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
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own lists
//   frame_is_zeroized        asks the stack, with the file's own FRAME
//   dirty_registers          fills the budget and leaves it that way
//   dirty_frame              one byte of the frame, at an offset given
//   clean_frame              the frame written and emptied

// uint64_t redoubt_aegis128l_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and some of the bits of whatever was not otherwise.
//
// The two halves are folded separately and then together, and the order is the
// whole of it. The general registers go into x1 first, so that x0's own value
// is read before the vector half needs x0 to carry its answer out. A vector
// register is a hundred and twenty-eight bits and the answer is sixty-four, so
// the two lanes of the fold are or-ed together before it leaves — what is lost
// is which lane a bit came from, and what is kept is whether there was one.
//
// Takes no argument on purpose. A destination passed in would cost x0, and x0
// is one of the registers being asked about — it would arrive holding our own
// pointer rather than the caller's value.
//
// x30 is not in the budget and this is the routine that shows why: `bl` writes
// it on the way here, so asking about it would be asking about the call that
// did the asking.
.p2align 4
.global FUNC(redoubt_aegis128l_registers_are_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_registers_are_zeroized)
FUNC(redoubt_aegis128l_registers_are_zeroized):
    AEGIS_EACH_GENERAL AEGIS_GATHER_GENERAL
    AEGIS_EACH_VECTOR AEGIS_GATHER_VECTOR

    // x0 and x2 are folded into x1 already, so borrowing them to bring the
    // vector half down costs nothing.
    mov x0, v0.d[0]
    mov x2, v0.d[1]
    orr x0, x0, x2
    orr x0, x0, x1
    ret

// uint64_t redoubt_aegis128l_frame_is_zeroized(void)
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
// Asked after the registers, never before: reading the frame takes registers,
// and the answer about those has to be taken first.
.p2align 4
.global FUNC(redoubt_aegis128l_frame_is_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_frame_is_zeroized)
FUNC(redoubt_aegis128l_frame_is_zeroized):
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
.global FUNC(redoubt_aegis128l_dirty_registers)
HIDDEN_FUNC(redoubt_aegis128l_dirty_registers)
FUNC(redoubt_aegis128l_dirty_registers):
    // The pattern does not fit in one instruction, so it is built sixteen bits
    // at a time before anything is copied out of x0.
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    // Both lanes of the vector, so a verifier that read only one still finds
    // the poison where it looked.
    dup v0.2d, x0
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    AEGIS_EACH_GENERAL AEGIS_FILL_GENERAL
    ret

// One byte of the frame, dirtied and left. x0 says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// whatever sits next door would show.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_frame)
HIDDEN_FUNC(redoubt_aegis128l_dirty_frame)
FUNC(redoubt_aegis128l_dirty_frame):
    sub sp, sp, #FRAME
    // Isolate this byte from every previous call's residue. The wipe takes no
    // register, so x0, the requested offset, is still the caller's.
    AEGIS_EMPTY_FRAME
    mov w1, #0x5c
    strb w1, [sp, x0]
    add sp, sp, #FRAME
    ret

// The whole frame written and then emptied.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.global FUNC(redoubt_aegis128l_clean_frame)
HIDDEN_FUNC(redoubt_aegis128l_clean_frame)
FUNC(redoubt_aegis128l_clean_frame):
    sub sp, sp, #FRAME
    mov x0, #0x5c5c
    movk x0, #0x5c5c, lsl #16
    movk x0, #0x5c5c, lsl #32
    movk x0, #0x5c5c, lsl #48
    stp x0, x0, [sp, #PARTIAL]
    stp x0, x0, [sp, #(PARTIAL + 16)]
    AEGIS_EMPTY_FRAME
    add sp, sp, #FRAME
    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
