// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// HKDF-SHA256 by hand, for aarch64 under AAPCS.
//
// # One path, and what it costs
//
// There is no runtime feature detection, no cryptographic-extension path and no
// SVE path: what the machine has is not asked, so the same instructions run
// everywhere and what is written here is what executed. A second copy would
// need a check, another copy of the rounds, and a wipe written once per
// register file — and none of that is paid for until somebody measures that it
// matters.
//
// The floor is the ARMv8-A baseline, and here that is the truth rather than a
// hope: the rounds use `ld1`, `st1`, `rev32`, `umov`, `ins` and `add` over the
// `v` registers, and every one of them is in the base instruction set. The
// SHA-256 extension instructions — `sha256h`, `sha256su0` — are not used and
// are not baseline, which is the line this file does not cross.
//
// # What crosses the boundary
//
// Four routines, in the order `backend/mod.rs` declares them. Every argument is
// a pointer to storage the caller declared, except the lengths, which are
// public: how long a message is says nothing about what is in it. Nothing is
// returned — a returned value leaves in a register, and a register carrying the
// answer out is one the wipe at the end cannot touch.
//
// # What must not branch on a secret
//
// Nothing here does. SHA-256 is adds, rotations and boolean functions over
// words, and the only branches are the block loop and the padding, which are
// decided by lengths the caller already knows.
//
// # What this file cannot answer for
//
// A core dump, a page that went to swap, a debugger attached to the process, or
// a signal handler that ran between two of these instructions. The registers
// and the frame are emptied before each routine returns; what the kernel did
// with them in between is outside what any of this can promise.

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
// The register budget
// ============================================================================
//
// AAPCS64:
//   - Caller-saved GPR: x0-x17
//   - Callee-saved GPR: x19-x28  (DO NOT TOUCH)
//   - Caller-saved SIMD: v0-v7, v16-v31
//   - Callee-saved SIMD: v8-v15, and only their low halves  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and every
// operation over the set goes through that one list. Emptying them and asking
// whether they are empty are the same registers by construction, not two lists
// that happen to agree today.
//
// The general list is the whole caller-saved set, and here that is also every
// register the file writes, so there is no exception to record.
//
// The vector list is v0, v1 and v16 through v24, which is where this file stops
// writing. That is the one place the rule above is not followed, and the reason
// is measured in calls: the compression clears its registers once per block of
// every message there is, and thirteen `movi` for registers nothing puts
// anything in are thirteen instructions per block for nothing.
//
// A routine that reaches for any other vector register has to add it here. That
// is the cost of the exception, and it is written down so the next reader knows
// the list is short on purpose rather than by oversight.
//
// Does NOT include sp, x18, x19-x28 or v8-v15. A routine that spilled into a
// callee-saved one would have to save it first, and that save is what writes
// the caller's register to the stack — a value that was never ours, that we
// cannot name, and that the caller cannot wipe because it does not know a copy
// was made.
//
// Does NOT include x30 either, and that one is not a choice. Every `bl` writes
// the link register, including the `bl` that reaches a verifier, so asking a
// verifier about x30 would be asking it about its own call. What the routines
// do instead is keep the caller's x30 in a frame slot across their own calls,
// and load it back before the frame is emptied.

.macro HKDF_EACH_GPR op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro HKDF_EACH_VECTOR op
    .irp reg,0,1,16,17,18,19,20,21,22,23,24
        \op v\reg
    .endr
.endm

.macro HKDF_CLEAR_GPR reg
    mov \reg, xzr
.endm

.macro HKDF_CLEAR_VECTOR reg
    movi \reg\().16b, #0
.endm

// Copies what x0 already holds into each of them, x0 included and harmless.
// Only the probe at the end of this file uses it, and it is here rather than
// there so that the budget has one list and every operation over it sits beside
// that list.
.macro HKDF_FILL_GPR reg
    mov \reg, x0
.endm

// Copies what v0 already holds into each of them, v0 included and harmless.
.macro HKDF_FILL_VECTOR reg
    mov \reg\().16b, v0.16b
.endm

// Gathers into x1, which is in the budget and therefore contributes its own
// value on its own line. What the gather leaves in x1 is the bits of anything
// that was not empty.
.macro HKDF_GATHER_GPR reg
    orr x1, x1, \reg
.endm

// Gathers into v0, whose own value goes in on the first line for the same
// reason.
.macro HKDF_GATHER_VECTOR reg
    orr v0.16b, v0.16b, \reg\().16b
.endm

// ============================================================================
// Catastrophic register zeroization
// ============================================================================
.macro HKDF_SHA256_ZEROIZE_ALL
    HKDF_EACH_GPR HKDF_CLEAR_GPR
    HKDF_EACH_VECTOR HKDF_CLEAR_VECTOR
.endm

// ============================================================================
// The frames
// ============================================================================
//
// One size per routine rather than one for the file. A single size would make
// the widest routine's frame the price every one of them pays, on every call,
// and `sha256_compress_block` is called once per block of every message there
// is.
//
// What a shared size buys is a probe written once. That is bought here another
// way: the probe at the end of this file is a macro instantiated per routine
// with that routine's own constant, so each verifier reads the window its
// routine took and the number still lives in exactly one place.
//
// Every size is a multiple of sixteen, which is what the architecture requires
// of the stack pointer at all times. `bl` writes no stack, so unlike x86-64
// there is no return-address slot to step over: the frame is exactly
// `[sp - FRAME, sp)` as the caller left it.
//
// Every routine that calls another has a slot for the link register. It is the
// caller's return address, which is public, and it is loaded back before the
// frame is emptied — so the slot goes out zeroized with everything else.

// sha256_compress_block: the message schedule. It calls nothing, so it needs no
// slot for the link register, and its arguments stay in the registers they
// arrived in for as long as they are read.
.set COMPRESS_W, 0
.set FRAME_COMPRESS, 64

// sha256_hash: the chaining state, the padded tail, and what has to outlive a
// call to the compression — which empties every caller-saved register before it
// returns, so nothing survives in one.
.set HASH_H, 0
.set HASH_BLOCK1, 32
.set HASH_BLOCK2, 96
.set HASH_MSG, 160
.set HASH_LEFT, 168
.set HASH_TOTAL, 176
.set HASH_DIGEST, 184
.set HASH_LR, 192
.set FRAME_HASH, 208

// sha256_update_finalize: the same, over a state the caller already has. The
// caller's H is read once at the start and never again, so it needs no slot.
.set UPDATE_H, 0
.set UPDATE_BLOCK1, 32
.set UPDATE_BLOCK2, 96
.set UPDATE_MSG, 160
.set UPDATE_LEFT, 168
.set UPDATE_TOTAL, 176
.set UPDATE_DIGEST, 184
.set UPDATE_LR, 192
.set FRAME_UPDATE, 208

// sha256_absorb: where it is in a message it is being handed in pieces.
.set ABSORB_H, 0
.set ABSORB_SRC, 8
.set ABSORB_LEFT, 16
.set ABSORB_BLOCK, 24
.set ABSORB_FILL, 32
.set ABSORB_LR, 40
.set FRAME_ABSORB, 48

// hmac_sha256: the key padded to a block, the inner and outer pads made from
// it, the inner digest, somewhere to hash a key that is too long, and the
// chaining state.
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

// hkdf_sha256: the pseudorandom key, the two pads made from it, the block being
// filled, the chaining state, the inner digest, the block of output being made,
// and the arguments that have to outlive a call.
//
// The pads are built once and read every iteration, which is why the expansion
// here does not call `hmac_sha256`: that routine would rebuild them from the
// key each time, and would want the message in one piece — which is the whole
// of the reason this routine used to size its frame from `info_len`.
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

// Empties a frame of `size` bytes and gives it back.
//
// Takes the size rather than reading one constant, because the routines here do
// not share a frame. What keeps it honest is that every call site names the
// same constant its own `sub sp` did.
.macro HKDF_EMPTY_FRAME size
    .set _empty_at, 0
    .rept \size / 16
        stp xzr, xzr, [sp, #_empty_at]
        .set _empty_at, _empty_at + 16
    .endr
    add sp, sp, #\size
.endm


// ============================================================================
// Constants
// ============================================================================

RODATA_SECTION
.p2align 6

// SHA-256 K constants (64 rounds)
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

// SHA-256 Initial Hash Values (H^(0) per FIPS 180-4)
.LH256_INIT:
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
// Registers: none callee-saved, and none preserved. Every caller-saved register
//            is empty when this returns, which is what the callers here are
//            written against — anything of theirs that has to survive the call
//            is in their own frame.
//
// Stack layout: FRAME_COMPRESS bytes, laid out by the COMPRESS_* constants
//               above, and zeroized in full before return.
//
.global FUNC(redoubt_sha256_compress_block)
HIDDEN_FUNC(redoubt_sha256_compress_block)
.p2align 4
FUNC(redoubt_sha256_compress_block):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: COMPRESS_W holds the message schedule, whose first
// ║ sixteen words are the caller's block in the clear and whose rest is that
// ║ block mixed with itself.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_COMPRESS

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

    // Load .LK256 pointer
#if defined(__APPLE__)
    adrp    x3, .LK256@PAGE
    add     x3, x3, .LK256@PAGEOFF
#else
    adrp    x3, .LK256
    add     x3, x3, :lo12:.LK256
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

    HKDF_EMPTY_FRAME FRAME_COMPRESS
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
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
.global FUNC(redoubt_sha256_hash)
HIDDEN_FUNC(redoubt_sha256_hash)
.p2align 4
FUNC(redoubt_sha256_hash):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HASH_BLOCK1 and HASH_BLOCK2 hold the tail of the
// ║ message with the padding written after it. That is message in the clear,
// ║ and it is here rather than in the caller's buffer because a caller that
// ║ handed over a whole message has no room to pad in. HASH_H holds the
// ║ chaining state, which is every byte of the message folded together.
// ║
// ║ The slots past them hold pointers, lengths and the caller's return
// ║ address. They are here because the compression empties every caller-saved
// ║ register before it returns, so nothing that has to outlive the call can be
// ║ left in one — and a prologue that saved a callee-saved register instead
// ║ would write the caller's value to a stack this routine cannot wipe.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HASH

    // What has to survive a call to the compression.
    str     x30, [sp, #HASH_LR]
    str     x0, [sp, #HASH_MSG]
    str     x1, [sp, #HASH_LEFT]
    str     x1, [sp, #HASH_TOTAL]
    str     x2, [sp, #HASH_DIGEST]

    // Initialize H with .LH256_INIT
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

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lhash_block_loop:
    ldr     x2, [sp, #HASH_LEFT]
    cmp     x2, #64
    b.lt    .Lhash_final_block

    add     x0, sp, #HASH_H
    ldr     x1, [sp, #HASH_MSG]
    bl      FUNC(redoubt_sha256_compress_block)

    // Advance to next block
    ldr     x0, [sp, #HASH_MSG]
    add     x0, x0, #64
    str     x0, [sp, #HASH_MSG]
    ldr     x0, [sp, #HASH_LEFT]
    sub     x0, x0, #64
    str     x0, [sp, #HASH_LEFT]
    b       .Lhash_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lhash_final_block:
    ldr     x13, [sp, #HASH_LEFT]
    ldr     x12, [sp, #HASH_MSG]

    // Zero first block buffer
    add     x16, sp, #HASH_BLOCK1
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
    ldr     x14, [sp, #HASH_TOTAL]
    lsl     x0, x14, #3         // bits = bytes * 8
    rev     x0, x0              // big-endian
    str     x0, [x16, #56]

    // Compress final block
    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK1

    bl      FUNC(redoubt_sha256_compress_block)

    b       .Lhash_finish

    // === TWO BLOCK CASE ===
.Lhash_two_blocks:
    // First block: remainder + 0x80 + zeros (no length yet)
    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK1

    bl      FUNC(redoubt_sha256_compress_block)

    // Second block: all zeros except length at end
    add     x16, sp, #HASH_BLOCK2
    stp     xzr, xzr, [x16]
    stp     xzr, xzr, [x16, #16]
    stp     xzr, xzr, [x16, #32]
    stp     xzr, xzr, [x16, #48]

    // Append 64-bit big-endian length at offset 56
    ldr     x14, [sp, #HASH_TOTAL]
    lsl     x0, x14, #3
    rev     x0, x0
    str     x0, [x16, #56]

    // Compress second block
    add     x0, sp, #HASH_H
    add     x1, sp, #HASH_BLOCK2

    bl      FUNC(redoubt_sha256_compress_block)

.Lhash_finish:
    // Copy H state to digest (as big-endian bytes per SHA-256 spec)
    add     x0, sp, #HASH_H
    ld1     {v0.4s, v1.4s}, [x0]

    // Convert to big-endian for output
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b

    ldr     x15, [sp, #HASH_DIGEST]
    st1     {v0.4s, v1.4s}, [x15]

    // The caller's return address, back out of the frame before the frame goes.
    ldr     x30, [sp, #HASH_LR]

    HKDF_EMPTY_FRAME FRAME_HASH
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
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
// Local: reached from `hmac_sha256` and from nowhere outside this file. A name
// in the symbol table is a name a linked library can collide with, and the
// linker resolves that without a word to anybody.
.p2align 4
.Lsha256_update_finalize:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: UPDATE_H holds the state the caller was carrying, which
// ║ for HMAC is the inner pad already folded in — key material. UPDATE_BLOCK1
// ║ and UPDATE_BLOCK2 hold the tail of the message with its padding, which is
// ║ message in the clear.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_UPDATE

    // The caller's state, copied in. Its pointer is not kept: nothing reads it
    // again.
    ld1     {v0.4s, v1.4s}, [x0]
    add     x0, sp, #UPDATE_H
    st1     {v0.4s, v1.4s}, [x0]

    // What has to survive a call to the compression.
    str     x30, [sp, #UPDATE_LR]
    str     x1, [sp, #UPDATE_MSG]
    str     x2, [sp, #UPDATE_LEFT]
    str     x3, [sp, #UPDATE_TOTAL]
    str     x4, [sp, #UPDATE_DIGEST]

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
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

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lupdate_final_block:
    ldr     x13, [sp, #UPDATE_LEFT]
    ldr     x12, [sp, #UPDATE_MSG]

    // Zero first block buffer
    add     x16, sp, #UPDATE_BLOCK1
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
    ldr     x14, [sp, #UPDATE_TOTAL]
    lsl     x0, x14, #3         // bits = bytes * 8
    rev     x0, x0              // big-endian
    str     x0, [x16, #56]

    add     x0, sp, #UPDATE_H
    add     x1, sp, #UPDATE_BLOCK1
    bl      FUNC(redoubt_sha256_compress_block)

    b       .Lupdate_finish

    // === TWO BLOCK CASE ===
.Lupdate_two_blocks:
    add     x0, sp, #UPDATE_H
    add     x1, sp, #UPDATE_BLOCK1
    bl      FUNC(redoubt_sha256_compress_block)

    // Second block: zeros + length
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
    // Copy H state to digest (big-endian)
    add     x0, sp, #UPDATE_H
    ld1     {v0.4s, v1.4s}, [x0]
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b
    ldr     x15, [sp, #UPDATE_DIGEST]
    st1     {v0.4s, v1.4s}, [x15]

    // The caller's return address, back out of the frame before the frame goes.
    ldr     x30, [sp, #UPDATE_LR]

    HKDF_EMPTY_FRAME FRAME_UPDATE
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
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
.globl FUNC(redoubt_hmac_sha256)
.p2align 4
FUNC(redoubt_hmac_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HMAC_KPAD holds the caller's key padded to a block, and
// ║ HMAC_IPAD and HMAC_OPAD hold it exclusive-ored with the constants RFC 2104
// ║ names — each of those is the key, recoverable by undoing one xor against a
// ║ byte anybody can look up. HMAC_KHASH holds the key hashed down where it was
// ║ too long to pad, and HMAC_H the state with a pad already folded in.
// ║
// ║ HMAC_INNER holds the inner digest, which is what the outer hash is keyed
// ║ over and is not a caller's to see.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HMAC

    // What has to survive the calls below.
    str     x30, [sp, #HMAC_LR]
    str     x0, [sp, #HMAC_KEY]
    str     x1, [sp, #HMAC_KEYLEN]
    str     x2, [sp, #HMAC_MSG]
    str     x3, [sp, #HMAC_MSGLEN]
    str     x4, [sp, #HMAC_MAC]

    // ========================================================================
    // Step 1: Process key
    // ========================================================================
    // If key_len > 64, hash it first; otherwise use as-is
    cmp     x1, #64
    b.le    .Lhmac_key_short

    // key_len > 64: K = SHA256(key). The key and its length are still in the
    // registers they arrived in.
    add     x2, sp, #HMAC_KHASH
    bl      FUNC(redoubt_sha256_hash)

    // Copy hashed key to K_padded (32 bytes)
    add     x0, sp, #HMAC_KHASH
    add     x1, sp, #HMAC_KPAD
    ldp     x2, x3, [x0]
    stp     x2, x3, [x1]
    ldp     x2, x3, [x0, #16]
    stp     x2, x3, [x1, #16]

    // Zero remaining 32 bytes of K_padded
    stp     xzr, xzr, [x1, #32]
    stp     xzr, xzr, [x1, #48]

    b       .Lhmac_key_ready

.Lhmac_key_short:
    // key_len <= 64: copy key to K_padded and zero-pad
    // First zero entire K_padded buffer
    add     x1, sp, #HMAC_KPAD
    stp     xzr, xzr, [x1]
    stp     xzr, xzr, [x1, #16]
    stp     xzr, xzr, [x1, #32]
    stp     xzr, xzr, [x1, #48]

    // Copy key bytes
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
    // ========================================================================
    // Step 2: Create ipad = K_padded ⊕ 0x36 and opad = K_padded ⊕ 0x5c
    // ========================================================================
    mov     w0, #0x36               // ipad constant
    mov     w1, #0x5c               // opad constant
    add     x6, sp, #HMAC_KPAD
    add     x7, sp, #HMAC_IPAD
    add     x8, sp, #HMAC_OPAD
    mov     x16, #0
.Lhmac_xor_loop:
    cmp     x16, #64
    b.ge    .Lhmac_xor_done

    ldrb    w17, [x6, x16]          // K_padded[i]

    eor     w2, w17, w0             // ipad[i] = K_padded[i] ⊕ 0x36
    strb    w2, [x7, x16]

    eor     w2, w17, w1             // opad[i] = K_padded[i] ⊕ 0x5c
    strb    w2, [x8, x16]

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

    // Initialize H with SHA256_INIT
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

    // Compress ipad block (64 bytes)
    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_IPAD
    bl      FUNC(redoubt_sha256_compress_block)

    // Now call sha256_update_finalize with msg
    add     x0, sp, #HMAC_H
    ldr     x1, [sp, #HMAC_MSG]
    ldr     x2, [sp, #HMAC_MSGLEN]
    add     x3, x2, #64         // total_len = 64 (ipad) + msg_len
    add     x4, sp, #HMAC_INNER
    bl      .Lsha256_update_finalize

    // ========================================================================
    // Step 4: Compute outer hash = SHA256(opad || inner_hash)
    // ========================================================================
    // Same strategy: use sha256_update_finalize
    //   1. Initialize H = SHA256_INIT
    //   2. Compress opad block
    //   3. Call sha256_update_finalize(H, inner_hash, 32, mac)

    // Initialize H with SHA256_INIT
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

    // Compress opad block (64 bytes)
    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_OPAD
    bl      FUNC(redoubt_sha256_compress_block)

    // Now call sha256_update_finalize with inner_hash
    add     x0, sp, #HMAC_H
    add     x1, sp, #HMAC_INNER
    mov     x2, #32             // inner_hash length (32 bytes)
    mov     x3, #96             // total_len = 64 (opad) + 32 (inner_hash)
    ldr     x4, [sp, #HMAC_MAC]
    bl      .Lsha256_update_finalize

    // The caller's return address, back out of the frame before the frame goes.
    ldr     x30, [sp, #HMAC_LR]

    HKDF_EMPTY_FRAME FRAME_HMAC
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret


//============================================================================
// sha256_absorb
//============================================================================
// Adds a run of bytes to a message being hashed a piece at a time
//
// C signature:
//   void sha256_absorb(
//       uint32_t H[8],
//       const uint8_t *src,
//       size_t len,
//       uint8_t block[64],
//       size_t *fill
//   );
//
// Parameters:
//   x0: H_ptr (the chaining state, advanced one block at a time)
//   x1: src_ptr (the bytes to add)
//   x2: len
//   x3: block_ptr (the caller's 64-byte buffer, filled across calls)
//   x4: fill_ptr (how many bytes the buffer holds; read and written)
//
// Behavior:
//   Appends the run to the buffer, and every time the buffer fills, folds it
//   into H and empties it. The buffer is left holding fewer than 64 bytes, so
//   the caller can add another run or hand what is left to
//   sha256_update_finalize.
//
// Usage: Called by hkdf_sha256, which has a message in three pieces and no
//        place to put the whole of it
//
// The buffer and the counter are the caller's, and are not zeroized here: this
// routine is called again on the same two, and the caller is the one that knows
// when they are finished with.
//============================================================================
// Local: reached from `hkdf_sha256` and from nowhere outside this file. A name
// in the symbol table is a name a linked library can collide with, and the
// linker resolves that without a word to anybody.
.p2align 4
.Lsha256_absorb:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds no message bytes, only the arguments —
// ║ but ABSORB_SRC and ABSORB_H are pointers into the caller's secrets, and a
// ║ pointer left behind is a pointer somebody can follow.
// ║
// ║ They are here because the compression empties every caller-saved register
// ║ before it returns, so nothing that has to outlive the call can be left in
// ║ one — and a prologue that saved a callee-saved register instead would write
// ║ the caller's value to a stack this routine cannot wipe.
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

    // The buffer is full: fold it in and start it again.
    ldr     x0, [sp, #ABSORB_H]
    ldr     x1, [sp, #ABSORB_BLOCK]
    bl      FUNC(redoubt_sha256_compress_block)

    ldr     x4, [sp, #ABSORB_FILL]
    str     xzr, [x4]
    b       .Labsorb_loop

.Labsorb_done:
    // The caller's return address, back out of the frame before the frame goes.
    ldr     x30, [sp, #ABSORB_LR]

    HKDF_EMPTY_FRAME FRAME_ABSORB
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

//============================================================================
// hkdf_sha256
//============================================================================
// HKDF-SHA256 per RFC 5869: Extract-and-Expand key derivation
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
// Behavior:
//   1. Extract: PRK = HMAC-SHA256(salt, IKM)
//   2. Expand: Iteratively generate OKM blocks:
//      T(1) = HMAC(PRK, info || 0x01)
//      T(i) = HMAC(PRK, T(i-1) || info || i) for i = 2..N
//      OKM = first okm_len bytes of T(1) || T(2) || ... || T(N)
//      where N = ceil(okm_len / 32)
//
// A length the counter has no block for is refused above this file, so the
// counter is written with one byte here and never checked.
//
// Why the expansion does not call hmac_sha256:
//   The message of each iteration is T(i-1) || info || counter, and a call
//   would need it in one piece — which means a buffer sized from info_len, and
//   a routine whose prologue cannot say how much stack it takes. Instead the
//   pieces are fed to the hash where they lie, the pads are built once from a
//   key that is already a block or less, and the frame is a number.
//
// Registers: none callee-saved. What has to outlive a call is in the frame.
//
// Stack layout: FRAME_HKDF bytes, laid out by the HKDF_* constants above, and
//               zeroized in full before return.
//
// Security: PRK, the pads, the block buffer, the chaining state, the inner
//           digest and T(i) are all in the frame and go out with it
//           + HKDF_SHA256_ZEROIZE_ALL clears all caller-saved registers
//============================================================================
.globl FUNC(redoubt_hkdf_sha256)
HIDDEN_FUNC(redoubt_hkdf_sha256)
.p2align 4
FUNC(redoubt_hkdf_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HKDF_PRK holds the extracted key, which is what every
// ║ byte of output is derived from. HKDF_IPAD and HKDF_OPAD hold it exclusive-
// ║ ored with the constants RFC 2104 names — each of those is the key,
// ║ recoverable by undoing one xor against a byte anybody can look up.
// ║
// ║ HKDF_H holds a state with a pad already folded in, HKDF_INNER the inner
// ║ digest the outer hash is keyed over, and HKDF_T a block of the output
// ║ itself. HKDF_BLOCK holds the tail of the message being hashed.
// ║
// ║ Frame is written before it is read, and zeroized in full before sp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub     sp, sp, #FRAME_HKDF

    // What has to survive the calls below. The salt and the IKM are not among
    // them: they are read by the extraction and never again.
    str     x30, [sp, #HKDF_LR]
    str     x4, [sp, #HKDF_INFO]
    str     x5, [sp, #HKDF_INFOLEN]
    str     x6, [sp, #HKDF_OKM]
    str     x7, [sp, #HKDF_OKMLEN]

    // ========================================================================
    // Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
    // ========================================================================
    // x0 through x3 still hold what the caller put there.
    add     x4, sp, #HKDF_PRK
    bl      FUNC(redoubt_hmac_sha256)

    // ========================================================================
    // Step 2: the pads, built once
    // ========================================================================
    // PRK is 32 bytes, which is inside a block, so the key needs no hashing
    // down and the bytes past it are the zero padding RFC 2104 asks for.
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
    // ========================================================================
    // Step 3: Expand
    // ========================================================================
    mov     x0, #1
    str     x0, [sp, #HKDF_COUNTER]
    str     xzr, [sp, #HKDF_TLEN]

.Lhkdf_expand_loop:
    ldr     x0, [sp, #HKDF_OKMLEN]
    cbz     x0, .Lhkdf_done

    // inner = SHA256(ipad || T(i-1) || info || counter)
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

    // T(i-1), which is nothing on the first round.
    add     x0, sp, #HKDF_H
    add     x1, sp, #HKDF_T
    ldr     x2, [sp, #HKDF_TLEN]
    add     x3, sp, #HKDF_BLOCK
    add     x4, sp, #HKDF_FILL
    bl      .Lsha256_absorb

    // info, read where the caller left it.
    add     x0, sp, #HKDF_H
    ldr     x1, [sp, #HKDF_INFO]
    ldr     x2, [sp, #HKDF_INFOLEN]
    add     x3, sp, #HKDF_BLOCK
    add     x4, sp, #HKDF_FILL
    bl      .Lsha256_absorb

    // The counter closes the message, so it goes into the buffer rather than
    // through the absorb: what is left is one partial block, which is what the
    // padding wants.
    ldr     x5, [sp, #HKDF_FILL]
    ldr     x6, [sp, #HKDF_COUNTER]
    add     x7, sp, #HKDF_BLOCK
    strb    w6, [x7, x5]
    add     x5, x5, #1

    // total_len = 64 + T_len + info_len + 1
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

    // T(i) = SHA256(opad || inner)
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

    // As much of T(i) as the caller still has room for.
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
    // The caller's return address, back out of the frame before the frame goes.
    ldr     x30, [sp, #HKDF_LR]

    HKDF_EMPTY_FRAME FRAME_HKDF
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================
//
// Nothing in production calls any of it. It is here and not in a file of its
// own because a reader asking whether the measurement is right should not have
// to find a second file and check that a number in it still matches a number
// in this one: the FRAME_* constants below are the frames, and the register
// budget it asks about is the list the wipe uses, not a copy of either.
//
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own list
//   frame_is_zeroized_X      asks the stack, with routine X's own FRAME_X
//   dirty_registers          fills the budget and leaves it that way
//   dirty_frame_X            one byte of X's frame, at an offset given
//   clean_frame_X            X's frame written and emptied, with no work
//
// # Why the frame instruments are one set per routine
//
// The routines here do not share a frame, so there is no one window to read.
// The three that concern a frame are written once, as a macro over a size, and
// instantiated with each routine's own constant — which is the same constant
// that routine's `sub sp` names. A verifier and the routine it is asked about
// therefore cannot disagree about where the frame was without the file saying
// two different things in the same place.

// Builds the pattern in place, four immediates at a time, because a 64-bit
// value does not fit in one instruction and a literal pool would put it in
// memory this file would then have to account for.
.macro HKDF_PROBE_PATTERN reg, half
    movz    \reg, #\half
    movk    \reg, #\half, lsl #16
    movk    \reg, #\half, lsl #32
    movk    \reg, #\half, lsl #48
.endm

// uint64_t redoubt_hkdf_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost x0, and x0
// is one of the registers being asked about — it would arrive holding our own
// pointer rather than the caller's value. With nothing passed, `bl` is the
// whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_hkdf_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hkdf_registers_are_zeroized)
FUNC(redoubt_hkdf_registers_are_zeroized):
    // The vectors gather first, into v0, whose own value goes in on the first
    // line. `orr` over `.16b` reads and writes nothing but vector registers, so
    // every general register is still the caller's when the next line reaches
    // it.
    HKDF_EACH_VECTOR HKDF_GATHER_VECTOR

    // x1 gathers, its own value going in on its own line, and x0 is read before
    // anything here writes to it.
    HKDF_EACH_GPR HKDF_GATHER_GPR

    // The vectors fold in last, through registers whose values x1 already has.
    umov    x2, v0.d[0]
    orr     x1, x1, x2
    umov    x3, v0.d[1]
    orr     x1, x1, x3

    mov     x0, x1
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before a verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_registers)
HIDDEN_FUNC(redoubt_hkdf_dirty_registers)
FUNC(redoubt_hkdf_dirty_registers):
    HKDF_PROBE_PATTERN x0, 0xa5a5
    dup     v0.2d, x0
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    HKDF_EACH_GPR HKDF_FILL_GPR
    ret

// The three frame instruments for a routine whose frame is \size bytes.
//
// uint64_t redoubt_hkdf_frame_is_zeroized_\name(void)
//
//   Whether any byte of the frame the call before it used is still holding
//   something. Zero when it is all empty, and the bits of whatever was not.
//
//   Reads below its own sp, and that is the whole of it: `bl` writes no stack,
//   so this routine's sp is the sp the routine before it was entered with, and
//   `[sp - \size, sp)` is the frame that one took and gave back.
//
//   Asked after the registers, never before: reading a frame takes registers,
//   and the answer about those has to be taken first.
//
// void redoubt_hkdf_dirty_frame_\name(size_t at)
//
//   One byte of the frame, dirtied and left. x0 says which.
//
//   Swept over every offset, this is what establishes that the verifier reads
//   the whole frame and not the first word of it — and that the byte it reaches
//   is the byte that was written, which is where an off-by-one against whatever
//   sits next door would show.
//
// void redoubt_hkdf_clean_frame_\name(void)
//
//   The whole frame written and then emptied: what the routine does, without
//   the work in between. The positive control — without it, "the frame came
//   back zero" is only ever asserted about routines whose correctness is what
//   is in question.
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
    // Isolate this byte from every previous call's residue. Keep x0, the
    // requested offset, intact until the whole frame is empty.
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

// The two routines with no name outside this file, given one for the length of
// a measurement.
//
// A branch and not a call. `b` leaves sp and the link register exactly as they
// arrived, so the routine takes its frame where it would have taken it from its
// real caller — and the one the verifier will read. A `bl` here would overwrite
// the return address with one of its own and the routine would come back to the
// trampoline instead of to the test.
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

    .section .note.GNU-stack,"",@progbits
