// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// HKDF-SHA256 by hand, for x86_64 under the SysV ABI.
//
// # One path, and what it costs
//
// There is no runtime feature detection, no SHA extension path and no AVX path:
// what the machine has is not asked, so the same instructions run everywhere
// and what is written here is what executed. A second copy would need a check,
// another copy of the rounds, and a wipe written once per register file — and
// none of that is paid for until somebody measures that it matters.
//
// The floor is not the x86-64 baseline, which is SSE2. The rounds move words
// between a vector register and a general one with `pextrd` and `pinsrd`, which
// are SSE4.1, and the byte swap and the sliding window use `pshufb` and
// `palignr`, which are SSSE3. A processor without SSE4.1 — which means before
// 2008 — raises an illegal instruction here rather than falling back, and
// `build.rs` compiles this file for every x86_64 target that is not Windows.
//
// Whether that is the right floor is a question for whoever knows where this
// runs. It is written down because the number is decided by these mnemonics and
// by nothing else, and a reader who assumes the baseline assumes wrong.
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

.intel_syntax noprefix
.text

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name)
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// Constants
#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif
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

.p2align 4
.Lbswap_mask:
    .byte 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12

.p2align 4
.LH256_INIT:
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

.text

// ============================================================================
// The register budget
// ============================================================================
//
// SysV AMD64 ABI:
//   - Caller-saved GPR: rax, rcx, rdx, rsi, rdi, r8-r11
//   - Callee-saved GPR: rbx, rbp, r12-r15  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and every
// operation over the set goes through that one list. Emptying them and asking
// whether they are empty are the same registers by construction, not two lists
// that happen to agree today.
//
// The general list is the whole caller-saved set, including the registers this
// file does not currently write. The list is what the verifier asks about as
// well as what the wipe clears, and a verifier asked about seven says nothing
// on the day somebody reaches for a spare one. Two spare `xor` are cheaper than
// that day.
//
// The vector list stops at xmm13, which is where this file stops writing. That
// is the one place the rule above is not followed, and the reason is measured
// in calls: the compression clears its registers once per block of every
// message there is, and two `pxor` for registers nothing puts anything in are
// two instructions per block for nothing.
//
// A routine that reaches for xmm14 or xmm15 has to add them here. That is the
// cost of the exception, and it is written down so the next reader knows the
// list is short on purpose rather than by oversight.
//
// Does NOT include rsp, rbx, rbp or r12-r15. A routine that spilled into one of
// those would have to save it first, and that save is what writes the caller's
// register to the stack — a value that was never ours, that we cannot name, and
// that the caller cannot wipe because it does not know a copy was made.

.macro HKDF_EACH_GPR op
    \op rax
    \op rcx
    \op rdx
    \op rsi
    \op rdi
    \op r8
    \op r9
    \op r10
    \op r11
.endm

.macro HKDF_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13
        \op xmm\reg
    .endr
.endm

.macro HKDF_CLEAR_GPR reg
    xor \reg, \reg
.endm

.macro HKDF_CLEAR_VECTOR reg
    pxor \reg, \reg
.endm

// Copies what rax already holds into each of them, rax included and harmless.
// Only the probe at the end of this file uses it, and it is here rather than
// there so that the budget has one list and every operation over it sits beside
// that list.
.macro HKDF_FILL_GPR reg
    mov \reg, rax
.endm

// Gathers into rcx, which is in the budget and therefore contributes its own
// value on its own line. What the gather leaves in rcx is the bits of anything
// that was not empty.
.macro HKDF_GATHER_GPR reg
    or rcx, \reg
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
// Every size is congruent to 8 modulo 16. `call` leaves rsp 8 past a boundary,
// so subtracting one of these lands the frame on one — which is what the
// sixteen-byte moves below need.

// sha256_compress_block: the message schedule, and the caller's H.
.set COMPRESS_W, 0
.set COMPRESS_HPTR, 64
.set FRAME_COMPRESS, 72

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
.set FRAME_HASH, 200

// sha256_update_finalize: the same, over a state the caller already has. The
// caller's H is read once at the start and never again, so it needs no slot.
.set UPDATE_H, 0
.set UPDATE_BLOCK1, 32
.set UPDATE_BLOCK2, 96
.set UPDATE_MSG, 160
.set UPDATE_LEFT, 168
.set UPDATE_TOTAL, 176
.set UPDATE_DIGEST, 184
.set FRAME_UPDATE, 200

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
.set FRAME_HMAC, 328

// sha256_absorb: where it is in a message it is being handed in pieces.
.set ABSORB_H, 0
.set ABSORB_SRC, 8
.set ABSORB_LEFT, 16
.set ABSORB_BLOCK, 24
.set ABSORB_FILL, 32
.set FRAME_ABSORB, 40

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
.set FRAME_HKDF, 376

// Empties a frame of `size` bytes and gives it back.
//
// Takes the size rather than reading one constant, because the routines here do
// not share a frame. What keeps it honest is that every call site names the
// same constant its own `sub rsp` did.
.macro HKDF_EMPTY_FRAME size
    xor eax, eax
    .set _empty_at, 0
    .rept \size / 8
        mov qword ptr [rsp + _empty_at], rax
        .set _empty_at, _empty_at + 8
    .endr
    add rsp, \size
.endm

//============================================================================
// sha256_compress_block
//============================================================================
// Compresses a single 64-byte block into H state (SHA-256, 64 rounds)
//
// C signature: void sha256_compress_block(uint32_t H[8], const uint8_t block[64]);
//
// Parameters (SysV ABI):
//   rdi: H_ptr (input/output, 32 bytes = 8 × uint32_t)
//   rsi: block_ptr (input, 64 bytes, big-endian message)
//
// Behavior:
//   Performs SHA-256 compression: H := H + SHA256_COMPRESS(block)
//
// Register allocation:
//   None callee-saved. H_ptr is in the frame at COMPRESS_HPTR, because the
//   round needs every caller-saved register it has and the alternative is
//   writing the caller's rbx to a stack this routine cannot wipe.
//   Loop control:
//     rdx = loop counter t (0-63)
//     rcx = K_ptr (.LK256 constants)
//   Round temporaries (32-bit):
//     eax, esi, edi, r8d-r11d = T1, T2, Ch, Maj, Σ, σ computations
//   K[t] and W[t] are read once each, at the point of their add, so neither
//   takes a register.
//   SIMD registers:
//     xmm0-xmm1 = H state (load/store)
//     xmm2-xmm3 = working variables {a,b,c,d}, {e,f,g,h}
//     xmm4-xmm7 = sliding window W[t-16..t-1] (rounds 16-63)
//     xmm8-xmm13 = temps for message schedule, window rotation, bswap mask
//
// Stack layout: FRAME_COMPRESS bytes, zeroized in full before return.
//============================================================================
.global FUNC(redoubt_sha256_compress_block)
HIDDEN_FUNC(redoubt_sha256_compress_block)
#if !defined(__APPLE__)
.type FUNC(redoubt_sha256_compress_block), @function
#endif
.p2align 4
FUNC(redoubt_sha256_compress_block):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: COMPRESS_W holds the message schedule — the caller's
// ║ block, byte-swapped, and then sixty-four words derived from it. For a
// ║ message that is key material this is that material in the clear, and it is
// ║ here rather than in the caller's buffer because the schedule is this
// ║ routine's own working space.
// ║
// ║ COMPRESS_HPTR holds the caller's pointer, which is the caller's own and no
// ║ secret. It is in the frame because the round needs every register there is,
// ║ and the alternative is a prologue that saves a callee-saved register — and
// ║ that save writes a value of the caller's to the stack that nothing here can
// ║ wipe.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_COMPRESS

    mov [rsp + COMPRESS_HPTR], rdi

    // Load H[0..7] from memory
    movdqu xmm0, [rdi]          // xmm0 = H[0..3]
    movdqu xmm1, [rdi + 16]     // xmm1 = H[4..7]

    // Load 64-byte message block and byte-swap from big-endian
    movdqu xmm4, [rsi]
    movdqu xmm5, [rsi + 16]
    movdqu xmm6, [rsi + 32]
    movdqu xmm7, [rsi + 48]

    // Byte swap using pshufb
#if defined(__APPLE__)
    lea rax, [rip + .Lbswap_mask]
#else
    lea rax, .Lbswap_mask[rip]
#endif
    movdqa xmm9, [rax]
    pshufb xmm4, xmm9
    pshufb xmm5, xmm9
    pshufb xmm6, xmm9
    pshufb xmm7, xmm9

    // Store W[0..15] on stack (for rounds 0-15)
    movdqa [rsp + COMPRESS_W], xmm4
    movdqa [rsp + COMPRESS_W + 16], xmm5
    movdqa [rsp + COMPRESS_W + 32], xmm6
    movdqa [rsp + COMPRESS_W + 48], xmm7

    // Initialize working variables
    movdqa xmm2, xmm0           // xmm2 = {a,b,c,d}
    movdqa xmm3, xmm1           // xmm3 = {e,f,g,h}

    // Load .LK256 pointer
#if defined(__APPLE__)
    lea rcx, [rip + .LK256]
#else
    lea rcx, .LK256[rip]
#endif

    // ========================================================================
    // Rounds 0-15: W[t] from stack
    // ========================================================================
    xor rdx, rdx                // t = 0

.Lround_0_15:
    // W[t] and K[t] stay in memory and arrive as operands where they are added.
    // Holding them would cost two registers the round has no room for, and each
    // is read exactly once.

    // Extract working variables from xmm3 {e,f,g,h}
    pextrd esi, xmm3, 3         // T1 = h
    pextrd eax, xmm3, 0         // e
    pextrd r11d, xmm3, 1        // f
    pextrd edi, xmm3, 2         // g

    // Σ₁(e) = ROTR(6) ^ ROTR(11) ^ ROTR(25)
    mov r10d, eax
    ror r10d, 6
    mov r9d, eax
    ror r9d, 11
    xor r10d, r9d
    mov r9d, eax
    ror r9d, 25
    xor r10d, r9d
    add esi, r10d               // T1 += Σ₁(e)

    // Ch(e,f,g) = (e & f) ^ (~e & g)
    mov r10d, eax
    not r10d
    and r10d, edi               // ~e & g
    mov r9d, eax
    and r9d, r11d               // e & f
    xor r10d, r9d
    add esi, r10d               // T1 += Ch(e,f,g)

    add esi, [rcx + rdx*4]              // T1 += K[t]
    add esi, [rsp + COMPRESS_W + rdx*4] // T1 += W[t]

    // Extract working variables from xmm2 {a,b,c,d}
    pextrd eax, xmm2, 0         // a
    pextrd r10d, xmm2, 1        // b
    pextrd r11d, xmm2, 2        // c

    // T2 = Σ₀(a) + Maj(a,b,c)
    // Σ₀(a) = ROTR(2) ^ ROTR(13) ^ ROTR(22)
    mov r8d, eax
    ror r8d, 2
    mov r9d, eax
    ror r9d, 13
    xor r8d, r9d
    mov r9d, eax
    ror r9d, 22
    xor r8d, r9d                // r8d = Σ₀(a)

    // Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c). `edi` held g, which is dead.
    mov edi, eax
    and edi, r10d               // a & b
    mov r9d, eax
    and r9d, r11d               // a & c
    xor edi, r9d
    mov r9d, r10d
    and r9d, r11d               // b & c
    xor edi, r9d                // edi = Maj

    add r8d, edi                // r8d = T2

    // Update working variables
    pextrd r10d, xmm2, 3        // d
    add r10d, esi               // e_new = d + T1
    add esi, r8d                // a_new = T1 + T2

    // Update xmm3 {e,f,g,h}: rotate right
    pextrd r8d, xmm3, 0         // e -> f
    pextrd r9d, xmm3, 1         // f -> g
    pextrd r11d, xmm3, 2        // g -> h

    pinsrd xmm3, r10d, 0        // e = e_new
    pinsrd xmm3, r8d, 1         // f = e_old
    pinsrd xmm3, r9d, 2         // g = f_old
    pinsrd xmm3, r11d, 3        // h = g_old

    // Update xmm2 {a,b,c,d}: rotate right
    pextrd r8d, xmm2, 0         // a -> b
    pextrd r9d, xmm2, 1         // b -> c
    pextrd r11d, xmm2, 2        // c -> d

    pinsrd xmm2, esi, 0         // a = a_new
    pinsrd xmm2, r8d, 1         // b = a_old
    pinsrd xmm2, r9d, 2         // c = b_old
    pinsrd xmm2, r11d, 3        // d = c_old

    inc rdx
    cmp rdx, 16
    jl .Lround_0_15

    // ========================================================================
    // Rounds 16-63: Compute W[t] from message schedule
    // ========================================================================
    // Sliding window: xmm4={W[t-16..t-13]}, xmm5={W[t-12..t-9]},
    //                 xmm6={W[t-8..t-5]}, xmm7={W[t-4..t-1]}

.Lround_16_63:
    // W[t] = W[t-16] + σ₀(W[t-15]) + W[t-7] + σ₁(W[t-2])
    // xmm4[0] = W[t-16], xmm4[1] = W[t-15]
    // xmm6[1] = W[t-7]
    // xmm7[2] = W[t-2]

    pextrd eax, xmm4, 0         // W[t-16]
    pextrd r8d, xmm4, 1         // W[t-15]
    pextrd r9d, xmm6, 1         // W[t-7]
    pextrd r10d, xmm7, 2        // W[t-2]

    // σ₀(W[t-15]) = ROTR(7) ^ ROTR(18) ^ SHR(3)
    mov r11d, r8d
    ror r11d, 7
    mov esi, r8d
    ror esi, 18
    xor r11d, esi
    mov esi, r8d
    shr esi, 3
    xor r11d, esi               // r11d = σ₀(W[t-15])

    // σ₁(W[t-2]) = ROTR(17) ^ ROTR(19) ^ SHR(10)
    mov r8d, r10d
    ror r8d, 17
    mov esi, r10d
    ror esi, 19
    xor r8d, esi
    mov esi, r10d
    shr esi, 10
    xor r8d, esi                // r8d = σ₁(W[t-2])

    // W[t] = W[t-16] + σ₀ + W[t-7] + σ₁
    add eax, r11d
    add eax, r9d
    add eax, r8d                // eax = W[t]

    // W[t] goes to the frame and to xmm8 here rather than staying in a
    // register: the round below needs every one there is, and it is read from
    // the frame where it is added and from xmm8 where the window rotates.
    mov [rsp + COMPRESS_W], eax
    movd xmm8, eax

    // === Compute round (same as rounds 0-15) ===
    pextrd esi, xmm3, 3         // T1 = h
    pextrd eax, xmm3, 0         // e
    pextrd r11d, xmm3, 1        // f
    pextrd edi, xmm3, 2         // g

    // Σ₁(e)
    mov r10d, eax
    ror r10d, 6
    mov r9d, eax
    ror r9d, 11
    xor r10d, r9d
    mov r9d, eax
    ror r9d, 25
    xor r10d, r9d
    add esi, r10d

    // Ch(e,f,g)
    mov r10d, eax
    not r10d
    and r10d, edi
    mov r9d, eax
    and r9d, r11d
    xor r10d, r9d
    add esi, r10d

    add esi, [rcx + rdx*4]      // + K[t]
    add esi, [rsp + COMPRESS_W] // + W[t]

    // T2
    pextrd eax, xmm2, 0         // a
    pextrd r10d, xmm2, 1        // b
    pextrd r11d, xmm2, 2        // c

    mov r8d, eax
    ror r8d, 2
    mov r9d, eax
    ror r9d, 13
    xor r8d, r9d
    mov r9d, eax
    ror r9d, 22
    xor r8d, r9d                // Σ₀(a)

    mov edi, eax
    and edi, r10d
    mov r9d, eax
    and r9d, r11d
    xor edi, r9d
    mov r9d, r10d
    and r9d, r11d
    xor edi, r9d                // Maj

    add r8d, edi                // T2

    pextrd r10d, xmm2, 3        // d
    add r10d, esi               // e_new
    add esi, r8d                // a_new

    // Update xmm3
    pextrd r8d, xmm3, 0
    pextrd r9d, xmm3, 1
    pextrd r11d, xmm3, 2

    pinsrd xmm3, r10d, 0
    pinsrd xmm3, r8d, 1
    pinsrd xmm3, r9d, 2
    pinsrd xmm3, r11d, 3

    // Update xmm2
    pextrd r8d, xmm2, 0
    pextrd r9d, xmm2, 1
    pextrd r11d, xmm2, 2

    pinsrd xmm2, esi, 0
    pinsrd xmm2, r8d, 1
    pinsrd xmm2, r9d, 2
    pinsrd xmm2, r11d, 3

    // Update sliding window: shift left by 1 word
    // PALIGNR dst, src, imm8: TEMP = (dst << 128) | src; dst = TEMP >> (imm8*8)
    // To get [W1,W2,W3,W4] we need TEMP = [xmm5 | xmm4] >> 32
    // So we do: dst=xmm5_copy, src=xmm4, palignr dst, src, 4
    // xmm8 already holds [W[t], 0, 0, 0]: it was filled where W[t] was
    // computed, because the round in between needs the register it was in.

    // Work backwards to preserve source values
    // xmm7_new = [W13,W14,W15,W[t]] from xmm8=[W[t],0,0,0] and xmm7=[W12..W15]
    movdqa xmm10, xmm8
    palignr xmm10, xmm7, 4      // xmm10 = [W13,W14,W15,W[t]]

    // xmm6_new = [W9,W10,W11,W12] from xmm7=[W12..W15] and xmm6=[W8..W11]
    movdqa xmm11, xmm7
    palignr xmm11, xmm6, 4      // xmm11 = [W9,W10,W11,W12]

    // xmm5_new = [W5,W6,W7,W8] from xmm6=[W8..W11] and xmm5=[W4..W7]
    movdqa xmm12, xmm6
    palignr xmm12, xmm5, 4      // xmm12 = [W5,W6,W7,W8]

    // xmm4_new = [W1,W2,W3,W4] from xmm5=[W4..W7] and xmm4=[W0..W3]
    movdqa xmm13, xmm5
    palignr xmm13, xmm4, 4      // xmm13 = [W1,W2,W3,W4]

    // Copy results back
    movdqa xmm4, xmm13
    movdqa xmm5, xmm12
    movdqa xmm6, xmm11
    movdqa xmm7, xmm10

    inc rdx
    cmp rdx, 64
    jl .Lround_16_63

    // ========================================================================
    // FINALIZE: H := H + {a,b,c,d,e,f,g,h}
    // ========================================================================
    // The caller's pointer comes back out of the frame: the round used the
    // register it arrived in.
    mov rdi, [rsp + COMPRESS_HPTR]

    movdqu xmm0, [rdi]
    paddd xmm0, xmm2
    movdqu [rdi], xmm0

    movdqu xmm1, [rdi + 16]
    paddd xmm1, xmm3
    movdqu [rdi + 16], xmm1

    HKDF_EMPTY_FRAME FRAME_COMPRESS
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_sha256_compress_block), .-FUNC(redoubt_sha256_compress_block)
#endif

//============================================================================
// sha256_hash
//============================================================================
// Computes SHA-256 hash of arbitrary-length message with SHA-256 padding (FIPS 180-4)
//
// C signature:
//   void sha256_hash(const uint8_t *msg, size_t msg_len, uint8_t digest[32]);
//
// Parameters (SysV ABI):
//   rdi: msg_ptr (input)
//   rsi: msg_len (input)
//   rdx: digest_ptr (output, 32 bytes, big-endian format per SHA-256 spec)
//
// Behavior:
//   1. Initialize H with SHA-256 IV (.LH256_INIT)
//   2. Process complete 64-byte blocks via sha256_compress_block
//   3. Apply SHA-256 padding to final block(s): 0x80 + zeros + 64-bit length
//   4. Output big-endian digest
//
// Registers: none callee-saved. What has to outlive a call to the compression
//            is in the frame, at HASH_MSG, HASH_LEFT, HASH_TOTAL and
//            HASH_DIGEST.
//
// Stack layout: FRAME_HASH bytes, laid out by the HASH_* constants above, and
//               zeroized in full before return.
//============================================================================
.global FUNC(redoubt_sha256_hash)
HIDDEN_FUNC(redoubt_sha256_hash)
#if !defined(__APPLE__)
.type FUNC(redoubt_sha256_hash), @function
#endif
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
// ║ The slots past them hold pointers and lengths. They are here because
// ║ the compression empties every caller-saved register before it returns, so
// ║ nothing that has to outlive the call can be left in one — and a prologue
// ║ that saved a callee-saved register instead would write the caller's value
// ║ to a stack this routine cannot wipe.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HASH

    // What has to survive a call to the compression.
    mov [rsp + HASH_MSG], rdi
    mov [rsp + HASH_LEFT], rsi
    mov [rsp + HASH_TOTAL], rsi
    mov [rsp + HASH_DIGEST], rdx

    // Initialize H with .LH256_INIT
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HASH_H], xmm0
    movdqa [rsp + HASH_H + 16], xmm1

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lhash_block_loop:
    cmp qword ptr [rsp + HASH_LEFT], 64
    jl .Lhash_final_block

    // Call sha256_compress_block(H_ptr, block_ptr)
    lea rdi, [rsp + HASH_H]
    mov rsi, [rsp + HASH_MSG]
    call FUNC(redoubt_sha256_compress_block)

    // Advance to next block
    add qword ptr [rsp + HASH_MSG], 64
    sub qword ptr [rsp + HASH_LEFT], 64
    jmp .Lhash_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lhash_final_block:
    // Zero first block buffer
    pxor xmm0, xmm0
    movdqa [rsp + HASH_BLOCK1], xmm0
    movdqa [rsp + HASH_BLOCK1 + 16], xmm0
    movdqa [rsp + HASH_BLOCK1 + 32], xmm0
    movdqa [rsp + HASH_BLOCK1 + 48], xmm0

    // Copy remainder bytes to block buffer
    mov r8, [rsp + HASH_MSG]
    mov r9, [rsp + HASH_LEFT]
    xor rcx, rcx            // counter = 0
.Lhash_copy_remainder:
    cmp rcx, r9
    jge .Lhash_remainder_done
    movzx eax, byte ptr [r8 + rcx]
    mov byte ptr [rsp + HASH_BLOCK1 + rcx], al
    inc rcx
    jmp .Lhash_copy_remainder

.Lhash_remainder_done:
    // Append 0x80 byte
    mov byte ptr [rsp + HASH_BLOCK1 + r9], 0x80

    // Check if length fits in this block (remainder < 56)
    cmp r9, 56
    jge .Lhash_two_blocks

    // === ONE BLOCK CASE ===
    // Append 64-bit big-endian length at offset 56
    mov rax, [rsp + HASH_TOTAL]
    shl rax, 3              // bits = bytes * 8
    bswap rax               // big-endian
    mov [rsp + HASH_BLOCK1 + 56], rax

    // Compress final block
    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    jmp .Lhash_finish

    // === TWO BLOCK CASE ===
.Lhash_two_blocks:
    // First block: remainder + 0x80 + zeros (no length yet)
    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    // Second block: all zeros except length at end
    pxor xmm0, xmm0
    movdqa [rsp + HASH_BLOCK2], xmm0
    movdqa [rsp + HASH_BLOCK2 + 16], xmm0
    movdqa [rsp + HASH_BLOCK2 + 32], xmm0
    movdqa [rsp + HASH_BLOCK2 + 48], xmm0

    // Append 64-bit big-endian length at offset 56
    mov rax, [rsp + HASH_TOTAL]
    shl rax, 3
    bswap rax
    mov [rsp + HASH_BLOCK2 + 56], rax

    // Compress second block
    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK2]
    call FUNC(redoubt_sha256_compress_block)

.Lhash_finish:
    // Copy H state to digest (as big-endian bytes per SHA-256 spec)
    movdqa xmm0, [rsp + HASH_H]
    movdqa xmm1, [rsp + HASH_H + 16]

    // Convert to big-endian for output (byte-swap each dword)
#if defined(__APPLE__)
    lea rax, [rip + .Lbswap_mask]
#else
    lea rax, .Lbswap_mask[rip]
#endif
    movdqa xmm2, [rax]
    pshufb xmm0, xmm2
    pshufb xmm1, xmm2

    mov rdi, [rsp + HASH_DIGEST]
    movdqu [rdi], xmm0
    movdqu [rdi + 16], xmm1

    HKDF_EMPTY_FRAME FRAME_HASH
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_sha256_hash), .-FUNC(redoubt_sha256_hash)
#endif

//============================================================================
// sha256_update_finalize
//============================================================================
// Continue SHA-256 from existing H state, process message, apply padding
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
// Parameters (SysV ABI):
//   rdi: H_ptr (input, existing H state from previous blocks)
//   rsi: msg_ptr (remaining message bytes)
//   rdx: msg_len (length of remaining message)
//   rcx: total_len (total bytes processed including previous blocks, for padding)
//   r8:  digest_ptr (output, 32 bytes, big-endian)
//
// Behavior:
//   1. Load existing H state from H_ptr
//   2. Process complete 64-byte blocks from msg
//   3. Apply SHA-256 padding to final block(s) using total_len
//   4. Output big-endian digest
//
// Usage: Called by hmac_sha256 after processing ipad/opad
//
// Registers: none callee-saved. What has to outlive a call to the compression
//            is in the frame, at UPDATE_MSG, UPDATE_LEFT, UPDATE_TOTAL and
//            UPDATE_DIGEST. The caller's H_ptr is not among them: the state is
//            copied in at the start and the pointer is never read again.
//
// Stack layout: FRAME_UPDATE bytes, laid out by the UPDATE_* constants above,
//               and zeroized in full before return.
//============================================================================
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
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_UPDATE

    // The caller's state, copied in. Its pointer is not kept: nothing reads it
    // again.
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqa [rsp + UPDATE_H], xmm0
    movdqa [rsp + UPDATE_H + 16], xmm1

    // What has to survive a call to the compression.
    mov [rsp + UPDATE_MSG], rsi
    mov [rsp + UPDATE_LEFT], rdx
    mov [rsp + UPDATE_TOTAL], rcx
    mov [rsp + UPDATE_DIGEST], r8

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lupdate_block_loop:
    cmp qword ptr [rsp + UPDATE_LEFT], 64
    jl .Lupdate_final_block

    lea rdi, [rsp + UPDATE_H]
    mov rsi, [rsp + UPDATE_MSG]
    call FUNC(redoubt_sha256_compress_block)

    add qword ptr [rsp + UPDATE_MSG], 64
    sub qword ptr [rsp + UPDATE_LEFT], 64
    jmp .Lupdate_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lupdate_final_block:
    // Zero first block buffer
    pxor xmm0, xmm0
    movdqa [rsp + UPDATE_BLOCK1], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 16], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 32], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 48], xmm0

    // Copy remainder bytes
    mov r8, [rsp + UPDATE_MSG]
    mov r9, [rsp + UPDATE_LEFT]
    xor rcx, rcx
.Lupdate_copy_remainder:
    cmp rcx, r9
    jge .Lupdate_remainder_done
    movzx eax, byte ptr [r8 + rcx]
    mov byte ptr [rsp + UPDATE_BLOCK1 + rcx], al
    inc rcx
    jmp .Lupdate_copy_remainder

.Lupdate_remainder_done:
    // Append 0x80
    mov byte ptr [rsp + UPDATE_BLOCK1 + r9], 0x80

    // Check if fits in one block
    cmp r9, 56
    jge .Lupdate_two_blocks

    // ONE BLOCK
    mov rax, [rsp + UPDATE_TOTAL]
    shl rax, 3
    bswap rax
    mov [rsp + UPDATE_BLOCK1 + 56], rax

    lea rdi, [rsp + UPDATE_H]
    lea rsi, [rsp + UPDATE_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    jmp .Lupdate_finish

.Lupdate_two_blocks:
    lea rdi, [rsp + UPDATE_H]
    lea rsi, [rsp + UPDATE_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    // Second block
    pxor xmm0, xmm0
    movdqa [rsp + UPDATE_BLOCK2], xmm0
    movdqa [rsp + UPDATE_BLOCK2 + 16], xmm0
    movdqa [rsp + UPDATE_BLOCK2 + 32], xmm0
    movdqa [rsp + UPDATE_BLOCK2 + 48], xmm0

    mov rax, [rsp + UPDATE_TOTAL]
    shl rax, 3
    bswap rax
    mov [rsp + UPDATE_BLOCK2 + 56], rax

    lea rdi, [rsp + UPDATE_H]
    lea rsi, [rsp + UPDATE_BLOCK2]
    call FUNC(redoubt_sha256_compress_block)

.Lupdate_finish:
    // Copy H to digest (big-endian)
    movdqa xmm0, [rsp + UPDATE_H]
    movdqa xmm1, [rsp + UPDATE_H + 16]

#if defined(__APPLE__)
    lea rax, [rip + .Lbswap_mask]
#else
    lea rax, .Lbswap_mask[rip]
#endif
    movdqa xmm2, [rax]
    pshufb xmm0, xmm2
    pshufb xmm1, xmm2

    mov rdi, [rsp + UPDATE_DIGEST]
    movdqu [rdi], xmm0
    movdqu [rdi + 16], xmm1

    HKDF_EMPTY_FRAME FRAME_UPDATE
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size .Lsha256_update_finalize, .-.Lsha256_update_finalize
#endif

//============================================================================
// hmac_sha256
//============================================================================
// HMAC-SHA256 per RFC 2104: HMAC(K, M) = H(K ⊕ opad || H(K ⊕ ipad || M))
//
// C signature:
//   void hmac_sha256(
//       const uint8_t *key, size_t key_len,
//       const uint8_t *msg, size_t msg_len,
//       uint8_t mac[32]
//   );
//
// Parameters (SysV ABI):
//   rdi: key_ptr
//   rsi: key_len
//   rdx: msg_ptr
//   rcx: msg_len
//   r8:  mac_ptr (output, 32 bytes)
//
// Behavior:
//   1. If key_len > 64: K = SHA256(key), else K = key || zeros
//   2. ipad = K ⊕ 0x36, opad = K ⊕ 0x5c
//   3. inner_hash = SHA256(ipad || msg)
//   4. mac = SHA256(opad || inner_hash)
//
// Registers: none callee-saved. What has to outlive a call is in the frame, at
//            HMAC_KEY, HMAC_KEYLEN, HMAC_MSG, HMAC_MSGLEN and HMAC_MAC.
//
// Stack layout: FRAME_HMAC bytes, laid out by the HMAC_* constants above, and
//               zeroized in full before return.
//
// Security: the padded key, the pads, the hashed key and the inner digest are
//           all in the frame and go out with it
//           + HKDF_SHA256_ZEROIZE_ALL clears all caller-saved registers
//============================================================================
.global FUNC(redoubt_hmac_sha256)
HIDDEN_FUNC(redoubt_hmac_sha256)
#if !defined(__APPLE__)
.type FUNC(redoubt_hmac_sha256), @function
#endif
.p2align 4
FUNC(redoubt_hmac_sha256):
// ║ ⚠️  SPILL REGION BEGIN ══════════════════════════════════════════════════════════════════
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
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HMAC

    // What has to survive the calls below.
    mov [rsp + HMAC_KEY], rdi
    mov [rsp + HMAC_KEYLEN], rsi
    mov [rsp + HMAC_MSG], rdx
    mov [rsp + HMAC_MSGLEN], rcx
    mov [rsp + HMAC_MAC], r8

    // ========================================================================
    // Step 1: Process key
    // ========================================================================
    cmp qword ptr [rsp + HMAC_KEYLEN], 64
    jle .Lhmac_key_short

    // key_len > 64: K = SHA256(key)
    mov rdi, [rsp + HMAC_KEY]
    mov rsi, [rsp + HMAC_KEYLEN]
    lea rdx, [rsp + HMAC_KHASH]
    call FUNC(redoubt_sha256_hash)

    // Copy hashed key to K_padded (32 bytes)
    movdqa xmm0, [rsp + HMAC_KHASH]
    movdqa xmm1, [rsp + HMAC_KHASH + 16]
    movdqa [rsp + HMAC_KPAD], xmm0
    movdqa [rsp + HMAC_KPAD + 16], xmm1

    // Zero remaining 32 bytes
    pxor xmm0, xmm0
    movdqa [rsp + HMAC_KPAD + 32], xmm0
    movdqa [rsp + HMAC_KPAD + 48], xmm0

    jmp .Lhmac_key_ready

.Lhmac_key_short:
    // key_len <= 64: copy key and zero-pad
    pxor xmm0, xmm0
    movdqa [rsp + HMAC_KPAD], xmm0
    movdqa [rsp + HMAC_KPAD + 16], xmm0
    movdqa [rsp + HMAC_KPAD + 32], xmm0
    movdqa [rsp + HMAC_KPAD + 48], xmm0

    // Copy key bytes
    mov r8, [rsp + HMAC_KEY]
    mov r9, [rsp + HMAC_KEYLEN]
    xor rcx, rcx
.Lhmac_copy_key:
    cmp rcx, r9
    jge .Lhmac_key_ready
    movzx eax, byte ptr [r8 + rcx]
    mov byte ptr [rsp + HMAC_KPAD + rcx], al
    inc rcx
    jmp .Lhmac_copy_key

.Lhmac_key_ready:
    // ========================================================================
    // Step 2: Create ipad and opad
    // ========================================================================
    xor rcx, rcx
.Lhmac_xor_loop:
    cmp rcx, 64
    jge .Lhmac_xor_done

    movzx eax, byte ptr [rsp + HMAC_KPAD + rcx]

    mov edx, eax
    xor edx, 0x36
    mov byte ptr [rsp + HMAC_IPAD + rcx], dl

    xor eax, 0x5c
    mov byte ptr [rsp + HMAC_OPAD + rcx], al

    inc rcx
    jmp .Lhmac_xor_loop

.Lhmac_xor_done:
    // ========================================================================
    // Step 3: inner_hash = SHA256(ipad || msg)
    // ========================================================================
    // Initialize H at [rsp + 256]
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HMAC_H], xmm0
    movdqa [rsp + HMAC_H + 16], xmm1

    // Compress ipad
    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_IPAD]
    call FUNC(redoubt_sha256_compress_block)

    // sha256_update_finalize(H, msg, msg_len, 64+msg_len, inner_hash)
    lea rdi, [rsp + HMAC_H]
    mov rsi, [rsp + HMAC_MSG]
    mov rdx, [rsp + HMAC_MSGLEN]
    mov rcx, rdx
    add rcx, 64             // total_len = 64 + msg_len
    lea r8, [rsp + HMAC_INNER]
    call .Lsha256_update_finalize

    // ========================================================================
    // Step 4: mac = SHA256(opad || inner_hash)
    // ========================================================================
    // Re-initialize H
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HMAC_H], xmm0
    movdqa [rsp + HMAC_H + 16], xmm1

    // Compress opad
    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_OPAD]
    call FUNC(redoubt_sha256_compress_block)

    // sha256_update_finalize(H, inner_hash, 32, 96, mac)
    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_INNER]
    mov rdx, 32             // inner_hash len
    mov rcx, 96             // total_len = 64 + 32
    mov r8, [rsp + HMAC_MAC]
    call .Lsha256_update_finalize

    HKDF_EMPTY_FRAME FRAME_HMAC
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_hmac_sha256), .-FUNC(redoubt_hmac_sha256)
#endif

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
// Parameters (SysV ABI):
//   rdi: H_ptr (the chaining state, advanced one block at a time)
//   rsi: src_ptr (the bytes to add)
//   rdx: len
//   rcx: block_ptr (the caller's 64-byte buffer, filled across calls)
//   r8:  fill_ptr (how many bytes the buffer holds; read and written)
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
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_ABSORB

    mov [rsp + ABSORB_H], rdi
    mov [rsp + ABSORB_SRC], rsi
    mov [rsp + ABSORB_LEFT], rdx
    mov [rsp + ABSORB_BLOCK], rcx
    mov [rsp + ABSORB_FILL], r8

.Labsorb_loop:
    mov rdx, [rsp + ABSORB_LEFT]
    test rdx, rdx
    jz .Labsorb_done

    mov r8, [rsp + ABSORB_FILL]
    mov r9, [r8]
    mov rcx, [rsp + ABSORB_BLOCK]
    mov rsi, [rsp + ABSORB_SRC]

    movzx eax, byte ptr [rsi]
    mov byte ptr [rcx + r9], al

    inc rsi
    dec rdx
    inc r9
    mov [rsp + ABSORB_SRC], rsi
    mov [rsp + ABSORB_LEFT], rdx
    mov [r8], r9

    cmp r9, 64
    jb .Labsorb_loop

    // The buffer is full: fold it in and start it again.
    mov rdi, [rsp + ABSORB_H]
    mov rsi, [rsp + ABSORB_BLOCK]
    call FUNC(redoubt_sha256_compress_block)

    mov r8, [rsp + ABSORB_FILL]
    mov qword ptr [r8], 0
    jmp .Labsorb_loop

.Labsorb_done:
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
// Parameters (SysV ABI - 8 args, last 2 on stack):
//   rdi: salt_ptr (for HMAC key in Extract phase)
//   rsi: salt_len
//   rdx: ikm_ptr (Input Key Material)
//   rcx: ikm_len
//   r8:  info_ptr (application-specific context)
//   r9:  info_len
//   [rsp + FRAME_HKDF + 8]:  okm_ptr (Output Key Material)
//   [rsp + FRAME_HKDF + 16]: okm_len
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
.global FUNC(redoubt_hkdf_sha256)
HIDDEN_FUNC(redoubt_hkdf_sha256)
#if !defined(__APPLE__)
.type FUNC(redoubt_hkdf_sha256), @function
#endif
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
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HKDF

    // What has to survive the calls below. The salt and the IKM are not among
    // them: they are read by the extraction and never again.
    mov [rsp + HKDF_INFO], r8
    mov [rsp + HKDF_INFOLEN], r9
    mov rax, [rsp + FRAME_HKDF + 8]
    mov [rsp + HKDF_OKM], rax
    mov rax, [rsp + FRAME_HKDF + 16]
    mov [rsp + HKDF_OKMLEN], rax

    // ========================================================================
    // Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
    // ========================================================================
    // rdi, rsi, rdx and rcx still hold what the caller put there.
    lea r8, [rsp + HKDF_PRK]
    call FUNC(redoubt_hmac_sha256)

    // ========================================================================
    // Step 2: the pads, built once
    // ========================================================================
    // PRK is 32 bytes, which is inside a block, so the key needs no hashing
    // down and the bytes past it are the zero padding RFC 2104 asks for.
    xor rcx, rcx
.Lhkdf_pad_loop:
    cmp rcx, 64
    jge .Lhkdf_pad_done

    xor eax, eax
    cmp rcx, 32
    jge .Lhkdf_pad_byte
    movzx eax, byte ptr [rsp + HKDF_PRK + rcx]

.Lhkdf_pad_byte:
    mov edx, eax
    xor edx, 0x36
    mov byte ptr [rsp + HKDF_IPAD + rcx], dl

    xor eax, 0x5c
    mov byte ptr [rsp + HKDF_OPAD + rcx], al

    inc rcx
    jmp .Lhkdf_pad_loop

.Lhkdf_pad_done:
    // ========================================================================
    // Step 3: Expand
    // ========================================================================
    mov qword ptr [rsp + HKDF_COUNTER], 1
    mov qword ptr [rsp + HKDF_TLEN], 0

.Lhkdf_expand_loop:
    cmp qword ptr [rsp + HKDF_OKMLEN], 0
    je .Lhkdf_done

    // inner = SHA256(ipad || T(i-1) || info || counter)
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HKDF_H], xmm0
    movdqa [rsp + HKDF_H + 16], xmm1

    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_IPAD]
    call FUNC(redoubt_sha256_compress_block)

    mov qword ptr [rsp + HKDF_FILL], 0

    // T(i-1), which is nothing on the first round.
    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_T]
    mov rdx, [rsp + HKDF_TLEN]
    lea rcx, [rsp + HKDF_BLOCK]
    lea r8, [rsp + HKDF_FILL]
    call .Lsha256_absorb

    // info, read where the caller left it.
    lea rdi, [rsp + HKDF_H]
    mov rsi, [rsp + HKDF_INFO]
    mov rdx, [rsp + HKDF_INFOLEN]
    lea rcx, [rsp + HKDF_BLOCK]
    lea r8, [rsp + HKDF_FILL]
    call .Lsha256_absorb

    // The counter closes the message, so it goes into the buffer rather than
    // through the absorb: what is left is one partial block, which is what the
    // padding wants.
    mov rax, [rsp + HKDF_FILL]
    mov rcx, [rsp + HKDF_COUNTER]
    mov byte ptr [rsp + HKDF_BLOCK + rax], cl
    inc rax

    mov r9, 64
    add r9, [rsp + HKDF_TLEN]
    add r9, [rsp + HKDF_INFOLEN]
    inc r9

    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_BLOCK]
    mov rdx, rax
    mov rcx, r9
    lea r8, [rsp + HKDF_INNER]
    call .Lsha256_update_finalize

    // T(i) = SHA256(opad || inner)
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HKDF_H], xmm0
    movdqa [rsp + HKDF_H + 16], xmm1

    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_OPAD]
    call FUNC(redoubt_sha256_compress_block)

    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_INNER]
    mov rdx, 32
    mov rcx, 96
    lea r8, [rsp + HKDF_T]
    call .Lsha256_update_finalize

    // As much of T(i) as the caller still has room for.
    mov rax, 32
    cmp qword ptr [rsp + HKDF_OKMLEN], 32
    jae .Lhkdf_emit
    mov rax, [rsp + HKDF_OKMLEN]

.Lhkdf_emit:
    mov r10, [rsp + HKDF_OKM]
    xor rcx, rcx
.Lhkdf_emit_loop:
    cmp rcx, rax
    jae .Lhkdf_emitted
    movzx edx, byte ptr [rsp + HKDF_T + rcx]
    mov byte ptr [r10 + rcx], dl
    inc rcx
    jmp .Lhkdf_emit_loop

.Lhkdf_emitted:
    add [rsp + HKDF_OKM], rax
    sub [rsp + HKDF_OKMLEN], rax

    inc qword ptr [rsp + HKDF_COUNTER]
    mov qword ptr [rsp + HKDF_TLEN], 32
    jmp .Lhkdf_expand_loop

.Lhkdf_done:
    HKDF_EMPTY_FRAME FRAME_HKDF
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_hkdf_sha256), .-FUNC(redoubt_hkdf_sha256)
#endif


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
// What it costs is a few hundred bytes of instructions that ship unused. What
// it buys is that the only sizes in the measurement, and the only list of
// registers, are the ones at the top of this file.
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
// that routine's `sub rsp` names. A verifier and the routine it is asked about
// therefore cannot disagree about where the frame was without the file saying
// two different things in the same place.

.macro HKDF_GATHER_VECTOR reg
    por xmm0, \reg
.endm

// Copies what xmm0 already holds into each of them, xmm0 included and harmless.
.macro HKDF_FILL_VECTOR reg
    movdqa \reg, xmm0
.endm

// uint64_t redoubt_hkdf_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost rdi, and
// rdi is one of the registers being asked about — it would arrive holding our
// own pointer rather than the caller's value. With nothing passed, `call` is
// the whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_hkdf_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hkdf_registers_are_zeroized)
FUNC(redoubt_hkdf_registers_are_zeroized):
    // The vectors gather first, into xmm0, whose own value goes in on the first
    // line. `por` reads and writes nothing but vector registers, so every
    // general register is still the caller's when the next line reaches it.
    HKDF_EACH_VECTOR HKDF_GATHER_VECTOR

    // rcx gathers, its own value going in on its own line, and rax is read
    // before anything here writes to it.
    HKDF_EACH_GPR HKDF_GATHER_GPR

    // The vectors fold in last, through a register whose value rcx already has.
    movq rax, xmm0
    or rcx, rax
    pextrq rax, xmm0, 1
    or rcx, rax

    mov rax, rcx
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before a verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_registers)
HIDDEN_FUNC(redoubt_hkdf_dirty_registers)
FUNC(redoubt_hkdf_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    punpcklqdq xmm0, xmm0
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
//   Reads below its own rsp, and that is the whole of it: `call` leaves rsp
//   where the routine before had it, so what sits under this one's return
//   address is what sat under that one's — the frame it took and gave back.
//
//   Asked after the registers, never before: reading a frame takes registers,
//   and the answer about those has to be taken first.
//
// void redoubt_hkdf_dirty_frame_\name(size_t at)
//
//   One byte of the frame, dirtied and left. rdi says which.
//
//   Swept over every offset, this is what establishes that the verifier reads
//   the whole frame and not the first word of it — and that the byte it reaches
//   is the byte that was written, which is where an off-by-one against the
//   return address sitting next door would show.
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
    // The index counts up from minus the frame to zero. x86 addresses with a
    // base plus an index, never a base minus one, so what reaches below rsp is
    // an index holding a negative number rather than a subtraction.
    xor eax, eax
    mov rcx, -\size
1:
    or rax, [rsp + rcx]
    add rcx, 8
    jnz 1b
    ret

.p2align 4
.globl FUNC(redoubt_hkdf_dirty_frame_\name)
HIDDEN_FUNC(redoubt_hkdf_dirty_frame_\name)
FUNC(redoubt_hkdf_dirty_frame_\name):
    sub rsp, \size
    // Isolate this byte from every previous call's residue. Keep rdi, the
    // requested offset, intact until the whole frame is empty.
    xor ecx, ecx
2:
    mov qword ptr [rsp + rcx], 0
    add rcx, 8
    cmp rcx, \size
    jb 2b
    mov byte ptr [rsp + rdi], 0x5c
    add rsp, \size
    ret

.p2align 4
.globl FUNC(redoubt_hkdf_clean_frame_\name)
HIDDEN_FUNC(redoubt_hkdf_clean_frame_\name)
FUNC(redoubt_hkdf_clean_frame_\name):
    sub rsp, \size
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
3:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, \size
    jb 3b
    HKDF_EMPTY_FRAME \size
    HKDF_SHA256_ZEROIZE_ALL
    ret
.endm

// The two routines with no name outside this file, given one for the length of
// a measurement.
//
// A jump and not a call. `jmp` leaves rsp and the return address exactly as
// they arrived, so the frame the routine takes is the one it would have taken
// from its real caller — and the one the verifier will read. A `call` here
// would put another return address in between and move the whole window.
.p2align 4
.globl FUNC(redoubt_hkdf_probe_update_finalize)
HIDDEN_FUNC(redoubt_hkdf_probe_update_finalize)
FUNC(redoubt_hkdf_probe_update_finalize):
    jmp .Lsha256_update_finalize

.p2align 4
.globl FUNC(redoubt_hkdf_probe_absorb)
HIDDEN_FUNC(redoubt_hkdf_probe_absorb)
FUNC(redoubt_hkdf_probe_absorb):
    jmp .Lsha256_absorb

HKDF_FRAME_PROBE compress_block, FRAME_COMPRESS
HKDF_FRAME_PROBE hash, FRAME_HASH
HKDF_FRAME_PROBE update_finalize, FRAME_UPDATE
HKDF_FRAME_PROBE hmac, FRAME_HMAC
HKDF_FRAME_PROBE absorb, FRAME_ABSORB
HKDF_FRAME_PROBE hkdf, FRAME_HKDF

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
