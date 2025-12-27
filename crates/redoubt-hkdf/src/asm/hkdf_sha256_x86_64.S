// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! HKDF-SHA256 - x86_64 Implementation (SysV ABI)
//!
//! Complete implementation of RFC 5869 (HKDF) with SHA-256
//! Ported from AArch64 v5 with register allocation adapted for x86_64 constraints
//!
//! KEY CONSTRAINTS:
//!   - x86_64 has only 6 callee-saved GPRs (rbx, r12-r15, rbp) vs 11 in AArch64
//!   - Strategy: Use callee-saved for critical values, stack slots for less frequent access
//!   - See REGISTER_ALLOCATION_X86_64.md for detailed allocation strategy
//!
//! PLATFORM SUPPORT:
//!   - Linux, macOS (SysV ABI)
//!   - Baseline x86_64 + SSE4.1 (pextrd, pinsrd, pshufb, palignr)
//!   - Intel syntax assembly
//!
//! SECURITY FEATURES:
//!   - Complete stack zeroization before return
//!   - Caller-saved register zeroization in top-level functions (HKDF_SHA256_ZEROIZE_ALL)
//!   - Constant-time operations where applicable
//!
//! FUNCTIONS:
//!   - sha256_compress_block: Single block compression (64 rounds)
//!   - sha256_hash: Full SHA-256 hash with padding
//!   - sha256_update_finalize: Continue from existing H state
//!   - hmac_sha256: HMAC-SHA256 per RFC 2104
//!   - hkdf_sha256: HKDF key derivation per RFC 5869

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

.p2align 4
.Lbswap_mask:
    .byte 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12

.p2align 4
H256_INIT:
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

.text

//============================================================================
// Complete Register Zeroization Macro
//============================================================================
//
// Strategy: Top-level functions (hmac_sha256, hkdf_sha256) use this macro
//           to zeroize ALL caller-saved registers after stack cleanup.
//
// Zeroizes ONLY caller-saved registers:
//   - xmm0-xmm15 : All SIMD registers (SysV ABI - all caller-saved)
//   - rax, rcx, rdx, rsi, rdi, r8-r11 : Caller-saved GPR
//
// Never zeroized (ABI requirement):
//   - rbx, r12-r15, rbp : Callee-saved GPR (restored by epilogue)
//   - rsp : Stack pointer
//
// Usage: Called by top-level functions (hmac_sha256, hkdf_sha256) after
//        stack zeroization but before restoring callee-saved registers.
//
.macro HKDF_SHA256_ZEROIZE_ALL
    // Zeroize caller-saved GPRs
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

    // Zeroize all SIMD registers (xmm0-xmm15)
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
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
// Register allocation (following REGISTER_ALLOCATION_X86_64.md):
//   Callee-saved (must preserve):
//     rbx, r12, r13, r14, r15 - saved in prologue
//   Preserved pointers:
//     r13 = H_ptr (saved from rdi, needed for final H update)
//     r14 = block_ptr (saved from rsi)
//   Loop control:
//     rdx = loop counter t (0-63)
//     rcx = K_ptr (K256 constants)
//   Round temporaries (32-bit):
//     eax, r8d-r12d, r15d, ebx, esi = T1, T2, Ch, Maj, Σ, σ computations
//   SIMD registers:
//     xmm0-xmm1 = H state (load/store)
//     xmm2-xmm3 = working variables {a,b,c,d}, {e,f,g,h}
//     xmm4-xmm7 = sliding window W[t-16..t-1] (rounds 16-63)
//     xmm8-xmm13 = temps for message schedule and window rotation
//     xmm9 = bswap mask
//
// Stack usage:
//   64 bytes for W[0..15] (zeroized before return)
//============================================================================
.global FUNC(sha256_compress_block)
HIDDEN_FUNC(sha256_compress_block)
#if !defined(__APPLE__)
.type FUNC(sha256_compress_block), @function
#endif
.p2align 4
FUNC(sha256_compress_block):
    // Save callee-saved registers
    push rbx
    push r12
    push r13
    push r14
    push r15

    // Allocate stack for W[0..15] (64 bytes) + alignment
    sub rsp, 80

    // Save pointers in callee-saved registers
    mov r13, rdi                // r13 = H_ptr
    mov r14, rsi                // r14 = block_ptr

    // Load H[0..7] from memory
    movdqu xmm0, [r13]          // xmm0 = H[0..3]
    movdqu xmm1, [r13 + 16]     // xmm1 = H[4..7]

    // Load 64-byte message block and byte-swap from big-endian
    movdqu xmm4, [r14]
    movdqu xmm5, [r14 + 16]
    movdqu xmm6, [r14 + 32]
    movdqu xmm7, [r14 + 48]

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
    movdqa [rsp], xmm4
    movdqa [rsp + 16], xmm5
    movdqa [rsp + 32], xmm6
    movdqa [rsp + 48], xmm7

    // Initialize working variables
    movdqa xmm2, xmm0           // xmm2 = {a,b,c,d}
    movdqa xmm3, xmm1           // xmm3 = {e,f,g,h}

    // Load K256 pointer
#if defined(__APPLE__)
    lea rcx, [rip + K256]
#else
    lea rcx, K256[rip]
#endif

    // ========================================================================
    // Rounds 0-15: W[t] from stack
    // ========================================================================
    xor rdx, rdx                // t = 0

.Lround_0_15:
    // Load W[t] and K[t]
    mov r8d, [rsp + rdx*4]      // r8d = W[t]
    mov r9d, [rcx + rdx*4]      // r9d = K[t]

    // Extract working variables from xmm3 {e,f,g,h}
    pextrd r10d, xmm3, 3        // h
    pextrd eax, xmm3, 0         // e
    pextrd r11d, xmm3, 1        // f
    pextrd ebx, xmm3, 2         // g

    // T1 = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
    mov r15d, r10d              // T1 = h

    // Σ₁(e) = ROTR(6) ^ ROTR(11) ^ ROTR(25)
    mov r10d, eax
    ror r10d, 6
    mov r12d, eax
    ror r12d, 11
    xor r10d, r12d
    mov r12d, eax
    ror r12d, 25
    xor r10d, r12d
    add r15d, r10d              // T1 += Σ₁(e)

    // Ch(e,f,g) = (e & f) ^ (~e & g)
    mov r10d, eax
    not r10d
    and r10d, ebx               // ~e & g
    mov r12d, eax
    and r12d, r11d              // e & f
    xor r10d, r12d
    add r15d, r10d              // T1 += Ch(e,f,g)

    add r15d, r9d               // T1 += K[t]
    add r15d, r8d               // T1 += W[t]

    // Extract working variables from xmm2 {a,b,c,d}
    pextrd eax, xmm2, 0         // a
    pextrd r10d, xmm2, 1        // b
    pextrd r11d, xmm2, 2        // c

    // T2 = Σ₀(a) + Maj(a,b,c)
    // Σ₀(a) = ROTR(2) ^ ROTR(13) ^ ROTR(22)
    mov r9d, eax
    ror r9d, 2
    mov r12d, eax
    ror r12d, 13
    xor r9d, r12d
    mov r12d, eax
    ror r12d, 22
    xor r9d, r12d               // r9d = Σ₀(a)

    // Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    mov r8d, eax
    and r8d, r10d               // a & b
    mov r12d, eax
    and r12d, r11d              // a & c
    xor r8d, r12d
    mov r12d, r10d
    and r12d, r11d              // b & c
    xor r8d, r12d               // r8d = Maj

    add r9d, r8d                // r9d = T2

    // Update working variables
    pextrd r10d, xmm2, 3        // d
    add r10d, r15d              // e_new = d + T1
    add r15d, r9d               // a_new = T1 + T2

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

    pinsrd xmm2, r15d, 0        // a = a_new
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
    mov r12d, r8d
    ror r12d, 18
    xor r11d, r12d
    mov r12d, r8d
    shr r12d, 3
    xor r11d, r12d              // r11d = σ₀(W[t-15])

    // σ₁(W[t-2]) = ROTR(17) ^ ROTR(19) ^ SHR(10)
    mov r8d, r10d
    ror r8d, 17
    mov r12d, r10d
    ror r12d, 19
    xor r8d, r12d
    mov r12d, r10d
    shr r12d, 10
    xor r8d, r12d               // r8d = σ₁(W[t-2])

    // W[t] = W[t-16] + σ₀ + W[t-7] + σ₁
    add eax, r11d
    add eax, r9d
    add eax, r8d                // eax = W[t]

    // Save W[t] for window update
    mov r8d, eax                // r8d = W[t]

    // Load K[t]
    mov r9d, [rcx + rdx*4]

    // === Compute round (same as rounds 0-15) ===
    pextrd r10d, xmm3, 3        // h
    pextrd eax, xmm3, 0         // e
    pextrd r11d, xmm3, 1        // f
    pextrd ebx, xmm3, 2         // g

    mov r15d, r10d              // T1 = h

    // Σ₁(e)
    mov r10d, eax
    ror r10d, 6
    mov r12d, eax
    ror r12d, 11
    xor r10d, r12d
    mov r12d, eax
    ror r12d, 25
    xor r10d, r12d
    add r15d, r10d

    // Ch(e,f,g)
    mov r10d, eax
    not r10d
    and r10d, ebx
    mov r12d, eax
    and r12d, r11d
    xor r10d, r12d
    add r15d, r10d

    add r15d, r9d               // + K[t]
    add r15d, r8d               // + W[t]

    // T2
    pextrd eax, xmm2, 0         // a
    pextrd r10d, xmm2, 1        // b
    pextrd r11d, xmm2, 2        // c

    mov r9d, eax
    ror r9d, 2
    mov r12d, eax
    ror r12d, 13
    xor r9d, r12d
    mov r12d, eax
    ror r12d, 22
    xor r9d, r12d

    mov esi, eax
    and esi, r10d
    mov r12d, eax
    and r12d, r11d
    xor esi, r12d
    mov r12d, r10d
    and r12d, r11d
    xor esi, r12d

    add r9d, esi                // T2

    pextrd r10d, xmm2, 3        // d
    add r10d, r15d              // e_new
    add r15d, r9d               // a_new

    // Update xmm3
    pextrd esi, xmm3, 0
    pextrd r9d, xmm3, 1
    pextrd r11d, xmm3, 2

    pinsrd xmm3, r10d, 0
    pinsrd xmm3, esi, 1
    pinsrd xmm3, r9d, 2
    pinsrd xmm3, r11d, 3

    // Update xmm2
    pextrd esi, xmm2, 0
    pextrd r9d, xmm2, 1
    pextrd r11d, xmm2, 2

    pinsrd xmm2, r15d, 0
    pinsrd xmm2, esi, 1
    pinsrd xmm2, r9d, 2
    pinsrd xmm2, r11d, 3

    // Update sliding window: shift left by 1 word
    // PALIGNR dst, src, imm8: TEMP = (dst << 128) | src; dst = TEMP >> (imm8*8)
    // To get [W1,W2,W3,W4] we need TEMP = [xmm5 | xmm4] >> 32
    // So we do: dst=xmm5_copy, src=xmm4, palignr dst, src, 4
    movd xmm8, r8d              // xmm8 = [W[t], 0, 0, 0]

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
    movdqu xmm0, [r13]
    paddd xmm0, xmm2
    movdqu [r13], xmm0

    movdqu xmm1, [r13 + 16]
    paddd xmm1, xmm3
    movdqu [r13 + 16], xmm1

    // ========================================================================
    // ZEROIZE STACK
    // ========================================================================
    pxor xmm0, xmm0
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0

    // Restore
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

#if !defined(__APPLE__)
.size FUNC(sha256_compress_block), .-FUNC(sha256_compress_block)
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
//   1. Initialize H with SHA-256 IV (H256_INIT)
//   2. Process complete 64-byte blocks via sha256_compress_block
//   3. Apply SHA-256 padding to final block(s): 0x80 + zeros + 64-bit length
//   4. Output big-endian digest
//
// Register allocation (callee-saved):
//   rbx, r12-r15, rbp - saved in prologue
//   r12 = msg_ptr_current (advances through message)
//   r13 = msg_remaining (decrements as blocks processed)
//   r14 = original_msg_len (constant, needed for padding length field)
//   r15 = digest_ptr (preserved across calls)
//
// Temporary registers (caller-saved):
//   rdi, rsi = params to sha256_compress_block
//   rax, rcx, r8-r9 = copy loops, temps
//   xmm0-xmm2 = H state transfer, bswap
//
// Stack layout:
//   [rsp+0..31]:   H state (32 bytes)
//   [rsp+32..95]:  final block buffer 1 (64 bytes)
//   [rsp+96..159]: final block buffer 2 (64 bytes, if needed)
//   Total: 168 bytes (160 + 8 alignment), zeroized before return
//============================================================================
.global FUNC(sha256_hash)
HIDDEN_FUNC(sha256_hash)
#if !defined(__APPLE__)
.type FUNC(sha256_hash), @function
#endif
.p2align 4
FUNC(sha256_hash):
    // Prologue: save callee-saved registers and frame pointer
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    // Allocate working space: 160 bytes + 8 for alignment = 168
    sub rsp, 168

    // Pre-zeroize H state
    pxor xmm0, xmm0
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm0

    // Save parameters in callee-saved registers
    mov r12, rdi            // msg_ptr_current
    mov r13, rsi            // msg_remaining
    mov r14, rsi            // original_msg_len (constant)
    mov r15, rdx            // digest_ptr

    // Initialize H with H256_INIT
#if defined(__APPLE__)
    lea rax, [rip + H256_INIT]
#else
    lea rax, H256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm1

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lhash_block_loop:
    cmp r13, 64
    jl .Lhash_final_block

    // Call sha256_compress_block(H_ptr, block_ptr)
    lea rdi, [rsp]          // H_ptr
    mov rsi, r12            // block_ptr
    call FUNC(sha256_compress_block)

    // Advance to next block
    add r12, 64
    sub r13, 64
    jmp .Lhash_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lhash_final_block:
    // r13 = remainder (0 to 63 bytes)
    // r14 = original_msg_len (for bit count in padding)

    // Zero first block buffer
    pxor xmm0, xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0

    // Copy remainder bytes to block buffer
    xor rcx, rcx            // counter = 0
.Lhash_copy_remainder:
    cmp rcx, r13
    jge .Lhash_remainder_done
    movzx eax, byte ptr [r12 + rcx]
    mov byte ptr [rsp + 32 + rcx], al
    inc rcx
    jmp .Lhash_copy_remainder

.Lhash_remainder_done:
    // Append 0x80 byte
    mov byte ptr [rsp + 32 + r13], 0x80

    // Check if length fits in this block (remainder < 56)
    cmp r13, 56
    jge .Lhash_two_blocks

    // === ONE BLOCK CASE ===
    // Append 64-bit big-endian length at offset 56
    mov rax, r14
    shl rax, 3              // bits = bytes * 8
    bswap rax               // big-endian
    mov [rsp + 32 + 56], rax

    // Compress final block
    lea rdi, [rsp]          // H_ptr
    lea rsi, [rsp + 32]     // block_ptr
    call FUNC(sha256_compress_block)

    jmp .Lhash_finish

    // === TWO BLOCK CASE ===
.Lhash_two_blocks:
    // First block: remainder + 0x80 + zeros (no length yet)
    lea rdi, [rsp]
    lea rsi, [rsp + 32]
    call FUNC(sha256_compress_block)

    // Second block: all zeros except length at end
    pxor xmm0, xmm0
    movdqa [rsp + 96], xmm0
    movdqa [rsp + 112], xmm0
    movdqa [rsp + 128], xmm0
    movdqa [rsp + 144], xmm0

    // Append 64-bit big-endian length at offset 56
    mov rax, r14
    shl rax, 3
    bswap rax
    mov [rsp + 96 + 56], rax

    // Compress second block
    lea rdi, [rsp]
    lea rsi, [rsp + 96]
    call FUNC(sha256_compress_block)

.Lhash_finish:
    // Copy H state to digest (as big-endian bytes per SHA-256 spec)
    movdqa xmm0, [rsp]
    movdqa xmm1, [rsp + 16]

    // Convert to big-endian for output (byte-swap each dword)
#if defined(__APPLE__)
    lea rax, [rip + .Lbswap_mask]
#else
    lea rax, .Lbswap_mask[rip]
#endif
    movdqa xmm2, [rax]
    pshufb xmm0, xmm2
    pshufb xmm1, xmm2

    movdqu [r15], xmm0
    movdqu [r15 + 16], xmm1

    // Zeroize entire stack (H state + block buffers)
    pxor xmm0, xmm0
    movdqa [rsp], xmm0          // H state
    movdqa [rsp + 16], xmm0
    movdqa [rsp + 32], xmm0     // block buffer 1
    movdqa [rsp + 48], xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0
    movdqa [rsp + 96], xmm0     // block buffer 2
    movdqa [rsp + 112], xmm0
    movdqa [rsp + 128], xmm0
    movdqa [rsp + 144], xmm0

    // Deallocate working space
    add rsp, 168

    // Epilogue: restore callee-saved registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

#if !defined(__APPLE__)
.size FUNC(sha256_hash), .-FUNC(sha256_hash)
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
// Register allocation (callee-saved):
//   rbx, r12-r15, rbp - saved in prologue
//   rbx = H_ptr (needed to reload H, preserved across sha256_compress_block)
//   r12 = msg_ptr_current
//   r13 = msg_remaining
//   r14 = total_len (for padding length field)
//   r15 = digest_ptr
//
// Temporary registers (caller-saved):
//   rdi, rsi = params to sha256_compress_block
//   rax, rcx, r8-r9 = copy loops, temps
//   xmm0-xmm2 = H state, bswap
//
// Stack layout:
//   [rsp+0..31]:   H state (32 bytes)
//   [rsp+32..95]:  final block buffer 1 (64 bytes)
//   [rsp+96..159]: final block buffer 2 (64 bytes, if needed)
//   Total: 168 bytes (160 + 8 alignment), zeroized before return
//============================================================================
.global FUNC(sha256_update_finalize)
HIDDEN_FUNC(sha256_update_finalize)
#if !defined(__APPLE__)
.type FUNC(sha256_update_finalize), @function
#endif
.p2align 4
FUNC(sha256_update_finalize):
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    sub rsp, 168

    // Save H_ptr to callee-saved
    mov rbx, rdi

    // Load existing H state from H_ptr to stack
    movdqu xmm0, [rbx]
    movdqu xmm1, [rbx + 16]
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm1

    // Save parameters
    mov r12, rsi            // msg_ptr_current
    mov r13, rdx            // msg_remaining
    mov r14, rcx            // total_len
    mov r15, r8             // digest_ptr

    // ========================================================================
    // Process complete 64-byte blocks
    // ========================================================================
.Lupdate_block_loop:
    cmp r13, 64
    jl .Lupdate_final_block

    lea rdi, [rsp]          // H_ptr
    mov rsi, r12            // block_ptr
    call FUNC(sha256_compress_block)

    add r12, 64
    sub r13, 64
    jmp .Lupdate_block_loop

    // ========================================================================
    // Process final block(s) with SHA-256 padding
    // ========================================================================
.Lupdate_final_block:
    // Zero first block buffer
    pxor xmm0, xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0

    // Copy remainder bytes
    xor rcx, rcx
.Lupdate_copy_remainder:
    cmp rcx, r13
    jge .Lupdate_remainder_done
    movzx eax, byte ptr [r12 + rcx]
    mov byte ptr [rsp + 32 + rcx], al
    inc rcx
    jmp .Lupdate_copy_remainder

.Lupdate_remainder_done:
    // Append 0x80
    mov byte ptr [rsp + 32 + r13], 0x80

    // Check if fits in one block
    cmp r13, 56
    jge .Lupdate_two_blocks

    // ONE BLOCK
    mov rax, r14
    shl rax, 3
    bswap rax
    mov [rsp + 32 + 56], rax

    lea rdi, [rsp]
    lea rsi, [rsp + 32]
    call FUNC(sha256_compress_block)

    jmp .Lupdate_finish

.Lupdate_two_blocks:
    lea rdi, [rsp]
    lea rsi, [rsp + 32]
    call FUNC(sha256_compress_block)

    // Second block
    pxor xmm0, xmm0
    movdqa [rsp + 96], xmm0
    movdqa [rsp + 112], xmm0
    movdqa [rsp + 128], xmm0
    movdqa [rsp + 144], xmm0

    mov rax, r14
    shl rax, 3
    bswap rax
    mov [rsp + 96 + 56], rax

    lea rdi, [rsp]
    lea rsi, [rsp + 96]
    call FUNC(sha256_compress_block)

.Lupdate_finish:
    // Copy H to digest (big-endian)
    movdqa xmm0, [rsp]
    movdqa xmm1, [rsp + 16]

#if defined(__APPLE__)
    lea rax, [rip + .Lbswap_mask]
#else
    lea rax, .Lbswap_mask[rip]
#endif
    movdqa xmm2, [rax]
    pshufb xmm0, xmm2
    pshufb xmm1, xmm2

    movdqu [r15], xmm0
    movdqu [r15 + 16], xmm1

    // Zeroize stack
    pxor xmm0, xmm0
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0
    movdqa [rsp + 96], xmm0
    movdqa [rsp + 112], xmm0
    movdqa [rsp + 128], xmm0
    movdqa [rsp + 144], xmm0

    add rsp, 168
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

#if !defined(__APPLE__)
.size FUNC(sha256_update_finalize), .-FUNC(sha256_update_finalize)
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
// Register allocation (callee-saved):
//   rbx, r12-r15, rbp - saved in prologue
//   rbx = key_ptr (used throughout key processing)
//   r12 = key_len (used throughout key processing)
//   r13 = msg_ptr (preserved for inner hash)
//   r14 = msg_len (preserved for inner hash)
//   r15 = mac_ptr (preserved for final output)
//
// Temporary registers (caller-saved):
//   rdi, rsi, rdx, rcx, r8 = params to sha256_hash/sha256_update_finalize
//   rax, r9-r11 = copy loops, XOR operations
//   xmm0-xmm1 = key/pad movement
//
// Stack layout:
//   [rsp+0..63]:    K_padded (64 bytes - key material, zeroized)
//   [rsp+64..127]:  ipad (64 bytes - K ⊕ 0x36, zeroized)
//   [rsp+128..191]: opad (64 bytes - K ⊕ 0x5c, zeroized)
//   [rsp+192..223]: inner_hash (32 bytes - intermediate, zeroized)
//   [rsp+224..255]: temp key hash (32 bytes - for long keys, zeroized)
//   [rsp+256..287]: H state (32 bytes - working space, zeroized)
//   Total: 296 bytes (288 + 8 alignment), fully zeroized before return
//
// Security: All sensitive data (K_padded, pads, inner_hash) zeroized
//           + HKDF_SHA256_ZEROIZE_ALL clears all caller-saved registers
//============================================================================
.global FUNC(hmac_sha256)
HIDDEN_FUNC(hmac_sha256)
#if !defined(__APPLE__)
.type FUNC(hmac_sha256), @function
#endif
.p2align 4
FUNC(hmac_sha256):
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    // Allocate 256 + 32 (for H state) + 8 alignment = 296
    sub rsp, 296

    // Save parameters
    mov rbx, rdi            // key_ptr
    mov r12, rsi            // key_len
    mov r13, rdx            // msg_ptr
    mov r14, rcx            // msg_len
    mov r15, r8             // mac_ptr

    // ========================================================================
    // Step 1: Process key
    // ========================================================================
    cmp r12, 64
    jle .Lhmac_key_short

    // key_len > 64: K = SHA256(key)
    mov rdi, rbx            // key_ptr
    mov rsi, r12            // key_len
    lea rdx, [rsp + 224]    // temp digest buffer
    call FUNC(sha256_hash)

    // Copy hashed key to K_padded (32 bytes)
    movdqa xmm0, [rsp + 224]
    movdqa xmm1, [rsp + 240]
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm1

    // Zero remaining 32 bytes
    pxor xmm0, xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0

    jmp .Lhmac_key_ready

.Lhmac_key_short:
    // key_len <= 64: copy key and zero-pad
    pxor xmm0, xmm0
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0

    // Copy key bytes
    xor rcx, rcx
.Lhmac_copy_key:
    cmp rcx, r12
    jge .Lhmac_key_ready
    movzx eax, byte ptr [rbx + rcx]
    mov byte ptr [rsp + rcx], al
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

    movzx eax, byte ptr [rsp + rcx]     // K_padded[i]

    mov edx, eax
    xor edx, 0x36
    mov byte ptr [rsp + 64 + rcx], dl   // ipad[i]

    xor eax, 0x5c
    mov byte ptr [rsp + 128 + rcx], al  // opad[i]

    inc rcx
    jmp .Lhmac_xor_loop

.Lhmac_xor_done:
    // ========================================================================
    // Step 3: inner_hash = SHA256(ipad || msg)
    // ========================================================================
    // Initialize H at [rsp + 256]
#if defined(__APPLE__)
    lea rax, [rip + H256_INIT]
#else
    lea rax, H256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + 256], xmm0
    movdqa [rsp + 272], xmm1

    // Compress ipad
    lea rdi, [rsp + 256]    // H_ptr
    lea rsi, [rsp + 64]     // ipad
    call FUNC(sha256_compress_block)

    // sha256_update_finalize(H, msg, msg_len, 64+msg_len, inner_hash)
    lea rdi, [rsp + 256]    // H_ptr
    mov rsi, r13            // msg_ptr
    mov rdx, r14            // msg_len
    lea rcx, [r14 + 64]     // total_len = 64 + msg_len
    lea r8, [rsp + 192]     // inner_hash output
    call FUNC(sha256_update_finalize)

    // ========================================================================
    // Step 4: mac = SHA256(opad || inner_hash)
    // ========================================================================
    // Re-initialize H
#if defined(__APPLE__)
    lea rax, [rip + H256_INIT]
#else
    lea rax, H256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + 256], xmm0
    movdqa [rsp + 272], xmm1

    // Compress opad
    lea rdi, [rsp + 256]    // H_ptr
    lea rsi, [rsp + 128]    // opad
    call FUNC(sha256_compress_block)

    // sha256_update_finalize(H, inner_hash, 32, 96, mac)
    lea rdi, [rsp + 256]    // H_ptr
    lea rsi, [rsp + 192]    // inner_hash
    mov rdx, 32             // inner_hash len
    mov rcx, 96             // total_len = 64 + 32
    mov r8, r15             // mac output
    call FUNC(sha256_update_finalize)

    // ========================================================================
    // Cleanup
    // ========================================================================
    pxor xmm0, xmm0
    // Zeroize K_padded, ipad, opad, inner_hash, temp, H
    movdqa [rsp], xmm0
    movdqa [rsp + 16], xmm0
    movdqa [rsp + 32], xmm0
    movdqa [rsp + 48], xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0
    movdqa [rsp + 96], xmm0
    movdqa [rsp + 112], xmm0
    movdqa [rsp + 128], xmm0
    movdqa [rsp + 144], xmm0
    movdqa [rsp + 160], xmm0
    movdqa [rsp + 176], xmm0
    movdqa [rsp + 192], xmm0
    movdqa [rsp + 208], xmm0
    movdqa [rsp + 224], xmm0
    movdqa [rsp + 240], xmm0
    movdqa [rsp + 256], xmm0
    movdqa [rsp + 272], xmm0

    // Zeroize all caller-saved registers (security-critical)
    HKDF_SHA256_ZEROIZE_ALL

    add rsp, 296
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

#if !defined(__APPLE__)
.size FUNC(hmac_sha256), .-FUNC(hmac_sha256)
#endif

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
//   [rbp+16]: okm_ptr (Output Key Material)
//   [rbp+24]: okm_len (must be <= 8160 bytes = 255 * 32)
//
// Behavior:
//   1. Extract: PRK = HMAC-SHA256(salt, IKM)
//   2. Expand: Iteratively generate OKM blocks:
//      T(1) = HMAC(PRK, info || 0x01)
//      T(i) = HMAC(PRK, T(i-1) || info || i) for i = 2..N
//      OKM = first okm_len bytes of T(1) || T(2) || ... || T(N)
//      where N = ceil(okm_len / 32)
//
// Register allocation (callee-saved):
//   rbx, r12-r15, rbp - saved in prologue
//   rbx = info_ptr (used every iteration)
//   r12 = info_len (used every iteration)
//   r13 = okm_ptr (cursor, advanced each iteration)
//   r14 = okm_len (remaining bytes, decremented each iteration)
//   r15 = counter (1..255, iteration index)
//
// Stack-based values (after 5 pushes + sub rsp,24):
//   [rbp-8]...[rbp-40]   = saved callee-saved regs (rbx, r12-r15)
//   [rbp-48] = T_len (0 for i=1, 32 for i>1)
//   [rbp-56] = locals_size (for cleanup)
//
// Temporary registers (caller-saved):
//   rdi, rsi, rdx, rcx, r8 = params to hmac_sha256
//   rax, r9-r11 = copy loops, calculations
//   xmm0 = zeroization
//
// Stack layout (variable size):
//   [rsp+0..31]:   PRK (32 bytes - Extract output, used as HMAC key in Expand)
//   [rsp+32..63]:  T(i) (32 bytes - current iteration output)
//   [rsp+64..end]: msg buffer for T(i-1) || info || counter
//                  size = align16(32 + info_len + 1)
//   Total: 64 + align16(32 + info_len + 1), fully zeroized before return
//
// Security: All intermediate values (PRK, T(i), msg buffers) zeroized
//           + HKDF_SHA256_ZEROIZE_ALL clears all caller-saved registers
//============================================================================
.global FUNC(hkdf_sha256)
HIDDEN_FUNC(hkdf_sha256)
#if !defined(__APPLE__)
.type FUNC(hkdf_sha256), @function
#endif
.p2align 4
FUNC(hkdf_sha256):
    // Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    // Reserve space for T_len and locals_size
    sub rsp, 24

    // Save stable params to callee-saved regs
    mov rbx, r8             // info_ptr
    mov r12, r9             // info_len
    mov r13, [rbp + 16]     // okm_ptr
    mov r14, [rbp + 24]     // okm_len

    // Compute msg_cap_aligned = align16(32 + info_len + 1)
    // and locals_size = 64 + msg_cap_aligned
    lea rax, [r12 + 33]     // msg_cap = info_len + 32 + 1
    add rax, 15
    and rax, -16            // msg_cap_aligned
    lea r10, [rax + 64]     // locals_size
    mov [rbp - 56], r10     // save locals_size

    // Allocate locals (variable size)
    // rsp is already 16-byte aligned (prologue=80, locals_size=16n)
    sub rsp, r10

    // ------------------------------------------------------------------------
    // Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
    // ------------------------------------------------------------------------
    // hmac_sha256(salt, salt_len, ikm, ikm_len, prk)
    // rdi=salt, rsi=salt_len already set from entry
    // rdx=ikm, rcx=ikm_len already set from entry
    lea r8, [rsp]           // out: PRK at rsp+0
    call FUNC(hmac_sha256)

    // ------------------------------------------------------------------------
    // Step 2: Expand
    // ------------------------------------------------------------------------
    mov r15, 1              // counter = 1
    mov qword ptr [rbp - 48], 0   // T_len = 0 for i=1

.Lhkdf_expand_loop:
    test r14, r14           // okm_len == 0?
    jz .Lhkdf_done

    // msg_base = rsp + 64
    lea r10, [rsp + 64]

    // Copy T(i-1) from [rsp+32] length T_len into msg_base
    lea r11, [rsp + 32]     // T(i-1) location
    mov rcx, [rbp - 48]      // T_len
    xor rax, rax
.Lhkdf_copy_t:
    cmp rax, rcx
    jae .Lhkdf_t_copied
    movzx edx, byte ptr [r11 + rax]
    mov byte ptr [r10 + rax], dl
    inc rax
    jmp .Lhkdf_copy_t

.Lhkdf_t_copied:
    // Copy info right after T(i-1)
    add r10, rcx            // r10 = msg_base + T_len
    xor rax, rax
.Lhkdf_copy_info:
    cmp rax, r12
    jae .Lhkdf_info_copied
    movzx edx, byte ptr [rbx + rax]
    mov byte ptr [r10 + rax], dl
    inc rax
    jmp .Lhkdf_copy_info

.Lhkdf_info_copied:
    // Append counter byte after info
    add r10, r12
    mov byte ptr [r10], r15b

    // msg_len = T_len + info_len + 1
    mov rax, [rbp - 48]      // T_len
    add rax, r12            // + info_len
    inc rax                 // + 1

    // T(i) = HMAC(PRK, msg)
    lea rdi, [rsp]          // key: PRK
    mov rsi, 32             // key_len
    lea rdx, [rsp + 64]     // msg
    mov rcx, rax            // msg_len
    lea r8, [rsp + 32]      // out: T(i)
    call FUNC(hmac_sha256)

    // Copy min(okm_len, 32) bytes from T(i) into okm_ptr
    mov rax, 32
    cmp r14, 32
    cmovb rax, r14          // bytes_to_copy = min(okm_len, 32)

    lea r10, [rsp + 32]     // T(i) location
    xor rcx, rcx
.Lhkdf_copy_okm:
    cmp rcx, rax
    jae .Lhkdf_okm_copied
    movzx edx, byte ptr [r10 + rcx]
    mov byte ptr [r13 + rcx], dl
    inc rcx
    jmp .Lhkdf_copy_okm

.Lhkdf_okm_copied:
    // Update output cursor and remaining length
    add r13, rax
    sub r14, rax

    // Next iteration state
    inc r15                 // counter++
    mov qword ptr [rbp - 48], 32  // T_len = 32 from now on

    // Wipe first 32 bytes of msg buffer (contains T(i-1))
    pxor xmm0, xmm0
    movdqa [rsp + 64], xmm0
    movdqa [rsp + 80], xmm0

    jmp .Lhkdf_expand_loop

.Lhkdf_done:
    // ------------------------------------------------------------------------
    // Strong zeroization of locals
    // ------------------------------------------------------------------------
    mov rcx, [rbp - 56]     // locals_size
    shr rcx, 4              // 16-byte chunks
    mov rdi, rsp
    pxor xmm0, xmm0
.Lhkdf_wipe_loop:
    movdqa [rdi], xmm0
    add rdi, 16
    dec rcx
    jnz .Lhkdf_wipe_loop

    // Zeroize all caller-saved registers (security-critical)
    HKDF_SHA256_ZEROIZE_ALL

    // Deallocate locals
    mov rsp, rbp
    sub rsp, 64             // back to after push r15 + 24 bytes reserved

    // Epilogue
    add rsp, 24             // free T_len/locals_size space
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

#if !defined(__APPLE__)
.size FUNC(hkdf_sha256), .-FUNC(hkdf_sha256)
#endif
