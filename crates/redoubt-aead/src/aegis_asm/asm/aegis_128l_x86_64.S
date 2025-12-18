// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L AEAD Cipher - x86_64 (SysV) Implementation
//
// This implementation uses AES-NI (aesenc) for AES round operations.
// The AEGIS-128L state consists of 8 blocks of 128 bits each (1024 bits total).
//
// Register-budgeted design goal:
//   - Maximum live XMM registers across the full algorithm: <= 15
//   - No hidden stack spills (except explicitly marked spill regions)
//   - Caller-saved only (no prologue/epilogue save/restore)
//
// Partial block handling uses a 32-byte stack buffer that is:
//   1. Pre-zeroized before any sensitive data is written
//   2. Immediately zeroized after use (before any other code runs)
//
// Platform Support: Linux x86_64, macOS x86_64
//
// References:
// - AEGIS: A Fast Authenticated Encryption Algorithm (v1.1)
// - Intel AES-NI: aesenc instruction semantics
// - RFC: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-17

.intel_syntax noprefix
.text

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name)
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// Constants
// ============================================================================

#if defined(__APPLE__)
.section __TEXT,__const
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
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
//
// SysV AMD64 ABI:
//   - Caller-saved GPR: rax, rcx, rdx, rsi, rdi, r8-r11
//   - Callee-saved GPR: rbx, rbp, r12-r15  (DO NOT TOUCH)
//   - XMM regs are caller-saved on SysV and macOS.
//
// Zeroizes:
//   - xmm0-xmm15 (safe; caller-saved in practice on SysV)
//   - rax, rcx, rdx, rsi, rdi, r8-r11
//
// Does NOT touch: rsp, rbx, rbp, r12-r15
//
.macro AEGIS_ZEROIZE_ALL
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

    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8,  r8
    xor r9,  r9
    xor r10, r10
    xor r11, r11
.endm

// ============================================================================
// AEGIS-128L Update Macro (Inline - register-budgeted, no stack spilling)
// ============================================================================
//
// Performs one AEGIS-128L state update round completely in registers.
//
// Inputs:
//   xmm0-xmm7   = Current state S0-S7
//   \m0         = First message block (M0)  (xmm reg)
//   \m1         = Second message block (M1) (xmm reg)
//
// Outputs:
//   xmm0-xmm7   = Updated state S'0-S'7 (modified in-place)
//
// Fixed scratch (clobbered):
//   xmm10       = key/xor temporary
//   xmm12       = saved old S7
//   xmm13       = AES round working register
//
// AES-NI mapping:
//   aesenc dst, rk  performs SubBytes + ShiftRows + MixColumns + AddRoundKey(rk).
//   Therefore: AESRound(A, B) == aesenc(A, B) with A as data, B as "round key".
//
.macro AEGIS_UPDATE m0, m1
    // Preserve old S7 for S'0
    movdqa xmm12, xmm7

    // S'7 = AESRound(S6, S7)
    movdqa xmm13, xmm6
    aesenc xmm13, xmm7
    movdqa xmm7, xmm13

    // S'6 = AESRound(S5, S6)
    movdqa xmm13, xmm5
    aesenc xmm13, xmm6
    movdqa xmm6, xmm13

    // S'5 = AESRound(S4, S5)
    movdqa xmm13, xmm4
    aesenc xmm13, xmm5
    movdqa xmm5, xmm13

    // S'4 = AESRound(S3, S4 ^ M1)
    movdqa xmm10, xmm4
    pxor   xmm10, \m1
    movdqa xmm13, xmm3
    aesenc xmm13, xmm10
    movdqa xmm4, xmm13

    // S'3 = AESRound(S2, S3)
    movdqa xmm13, xmm2
    aesenc xmm13, xmm3
    movdqa xmm3, xmm13

    // S'2 = AESRound(S1, S2)
    movdqa xmm13, xmm1
    aesenc xmm13, xmm2
    movdqa xmm2, xmm13

    // S'1 = AESRound(S0, S1)
    movdqa xmm13, xmm0
    aesenc xmm13, xmm1
    movdqa xmm1, xmm13

    // S'0 = AESRound(old S7, S0 ^ M0)
    movdqa xmm10, xmm0
    pxor   xmm10, \m0
    movdqa xmm13, xmm12
    aesenc xmm13, xmm10
    movdqa xmm0, xmm13
.endm

// ============================================================================
// AEGIS-128L Update Function (pointer-based interface for external use)
// ============================================================================
//
// SysV ABI params:
//   rdi = state ptr (128 bytes, modified in-place)
//   rsi = m0 ptr (16 bytes)
//   rdx = m1 ptr (16 bytes)
//
.global FUNC(aegis128l_update)
HIDDEN_FUNC(aegis128l_update)
.p2align 4
FUNC(aegis128l_update):
    // Load state
    movdqu xmm0,  [rdi + 0*16]
    movdqu xmm1,  [rdi + 1*16]
    movdqu xmm2,  [rdi + 2*16]
    movdqu xmm3,  [rdi + 3*16]
    movdqu xmm4,  [rdi + 4*16]
    movdqu xmm5,  [rdi + 5*16]
    movdqu xmm6,  [rdi + 6*16]
    movdqu xmm7,  [rdi + 7*16]

    // Load M0/M1
    movdqu xmm8, [rsi]
    movdqu xmm9, [rdx]

    AEGIS_UPDATE xmm8, xmm9

    // Store state
    movdqu [rdi + 0*16], xmm0
    movdqu [rdi + 1*16], xmm1
    movdqu [rdi + 2*16], xmm2
    movdqu [rdi + 3*16], xmm3
    movdqu [rdi + 4*16], xmm4
    movdqu [rdi + 5*16], xmm5
    movdqu [rdi + 6*16], xmm6
    movdqu [rdi + 7*16], xmm7

    ret

// ============================================================================
// AEGIS-128L Encryption Function (Full support including partial blocks)
// ============================================================================
//
// SysV ABI params:
//   rdi = key ptr (16 bytes)
//   rsi = nonce ptr (16 bytes)
//   rdx = aad ptr
//   rcx = aad len (bytes)
//   r8  = plaintext ptr (in-place -> ciphertext)
//   r9  = plaintext len (bytes)
//   [rsp+8] = tag_out ptr (16 bytes)
//
// Returns: void
//
.global FUNC(aegis128l_encrypt)
HIDDEN_FUNC(aegis128l_encrypt)
.p2align 4
FUNC(aegis128l_encrypt):
    // Load tag pointer (7th argument)
    mov r11, [rsp + 8]

    // Preserve AAD pointer and length for finalization
    mov r10, rdx      // r10 = aad_ptr
    mov rdx, rcx      // rdx = aad_len (preserved)
    // Preserve msg_len in r9 (do not clobber)

    // === Phase 1: Initialization ===
    movdqu xmm8, [rdi]       // xmm8 = key
    movdqu xmm9, [rsi]       // xmm9 = nonce

    // Load constants
    lea rax, [rip + AEGIS_C0]
    movdqu xmm10, [rax]      // xmm10 = C0
    lea rax, [rip + AEGIS_C1]
    movdqu xmm11, [rax]      // xmm11 = C1

    // S0 = key ^ nonce
    movdqa xmm0, xmm8
    pxor   xmm0, xmm9

    // S1 = C1
    movdqa xmm1, xmm11
    // S2 = C0
    movdqa xmm2, xmm10
    // S3 = C1
    movdqa xmm3, xmm11

    // S4 = key ^ nonce
    movdqa xmm4, xmm8
    pxor   xmm4, xmm9

    // S5 = key ^ C0
    movdqa xmm5, xmm8
    pxor   xmm5, xmm10

    // S6 = key ^ C1
    movdqa xmm6, xmm8
    pxor   xmm6, xmm11

    // S7 = key ^ C0
    movdqa xmm7, xmm8
    pxor   xmm7, xmm10

    // 10 init rounds: Update(nonce, key) (order matches ARM version contract)
    // Use: M0=nonce (xmm9), M1=key (xmm8)
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8

    // === Phase 2: Process AAD ===
    mov rdi, r10      // rdi = aad_ptr (cursor)
    mov rcx, rdx      // rcx = aad_remaining

.Laad_full_blocks_x86:
    cmp rcx, 32
    jl  .Laad_partial_x86

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp .Laad_full_blocks_x86

.Laad_partial_x86:
    test rcx, rcx
    jz   .Laad_done_x86

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of partial AAD data
// ║
// ║ Buffer MUST be pre-zeroized and immediately zeroized after use.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, 32

    // Pre-zeroize 32-byte buffer
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax

    // Copy rcx bytes from [rdi] to [rsp]
    mov rax, rcx            // save len for rewind if needed (not strictly needed here)
    lea rsi, [rsp]
.Laad_copy_loop_x86:
    test rcx, rcx
    jz   .Laad_copy_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Laad_copy_loop_x86
.Laad_copy_done_x86:

    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax
    add rsp, 32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Laad_done_x86:

    // === Phase 3: Encrypt plaintext ===
    mov rdi, r8       // rdi = data_ptr (cursor)
    mov rcx, r9       // rcx = data_remaining

.Lenc_full_blocks_x86:
    cmp rcx, 32
    jl  .Lenc_partial_x86

    // Load plaintext into xmm8/xmm9 (kept intact for state update)
    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]

    // z0 = S1 ^ S6 ^ (S2 & S3)
    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    // z1 = S2 ^ S5 ^ (S6 & S7)
    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

    // ciphertext = plaintext ^ keystream (write in xmm10/xmm11)
    pxor xmm10, xmm8
    pxor xmm11, xmm9

    // Store ciphertext in-place
    movdqu [rdi],      xmm10
    movdqu [rdi + 16], xmm11

    // Update state with plaintext
    AEGIS_UPDATE xmm8, xmm9

    add rdi, 32
    sub rcx, 32
    jmp .Lenc_full_blocks_x86

.Lenc_partial_x86:
    test rcx, rcx
    jz   .Lfinalize_x86

    // Generate keystream into xmm10/xmm11
    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: Temporary stack spill of partial PLAINTEXT data
// ║
// ║ Buffer MUST be pre-zeroized and immediately zeroized after use.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, 32

    // Pre-zeroize
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax

    // Copy rcx bytes plaintext -> stack buffer
    mov rax, rcx              // save len
    lea rsi, [rsp]
.Lenc_copy_pt_loop_x86:
    test rcx, rcx
    jz   .Lenc_copy_pt_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Lenc_copy_pt_loop_x86
.Lenc_copy_pt_done_x86:

    // Rewind rdi to start of partial block
    sub rdi, rax

    // Load padded plaintext into xmm8/xmm9
    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // ciphertext = plaintext ^ keystream -> xmm10/xmm11
    pxor xmm10, xmm8
    pxor xmm11, xmm9

    // Store ciphertext to stack buffer
    movdqu [rsp],      xmm10
    movdqu [rsp + 16], xmm11

    // Copy only 'rax' bytes ciphertext back in-place
    mov rcx, rax
    lea rsi, [rsp]
.Lenc_copy_ct_loop_x86:
    test rcx, rcx
    jz   .Lenc_copy_ct_done_x86
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .Lenc_copy_ct_loop_x86
.Lenc_copy_ct_done_x86:

    // Rewind rdi to end position (optional; not used further)
    // (cursor no longer used after partial)

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax
    add rsp, 32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext (xmm8/xmm9)
    AEGIS_UPDATE xmm8, xmm9

.Lfinalize_x86:
    // === Phase 4: Finalization and Tag Generation ===
    //
    // tmp = S2 ^ (le64(aad_bits) || le64(msg_bits))
    // Update(tmp, tmp) x 7
    // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6

    // aad_bits in rax, msg_bits in r10 (caller-saved)
    mov rax, rdx
    shl rax, 3
    mov r10, r9
    shl r10, 3

    // Build 128-bit lengths block in xmm8 without SSE4.1:
    // xmm8.low  = aad_bits (rax)
    // xmm9.low  = msg_bits (r10)
    // xmm8 = [aad_bits || msg_bits]
    movq xmm8, rax
    movq xmm9, r10
    punpcklqdq xmm8, xmm9

    // tmp ^= S2
    pxor xmm8, xmm2

    // 7 finalization rounds
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8

    // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    movdqa xmm8, xmm0
    pxor   xmm8, xmm1
    pxor   xmm8, xmm2
    pxor   xmm8, xmm3
    pxor   xmm8, xmm4
    pxor   xmm8, xmm5
    pxor   xmm8, xmm6

    // Write tag
    movdqu [r11], xmm8

    // Zeroize caller-saved regs
    AEGIS_ZEROIZE_ALL
    ret

// ============================================================================
// AEGIS-128L Decryption Function (Full support including partial blocks)
// ============================================================================
//
// IMPORTANT: This function does NOT perform constant-time tag comparison.
// The caller MUST compare tags in constant time and handle authentication
// failure appropriately (e.g., zeroize plaintext output on failure).
//
// SysV ABI params:
//   rdi = key ptr (16 bytes)
//   rsi = nonce ptr (16 bytes)
//   rdx = aad ptr
//   rcx = aad len (bytes)
//   r8  = ciphertext ptr (in-place -> plaintext)
//   r9  = ciphertext len (bytes)
//   [rsp+8]  = expected_tag ptr (16 bytes)   (unused here, for caller)
//   [rsp+16] = computed_tag_out ptr (16 bytes)
//
// Returns: void (computed tag written)
//
.global FUNC(aegis128l_decrypt)
HIDDEN_FUNC(aegis128l_decrypt)
.p2align 4
FUNC(aegis128l_decrypt):
    // Load stack arguments
    mov r11, [rsp + 8]     // expected_tag (not compared here)
    mov r10, [rsp + 16]    // computed_tag_out

    // Preserve AAD pointer and length for finalization
    mov rax, rdx           // rax = aad_ptr (preserved)
    mov rdx, rcx           // rdx = aad_len (preserved)
    // Preserve msg_len in r9 (do not clobber)

    // === Phase 1: Initialization ===
    movdqu xmm8, [rdi]     // key
    movdqu xmm9, [rsi]     // nonce

    lea rsi, [rip + AEGIS_C0]
    movdqu xmm10, [rsi]    // C0
    lea rsi, [rip + AEGIS_C1]
    movdqu xmm11, [rsi]    // C1

    movdqa xmm0, xmm8
    pxor   xmm0, xmm9

    movdqa xmm1, xmm11
    movdqa xmm2, xmm10
    movdqa xmm3, xmm11

    movdqa xmm4, xmm8
    pxor   xmm4, xmm9

    movdqa xmm5, xmm8
    pxor   xmm5, xmm10

    movdqa xmm6, xmm8
    pxor   xmm6, xmm11

    movdqa xmm7, xmm8
    pxor   xmm7, xmm10

    // 10 init rounds
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8
    AEGIS_UPDATE xmm9, xmm8

    // === Phase 2: Process AAD ===
    mov rdi, rax      // cursor = aad_ptr
    mov rcx, rdx      // remaining = aad_len

.Ldec_aad_full_blocks_x86:
    cmp rcx, 32
    jl  .Ldec_aad_partial_x86

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp .Ldec_aad_full_blocks_x86

.Ldec_aad_partial_x86:
    test rcx, rcx
    jz   .Ldec_aad_done_x86

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║ SECURITY WARNING: Temporary stack spill of partial AAD data
// ║ Buffer MUST be pre-zeroized and immediately zeroized after use.
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, 32

    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax

    lea rsi, [rsp]
.Ldec_aad_copy_loop_x86:
    test rcx, rcx
    jz   .Ldec_aad_copy_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Ldec_aad_copy_loop_x86
.Ldec_aad_copy_done_x86:

    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax
    add rsp, 32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Ldec_aad_done_x86:

    // === Phase 3: Decrypt ciphertext ===
    mov rdi, r8       // cursor = data
    mov rcx, r9       // remaining

.Ldec_full_blocks_x86:
    cmp rcx, 32
    jl  .Ldec_partial_x86

    // Load ciphertext into xmm8/xmm9
    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]

    // keystream z0 -> xmm10
    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    // keystream z1 -> xmm11
    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

    // plaintext = ciphertext ^ keystream (in-place xmm8/xmm9)
    pxor xmm8, xmm10
    pxor xmm9, xmm11

    // Store plaintext in-place
    movdqu [rdi],      xmm8
    movdqu [rdi + 16], xmm9

    // Update state with PLAINTEXT
    AEGIS_UPDATE xmm8, xmm9

    add rdi, 32
    sub rcx, 32
    jmp .Ldec_full_blocks_x86

.Ldec_partial_x86:
    test rcx, rcx
    jz   .Ldec_finalize_x86

    // keystream before spill
    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║ SECURITY WARNING: Temporary stack spill of CIPHERTEXT and PLAINTEXT
// ║ Buffer MUST be pre-zeroized and immediately zeroized after use.
// ║ WARNING: Buffer will contain DECRYPTED PLAINTEXT.
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, 32

    // Pre-zeroize
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax

    // Copy rcx bytes ciphertext -> buffer
    mov rax, rcx              // save len
    lea rsi, [rsp]
.Ldec_copy_ct_loop_x86:
    test rcx, rcx
    jz   .Ldec_copy_ct_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Ldec_copy_ct_loop_x86
.Ldec_copy_ct_done_x86:

    // Rewind rdi to start of partial block
    sub rdi, rax

    // Load padded ciphertext into xmm8/xmm9
    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // plaintext = ciphertext ^ keystream (xmm8/xmm9)
    pxor xmm8, xmm10
    pxor xmm9, xmm11

    // Store plaintext to buffer
    movdqu [rsp],      xmm8
    movdqu [rsp + 16], xmm9

    // Zero padding bytes beyond valid length so state absorbs padded-plaintext=0
    // (This is REQUIRED; otherwise keystream bytes would be absorbed as data.)
    lea rsi, [rsp]
    add rsi, rax              // rsi = buf + len
    mov rcx, 32
    sub rcx, rax
.Ldec_zero_pad_loop_x86:
    test rcx, rcx
    jz   .Ldec_zero_pad_done_x86
    mov byte ptr [rsi], 0
    inc rsi
    dec rcx
    jmp .Ldec_zero_pad_loop_x86
.Ldec_zero_pad_done_x86:

    // Copy plaintext first 'len' bytes back in-place
    mov rcx, rax
    lea rsi, [rsp]
.Ldec_copy_pt_loop_x86:
    test rcx, rcx
    jz   .Ldec_copy_pt_done_x86
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .Ldec_copy_pt_loop_x86
.Ldec_copy_pt_done_x86:

    // Reload padded plaintext for state update
    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    xor rax, rax
    mov [rsp +  0], rax
    mov [rsp +  8], rax
    mov [rsp + 16], rax
    mov [rsp + 24], rax
    add rsp, 32
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext
    AEGIS_UPDATE xmm8, xmm9

.Ldec_finalize_x86:
    // === Phase 4: Finalization and computed tag ===
    mov rax, rdx
    shl rax, 3
    mov r8, r9
    shl r8, 3

    movq xmm8, rax
    movq xmm9, r8
    punpcklqdq xmm8, xmm9
    pxor xmm8, xmm2

    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8
    AEGIS_UPDATE xmm8, xmm8

    movdqa xmm8, xmm0
    pxor   xmm8, xmm1
    pxor   xmm8, xmm2
    pxor   xmm8, xmm3
    pxor   xmm8, xmm4
    pxor   xmm8, xmm5
    pxor   xmm8, xmm6

    // Write computed tag
    movdqu [r10], xmm8

    AEGIS_ZEROIZE_ALL
    ret
