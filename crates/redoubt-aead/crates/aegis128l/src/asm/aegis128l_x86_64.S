// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L AEAD Cipher - x86_64 (SysV ABI) Implementation
//
// The state is eight blocks of a hundred and twenty-eight bits, and the round
// function is the AES one — `aesenc`, taken as a permutation rather than as a
// cipher.
//
// What this file needs and does not ask for:
//   AES-NI. There is no detection here and no fallback, because a fallback
//   would be a different algorithm with the same name. A machine without it
//   does not answer wrong, it stops: the first `aesenc` is an illegal
//   instruction. The build script compiles this wherever the ABI fits, so the
//   symbols exist on every SysV x86-64 target — which makes asking whether the
//   machine has AES somebody's job, and that somebody is whatever chooses this
//   AEAD over another. One question, asked once, where the choice is made.
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
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes its first arguments in other
//     registers and leaves only xmm0-xmm5 caller-saved, which is fewer than
//     the state alone needs. This file is SysV throughout, and a target without
//     it gets no AEGIS at all rather than a slower one.
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
//   something this file never reads is a pointer the caller pushes for nothing,
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
// The register budget
// ============================================================================
//
// SysV AMD64 ABI:
//   - Caller-saved GPR: rax, rcx, rdx, rsi, rdi, r8-r11
//   - Callee-saved GPR: rbx, rbp, r12-r15  (DO NOT TOUCH)
//   - Every xmm is caller-saved
//
// Every register these routines put anything in is named once, below, and
// every operation over the set goes through that one list. Emptying them and
// asking whether they are empty are the same registers by construction, not by
// two lists that happen to agree today.
//
// The SIMD half is here and not excluded, which is the one place this file
// parts company with the other primitives in this workspace. Theirs never write
// an xmm, so clearing one would be clearing a register they never touched;
// AEGIS is the AES round function used as a permutation, so the whole state
// lives there and nowhere else.
//
// xmm14 and xmm15 are in the list and nothing writes them. Two `pxor` against
// the day somebody reaches for a spare register and the verifier, asked about
// fourteen, says nothing about it.
//
// Does NOT include: rsp, rbx, rbp, r12-r15. Nothing here puts anything in them,
// so there is nothing of ours to clear — and no prologue saving them, which
// means no copy of the caller's values in memory for an epilogue to take back
// out.
//
// What each one holds. Both routines use the same allocation, and the peak live
// vector set is thirteen against a budget of sixteen:
//
//   xmm0-xmm7    the state, S0 to S7, live from init to the tag
//   xmm8-xmm9    the pair of blocks being absorbed — AAD, plaintext, ciphertext
//   xmm10-xmm11  scratch and keystream; the two constants at init
//   xmm12        AEGIS_UPDATE: the old S7, which S'0 is made from
//   xmm13        AEGIS_UPDATE: the AES working register
//   xmm14-xmm15  nothing writes them, and see above for why they are listed
//
//   rdi, rsi     the key and the nonce on the way in, then cursors
//   rdx          how long the AAD was, kept until the tag needs it
//   rcx          what is left of whatever is being walked
//   r8, r9       the message and its length, kept until the tag needs it
//   r10, r11     where the tag goes, and the lengths in bits it is made from
//   rax          lengths and constants on their way somewhere else
.macro AEGIS_EACH_VECTOR op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        \op xmm\reg
    .endr
.endm

.macro AEGIS_EACH_GENERAL op
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

.macro AEGIS_CLEAR_VECTOR reg
    pxor \reg, \reg
.endm

.macro AEGIS_CLEAR_GENERAL reg
    xor \reg, \reg
.endm

// Gathers into the first of each half, which is in its own list and therefore
// contributes its own value on its own line. Only the probe below uses these,
// and they are here rather than there so that the budget and everything done to
// it sit together.
.macro AEGIS_GATHER_VECTOR reg
    por xmm0, \reg
.endm

.macro AEGIS_GATHER_GENERAL reg
    or rcx, \reg
.endm

// Copies what rax and xmm0 already hold into each of them, the two sources
// included and harmless.
.macro AEGIS_FILL_VECTOR reg
    movdqa \reg, xmm0
.endm

.macro AEGIS_FILL_GENERAL reg
    mov \reg, rax
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro AEGIS_ZEROIZE_ALL
    AEGIS_EACH_VECTOR AEGIS_CLEAR_VECTOR
    AEGIS_EACH_GENERAL AEGIS_CLEAR_GENERAL
.endm

// ============================================================================
// Frame layout — 32 bytes, entirely above rsp
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
    xor rax, rax
    mov [rsp + PARTIAL +  0], rax
    mov [rsp + PARTIAL +  8], rax
    mov [rsp + PARTIAL + 16], rax
    mov [rsp + PARTIAL + 24], rax
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
// PRECONDITION: None (all temporaries initialized within macro)
//
// Schedule safety: In-place descending update (S'7→S'1) ensures each S'i
// reads S_{i-1} before it's overwritten. S'0 requires old S7 (saved in xmm12 first).
//
// AES-NI mapping:
//   aesenc dst, rk  performs SubBytes + ShiftRows + MixColumns + AddRoundKey(rk).
//   Therefore: AESRound(A, B) == aesenc(A, B) with A as data, B as "round key".
//
.macro AEGIS_UPDATE m0, m1
    // Preserve old S7 for S'0 (S7 is overwritten early in the in-place schedule)
    movdqa xmm12, xmm7

    // ---- Compute S'7..S'1 in descending order (in-place safe) ----
    //
    // Schedule safety: Each S'i = AESRound(S_{i-1}, S_i)
    //   - Reads S_{i-1} and S_i BEFORE overwriting S_i
    //   - Descending order ensures S_{i-1} not yet overwritten when needed
    //   - Example: S'7 reads S6,S7 → overwrites S7 → S'6 reads S5,S6 (S6 intact)
    //
    // Exception: S'0 = AESRound(S7, S0^M0) needs OLD S7 → saved in xmm12 first

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

    // ---- Compute S'0 last (requires old S7 and old S0) ----

    // S'0 = AESRound(old S7, S0 ^ M0)
    movdqa xmm10, xmm0
    pxor   xmm10, \m0
    movdqa xmm13, xmm12
    aesenc xmm13, xmm10
    movdqa xmm0, xmm13
.endm

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
.global FUNC(redoubt_aegis128l_encrypt)
HIDDEN_FUNC(redoubt_aegis128l_encrypt)
.p2align 4
FUNC(redoubt_aegis128l_encrypt):
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

Laad_full_blocks_x86:
    cmp rcx, 32
    jl  Laad_partial_x86

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp Laad_full_blocks_x86

Laad_partial_x86:
    test rcx, rcx
    jz   Laad_done_x86

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the AAD, the bytes that did
// ║ not fill a block, padded here because the caller's buffer has no room to
// ║ pad in.
// ║
// ║ Frame is emptied before it is written and emptied again before rsp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME

    // Pre-zeroize 32-byte buffer
    AEGIS_EMPTY_FRAME

    // Copy rcx bytes from [rdi] to [rsp]
    lea rsi, [rsp]
Laad_copy_loop_x86:
    test rcx, rcx
    jz   Laad_copy_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp Laad_copy_loop_x86
Laad_copy_done_x86:

    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    AEGIS_EMPTY_FRAME
    add rsp, FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

Laad_done_x86:

    // === Phase 3: Encrypt plaintext ===
    mov rdi, r8       // rdi = data_ptr (cursor)
    mov rcx, r9       // rcx = data_remaining

Lenc_full_blocks_x86:
    cmp rcx, 32
    jl  Lenc_partial_x86

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
    jmp Lenc_full_blocks_x86

Lenc_partial_x86:
    test rcx, rcx
    jz   Lfinalize_x86

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
// ║ SECURITY WARNING: the frame holds the tail of the message in the clear —
// ║ plaintext on the way in, and the ciphertext it becomes on the way out.
// ║
// ║ Frame is emptied before it is written and emptied again before rsp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME

    // Pre-zeroize
    AEGIS_EMPTY_FRAME

    // Copy rcx bytes plaintext -> stack buffer
    mov r10, rcx              // save len in r10 (caller-saved)
    lea rsi, [rsp]
Lenc_copy_pt_loop_x86:
    test rcx, rcx
    jz   Lenc_copy_pt_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp Lenc_copy_pt_loop_x86
Lenc_copy_pt_done_x86:

    // Rewind rdi to start of partial block
    sub rdi, r10

    // Load padded plaintext into xmm8/xmm9
    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // ciphertext = plaintext ^ keystream -> xmm10/xmm11
    pxor xmm10, xmm8
    pxor xmm11, xmm9

    // Store ciphertext to stack buffer
    movdqu [rsp],      xmm10
    movdqu [rsp + 16], xmm11

    // Copy only 'r10' bytes ciphertext back in-place
    mov rcx, r10
    lea rsi, [rsp]
Lenc_copy_ct_loop_x86:
    test rcx, rcx
    jz   Lenc_copy_ct_done_x86
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp Lenc_copy_ct_loop_x86
Lenc_copy_ct_done_x86:

    // Rewind rdi to end position (optional; not used further)
    // (cursor no longer used after partial)

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    AEGIS_EMPTY_FRAME
    add rsp, FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext (xmm8/xmm9)
    AEGIS_UPDATE xmm8, xmm9

Lfinalize_x86:
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
//   [rsp+8] = computed_tag_out ptr (16 bytes)
//
// The tag the caller expected does not arrive here. It would be a pointer this
// routine loads and never reads — and the comparison it exists for is not ours
// to make, for the reason above.
//
// Returns: void (computed tag written)
//
.global FUNC(redoubt_aegis128l_decrypt)
HIDDEN_FUNC(redoubt_aegis128l_decrypt)
.p2align 4
FUNC(redoubt_aegis128l_decrypt):
    // Load the stack argument
    mov r10, [rsp + 8]     // computed_tag_out

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

Ldec_aad_full_blocks_x86:
    cmp rcx, 32
    jl  Ldec_aad_partial_x86

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp Ldec_aad_full_blocks_x86

Ldec_aad_partial_x86:
    test rcx, rcx
    jz   Ldec_aad_done_x86

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: the frame holds the tail of the AAD, the bytes that did
// ║ not fill a block, padded here because the caller's buffer has no room to
// ║ pad in.
// ║
// ║ Frame is emptied before it is written and emptied again before rsp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME

    AEGIS_EMPTY_FRAME

    lea rsi, [rsp]
Ldec_aad_copy_loop_x86:
    test rcx, rcx
    jz   Ldec_aad_copy_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp Ldec_aad_copy_loop_x86
Ldec_aad_copy_done_x86:

    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    AEGIS_EMPTY_FRAME
    add rsp, FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

Ldec_aad_done_x86:

    // === Phase 3: Decrypt ciphertext ===
    mov rdi, r8       // cursor = data
    mov rcx, r9       // remaining

Ldec_full_blocks_x86:
    cmp rcx, 32
    jl  Ldec_partial_x86

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
    jmp Ldec_full_blocks_x86

Ldec_partial_x86:
    test rcx, rcx
    jz   Ldec_finalize_x86

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
// ║
// ║ SECURITY WARNING: the frame holds the tail of the message — the ciphertext
// ║ on the way in, and the plaintext it is deciphered into on the way out. This
// ║ is the one region in either routine that holds a plaintext the caller has
// ║ not authenticated yet.
// ║
// ║ Frame is emptied before it is written and emptied again before rsp is
// ║ advanced, so the second use cannot see what the first left.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME

    // Pre-zeroize
    AEGIS_EMPTY_FRAME

    // Copy rcx bytes ciphertext -> buffer
    mov r11, rcx              // save len in r11
    lea rsi, [rsp]
Ldec_copy_ct_loop_x86:
    test rcx, rcx
    jz   Ldec_copy_ct_done_x86
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp Ldec_copy_ct_loop_x86
Ldec_copy_ct_done_x86:

    // Rewind rdi to start of partial block
    sub rdi, r11

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
    add rsi, r11              // rsi = buf + len
    mov rcx, 32
    sub rcx, r11
Ldec_zero_pad_loop_x86:
    test rcx, rcx
    jz   Ldec_zero_pad_done_x86
    mov byte ptr [rsi], 0
    inc rsi
    dec rcx
    jmp Ldec_zero_pad_loop_x86
Ldec_zero_pad_done_x86:

    // Copy plaintext first 'len' bytes back in-place
    mov rcx, r11
    lea rsi, [rsp]
Ldec_copy_pt_loop_x86:
    test rcx, rcx
    jz   Ldec_copy_pt_done_x86
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp Ldec_copy_pt_loop_x86
Ldec_copy_pt_done_x86:

    // Reload padded plaintext for state update
    movdqu xmm8, [rsp]
    movdqu xmm9, [rsp + 16]

    // >>> ZEROIZATION OF SPILL BUFFER HAPPENS HERE <<<
    AEGIS_EMPTY_FRAME
    add rsp, FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    // Update state with zero-padded plaintext
    AEGIS_UPDATE xmm8, xmm9

Ldec_finalize_x86:
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
// whole of it. The general registers go into rcx first, so that rax's own value
// is read before the vector half needs rax to carry its answer out. A vector
// register is a hundred and twenty-eight bits and the answer is sixty-four, so
// the two halves of the fold are or-ed together before it leaves — what is lost
// is which half a bit came from, and what is kept is whether there was one.
//
// Takes no argument on purpose. A destination passed in would cost rdi, and
// rdi is one of the registers being asked about — it would arrive holding our
// own pointer rather than the caller's value.
.p2align 4
.global FUNC(redoubt_aegis128l_registers_are_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_registers_are_zeroized)
FUNC(redoubt_aegis128l_registers_are_zeroized):
    AEGIS_EACH_GENERAL AEGIS_GATHER_GENERAL
    AEGIS_EACH_VECTOR AEGIS_GATHER_VECTOR

    // xmm1 is folded in already, so borrowing it to bring the top half of the
    // fold down costs nothing.
    movdqa xmm1, xmm0
    psrldq xmm1, 8
    por xmm0, xmm1

    movq rax, xmm0
    or rax, rcx
    ret

// uint64_t redoubt_aegis128l_frame_is_zeroized(void)
//
// Whether any byte of the frame the call before it used is still holding
// something. Zero when it is all empty, and the bits of whatever was not.
//
// Reads below its own rsp, and that is the whole of it: `call` leaves rsp
// where the routine before had it, so what sits under this one's return
// address is what sat under that one's — the frame it took and gave back.
//
// Asked after the registers, never before: reading the frame takes registers,
// and the answer about those has to be taken first.
.p2align 4
.global FUNC(redoubt_aegis128l_frame_is_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_frame_is_zeroized)
FUNC(redoubt_aegis128l_frame_is_zeroized):
    // The index counts up from minus the frame to zero. x86 addresses with a
    // base plus an index, never a base minus one, so what reaches below rsp is
    // an index holding a negative number rather than a subtraction.
    xor eax, eax
    mov rcx, -FRAME
Lframe_scan_x86:
    or rax, [rsp + rcx]
    add rcx, 8
    jnz Lframe_scan_x86
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_registers)
HIDDEN_FUNC(redoubt_aegis128l_dirty_registers)
FUNC(redoubt_aegis128l_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    // Both halves of the vector, so a verifier that read only one still finds
    // the poison where it looked.
    punpcklqdq xmm0, xmm0
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    AEGIS_EACH_GENERAL AEGIS_FILL_GENERAL
    ret

// One byte of the frame, dirtied and left. rdi says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// the return address sitting next door would show.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_frame)
HIDDEN_FUNC(redoubt_aegis128l_dirty_frame)
FUNC(redoubt_aegis128l_dirty_frame):
    sub rsp, FRAME
    // Isolate this byte from every previous call's residue. Keep rdi, the
    // requested offset, intact until the whole frame is empty.
    AEGIS_EMPTY_FRAME
    mov byte ptr [rsp + rdi], 0x5c
    add rsp, FRAME
    ret

// The whole frame written and then emptied.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.global FUNC(redoubt_aegis128l_clean_frame)
HIDDEN_FUNC(redoubt_aegis128l_clean_frame)
FUNC(redoubt_aegis128l_clean_frame):
    sub rsp, FRAME
    mov rax, 0x5c5c5c5c5c5c5c5c
    mov [rsp + PARTIAL +  0], rax
    mov [rsp + PARTIAL +  8], rax
    mov [rsp + PARTIAL + 16], rax
    mov [rsp + PARTIAL + 24], rax
    AEGIS_EMPTY_FRAME
    add rsp, FRAME
    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
