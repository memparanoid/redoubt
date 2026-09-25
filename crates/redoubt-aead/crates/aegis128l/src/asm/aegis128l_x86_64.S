// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L - x86_64 (SysV ABI) Implementation
//
// Eight 128-bit blocks of state, and the AES round function used as a
// permutation. The state lives in xmm0-xmm7 from the first instruction to the
// tag, and what does not fit a register — the tail of an AAD or a message that
// does not fill a block — goes through a frame this file names and empties.
//
// SSE2 and AES-NI, nothing else, and nothing detected at runtime. A machine
// without AES-NI does not answer wrong: the first `aesenc` is an illegal
// instruction. The build script assembles this for every SysV x86-64 target,
// so asking whether the machine has AES belongs to whoever chooses this AEAD.
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 leaves only xmm0-xmm5 caller-saved, fewer
//     than the state alone needs.
//
// Every argument is a pointer to storage the caller declared, except the
// lengths, which are public. Nothing is returned. `decrypt` writes the tag it
// computed and does not compare: the comparison is `redoubt-aead-core`'s, in
// constant time, and the tag the caller expected never arrives here.
//
// Nothing branches on a key, a nonce, a message or a tag. Every branch is on a
// length.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context, vectors included, to a frame on the user stack that nothing in
//   user space wipes. The same for a core dump, a page that reached swap, and
//   anything ptrace can read.
//
// References:
// - draft-irtf-cfrg-aegis-aead-17
// - Intel SDM, AESENC

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
// Shared constants
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
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through these two lists. A register added to the
// wipe and missing from the verifier is a register nothing looks at, silently.
//
// SysV AMD64 makes rax, rcx, rdx, rsi, rdi, r8-r11 and every xmm caller-saved,
// and rbx, rbp and r12-r15 callee-saved. Nothing here writes one of the second
// kind: saving one would spill the caller's value into this file's stack.
//
// The vector half is here because the state is: xmm0-xmm7 hold S0-S7, xmm8-xmm13
// the blocks absorbed and the round's temporaries. xmm14 and xmm15 are written
// by nothing and listed anyway, so the verifier still asks about them the day
// somebody reaches for a spare.
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

// Copies what xmm0 and rax already hold into each, themselves included. Used
// by the probe.
.macro AEGIS_FILL_VECTOR reg
    movdqa \reg, xmm0
.endm

.macro AEGIS_FILL_GENERAL reg
    mov \reg, rax
.endm

// Folds each half into xmm0 and rcx, which are in their lists and so contribute
// their own values. Used by the probe.
.macro AEGIS_GATHER_VECTOR reg
    por xmm0, \reg
.endm

.macro AEGIS_GATHER_GENERAL reg
    or rcx, \reg
.endm

.macro AEGIS_ZEROIZE_ALL
    AEGIS_EACH_VECTOR AEGIS_CLEAR_VECTOR
    AEGIS_EACH_GENERAL AEGIS_CLEAR_GENERAL
.endm

// ============================================================================
// Frame layout
// ============================================================================
//
// PARTIAL is one pair of blocks: the tail of an AAD or a message, padded with
// zeros. Each tail takes the frame and gives it back before the round that
// absorbs it.
//
// FRAME is congruent to eight modulo sixteen, the size every frame here has:
// `call` leaves rsp eight past a boundary, and a frame of that shape puts it
// back on one.
.set PARTIAL, 0
.set FRAME, 40

// ============================================================================
// Frame wipe
// ============================================================================

// Every qword of the frame, padding included. Run before a tail is written,
// so the zeros past it are the padding the standard asks for, and again on the
// way out.
.macro AEGIS_CLEAR_FRAME
    xor eax, eax
    .set _empty_at, 0
    .rept FRAME / 8
        mov qword ptr [rsp + _empty_at], rax
        .set _empty_at, _empty_at + 8
    .endr
.endm

.macro AEGIS_EMPTY_FRAME
    AEGIS_CLEAR_FRAME
    add rsp, FRAME
.endm

// ============================================================================
// Arithmetic macros
// ============================================================================

// One state update: S'i = AESRound(S(i-1), Si), with m0 folded into S0 and m1
// into S4. `aesenc a, b` is AESRound(a, b), SubBytes through MixColumns on a
// and b added as the round key.
//
// Written in place from S'7 down to S'1, so each reads S(i-1) before it is
// overwritten. S'0 needs the old S7, which is gone by then: xmm12 keeps it.
// xmm10 and xmm13 are scratch.
.macro AEGIS_UPDATE m0, m1
    movdqa xmm12, xmm7

    movdqa xmm13, xmm6
    aesenc xmm13, xmm7
    movdqa xmm7, xmm13

    movdqa xmm13, xmm5
    aesenc xmm13, xmm6
    movdqa xmm6, xmm13

    movdqa xmm13, xmm4
    aesenc xmm13, xmm5
    movdqa xmm5, xmm13

    movdqa xmm10, xmm4
    pxor   xmm10, \m1
    movdqa xmm13, xmm3
    aesenc xmm13, xmm10
    movdqa xmm4, xmm13

    movdqa xmm13, xmm2
    aesenc xmm13, xmm3
    movdqa xmm3, xmm13

    movdqa xmm13, xmm1
    aesenc xmm13, xmm2
    movdqa xmm2, xmm13

    movdqa xmm13, xmm0
    aesenc xmm13, xmm1
    movdqa xmm1, xmm13

    movdqa xmm10, xmm0
    pxor   xmm10, \m0
    movdqa xmm13, xmm12
    aesenc xmm13, xmm10
    movdqa xmm0, xmm13
.endm

// ============================================================================
// aegis128l_encrypt
// ============================================================================
//
// C signature:
//   void redoubt_aegis128l_encrypt(
//       const uint8_t key[16],
//       const uint8_t nonce[16],
//       const uint8_t *aad,
//       size_t         aad_len,
//       uint8_t       *data,
//       size_t         data_len,
//       uint8_t        tag[16]
//   );
//
// Parameters (SysV ABI):
//   rdi: key, rsi: nonce, rdx: aad, rcx: aad_len, r8: data, r9: data_len,
//   [rsp + 8]: tag, the seventh argument, which SysV passes on the stack.
//
// `data` is enciphered where it lies. The lengths are kept, rdx the AAD's and
// r9 the message's, until the tag is made from them.
.global FUNC(redoubt_aegis128l_encrypt)
HIDDEN_FUNC(redoubt_aegis128l_encrypt)
#if !defined(__APPLE__)
.type FUNC(redoubt_aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_encrypt):
    mov r11, [rsp + 8]

    mov r10, rdx
    mov rdx, rcx

    movdqu xmm8, [rdi]
    movdqu xmm9, [rsi]

    lea rax, [rip + AEGIS_C0]
    movdqu xmm10, [rax]
    lea rax, [rip + AEGIS_C1]
    movdqu xmm11, [rax]

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

    .rept 10
        AEGIS_UPDATE xmm9, xmm8
    .endr

    mov rdi, r10
    mov rcx, rdx

.Lenc_aad_whole:
    cmp rcx, 32
    jl  .Lenc_aad_tail

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp .Lenc_aad_whole

.Lenc_aad_tail:
    test rcx, rcx
    jz   .Lenc_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the AAD, padded here because
// ║ the caller's buffer has no room to pad in.
// ║
// ║ Frame is zeroized before the tail is written and again before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    AEGIS_CLEAR_FRAME

    lea rsi, [rsp + PARTIAL]
.Lenc_aad_copy:
    test rcx, rcx
    jz   .Lenc_aad_copied
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Lenc_aad_copy
.Lenc_aad_copied:

    movdqu xmm8, [rsp + PARTIAL]
    movdqu xmm9, [rsp + PARTIAL + 16]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Lenc_aad_done:
    mov rdi, r8
    mov rcx, r9

.Lenc_whole:
    cmp rcx, 32
    jl  .Lenc_tail

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]

    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

    pxor xmm10, xmm8
    pxor xmm11, xmm9

    movdqu [rdi],      xmm10
    movdqu [rdi + 16], xmm11

    AEGIS_UPDATE xmm8, xmm9

    add rdi, 32
    sub rcx, 32
    jmp .Lenc_whole

.Lenc_tail:
    test rcx, rcx
    jz   .Lenc_finalize

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
// ║ SECURITY WARNING: PARTIAL holds the tail of the message in the clear,
// ║ then the ciphertext it becomes, with keystream past the tail.
// ║
// ║ Frame is zeroized before the tail is written and again before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    AEGIS_CLEAR_FRAME

    mov r10, rcx
    lea rsi, [rsp + PARTIAL]
.Lenc_plaintext_copy:
    test rcx, rcx
    jz   .Lenc_plaintext_copied
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Lenc_plaintext_copy
.Lenc_plaintext_copied:

    sub rdi, r10

    movdqu xmm8, [rsp + PARTIAL]
    movdqu xmm9, [rsp + PARTIAL + 16]

    pxor xmm10, xmm8
    pxor xmm11, xmm9

    movdqu [rsp + PARTIAL],      xmm10
    movdqu [rsp + PARTIAL + 16], xmm11

    mov rcx, r10
    lea rsi, [rsp + PARTIAL]
.Lenc_ciphertext_copy:
    test rcx, rcx
    jz   .Lenc_ciphertext_copied
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .Lenc_ciphertext_copy
.Lenc_ciphertext_copied:

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Lenc_finalize:
    // The lengths in bits, le64(aad) || le64(message), folded into S2.
    mov rax, rdx
    shl rax, 3
    mov r10, r9
    shl r10, 3

    movq xmm8, rax
    movq xmm9, r10
    punpcklqdq xmm8, xmm9
    pxor xmm8, xmm2

    .rept 7
        AEGIS_UPDATE xmm8, xmm8
    .endr

    movdqa xmm8, xmm0
    pxor   xmm8, xmm1
    pxor   xmm8, xmm2
    pxor   xmm8, xmm3
    pxor   xmm8, xmm4
    pxor   xmm8, xmm5
    pxor   xmm8, xmm6

    movdqu [r11], xmm8

    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_aegis128l_encrypt), .-FUNC(redoubt_aegis128l_encrypt)
#endif

// ============================================================================
// aegis128l_decrypt
// ============================================================================
//
// C signature:
//   void redoubt_aegis128l_decrypt(
//       const uint8_t key[16],
//       const uint8_t nonce[16],
//       const uint8_t *aad,
//       size_t         aad_len,
//       uint8_t       *data,
//       size_t         data_len,
//       uint8_t        tag[16]
//   );
//
// Parameters (SysV ABI):
//   rdi: key, rsi: nonce, rdx: aad, rcx: aad_len, r8: data, r9: data_len,
//   [rsp + 8]: tag, the seventh argument, which SysV passes on the stack.
//
// `data` is deciphered where it lies, and `tag` is written with the tag it
// deserves. Until the caller has compared, `data` is a plaintext nothing has
// vouched for.
.global FUNC(redoubt_aegis128l_decrypt)
HIDDEN_FUNC(redoubt_aegis128l_decrypt)
#if !defined(__APPLE__)
.type FUNC(redoubt_aegis128l_decrypt), @function
#endif
.p2align 4
FUNC(redoubt_aegis128l_decrypt):
    mov r10, [rsp + 8]

    mov rax, rdx
    mov rdx, rcx

    movdqu xmm8, [rdi]
    movdqu xmm9, [rsi]

    lea rsi, [rip + AEGIS_C0]
    movdqu xmm10, [rsi]
    lea rsi, [rip + AEGIS_C1]
    movdqu xmm11, [rsi]

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

    .rept 10
        AEGIS_UPDATE xmm9, xmm8
    .endr

    mov rdi, rax
    mov rcx, rdx

.Ldec_aad_whole:
    cmp rcx, 32
    jl  .Ldec_aad_tail

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]
    add rdi, 32
    sub rcx, 32
    AEGIS_UPDATE xmm8, xmm9
    jmp .Ldec_aad_whole

.Ldec_aad_tail:
    test rcx, rcx
    jz   .Ldec_aad_done

// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: PARTIAL holds the tail of the AAD, padded here because
// ║ the caller's buffer has no room to pad in.
// ║
// ║ Frame is zeroized before the tail is written and again before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    AEGIS_CLEAR_FRAME

    lea rsi, [rsp + PARTIAL]
.Ldec_aad_copy:
    test rcx, rcx
    jz   .Ldec_aad_copied
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Ldec_aad_copy
.Ldec_aad_copied:

    movdqu xmm8, [rsp + PARTIAL]
    movdqu xmm9, [rsp + PARTIAL + 16]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Ldec_aad_done:
    mov rdi, r8
    mov rcx, r9

.Ldec_whole:
    cmp rcx, 32
    jl  .Ldec_tail

    movdqu xmm8, [rdi]
    movdqu xmm9, [rdi + 16]

    movdqa xmm10, xmm2
    pand  xmm10, xmm3
    pxor  xmm10, xmm1
    pxor  xmm10, xmm6

    movdqa xmm11, xmm6
    pand  xmm11, xmm7
    pxor  xmm11, xmm2
    pxor  xmm11, xmm5

    pxor xmm8, xmm10
    pxor xmm9, xmm11

    movdqu [rdi],      xmm8
    movdqu [rdi + 16], xmm9

    AEGIS_UPDATE xmm8, xmm9

    add rdi, 32
    sub rcx, 32
    jmp .Ldec_whole

.Ldec_tail:
    test rcx, rcx
    jz   .Ldec_finalize

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
// ║ SECURITY WARNING: PARTIAL holds the tail of the ciphertext, then the
// ║ plaintext it deciphers into — a plaintext the caller has not
// ║ authenticated yet.
// ║
// ║ Frame is zeroized before the tail is written and again before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    AEGIS_CLEAR_FRAME

    mov r11, rcx
    lea rsi, [rsp + PARTIAL]
.Ldec_ciphertext_copy:
    test rcx, rcx
    jz   .Ldec_ciphertext_copied
    mov al, byte ptr [rdi]
    mov byte ptr [rsi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .Ldec_ciphertext_copy
.Ldec_ciphertext_copied:

    sub rdi, r11

    movdqu xmm8, [rsp + PARTIAL]
    movdqu xmm9, [rsp + PARTIAL + 16]

    pxor xmm8, xmm10
    pxor xmm9, xmm11

    movdqu [rsp + PARTIAL],      xmm8
    movdqu [rsp + PARTIAL + 16], xmm9

    // Past the tail the xor left keystream, and the state absorbs the plaintext
    // padded with zeros.
    lea rsi, [rsp + PARTIAL]
    add rsi, r11
    mov rcx, 32
    sub rcx, r11
.Ldec_padding_empty:
    test rcx, rcx
    jz   .Ldec_padding_emptied
    mov byte ptr [rsi], 0
    inc rsi
    dec rcx
    jmp .Ldec_padding_empty
.Ldec_padding_emptied:

    mov rcx, r11
    lea rsi, [rsp + PARTIAL]
.Ldec_plaintext_copy:
    test rcx, rcx
    jz   .Ldec_plaintext_copied
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .Ldec_plaintext_copy
.Ldec_plaintext_copied:

    movdqu xmm8, [rsp + PARTIAL]
    movdqu xmm9, [rsp + PARTIAL + 16]

    AEGIS_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    AEGIS_UPDATE xmm8, xmm9

.Ldec_finalize:
    // The lengths in bits, le64(aad) || le64(message), folded into S2.
    mov rax, rdx
    shl rax, 3
    mov r8, r9
    shl r8, 3

    movq xmm8, rax
    movq xmm9, r8
    punpcklqdq xmm8, xmm9
    pxor xmm8, xmm2

    .rept 7
        AEGIS_UPDATE xmm8, xmm8
    .endr

    movdqa xmm8, xmm0
    pxor   xmm8, xmm1
    pxor   xmm8, xmm2
    pxor   xmm8, xmm3
    pxor   xmm8, xmm4
    pxor   xmm8, xmm5
    pxor   xmm8, xmm6

    movdqu [r10], xmm8

    AEGIS_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_aegis128l_decrypt), .-FUNC(redoubt_aegis128l_decrypt)
#endif

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_aegis128l_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because rdi is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
//
// The generals are gathered first, so rax is read before it carries the answer.
// The halves of the vector fold are or-ed together into the one word that
// leaves: which half a bit came from is lost, whether there was one is not.
.p2align 4
.global FUNC(redoubt_aegis128l_registers_are_zeroized)
HIDDEN_FUNC(redoubt_aegis128l_registers_are_zeroized)
FUNC(redoubt_aegis128l_registers_are_zeroized):
    AEGIS_EACH_GENERAL AEGIS_GATHER_GENERAL
    AEGIS_EACH_VECTOR AEGIS_GATHER_VECTOR

    movdqa xmm1, xmm0
    psrldq xmm1, 8
    por xmm0, xmm1

    movq rax, xmm0
    or rax, rcx
    ret

// Every register in the budget filled with a pattern, and left that way. Both
// halves of each vector, so a verifier that read only one still finds it.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_registers)
HIDDEN_FUNC(redoubt_aegis128l_dirty_registers)
FUNC(redoubt_aegis128l_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    punpcklqdq xmm0, xmm0
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    AEGIS_EACH_GENERAL AEGIS_FILL_GENERAL
    ret

// The low half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only be those halves.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_vector_low)
HIDDEN_FUNC(redoubt_aegis128l_dirty_vector_low)
FUNC(redoubt_aegis128l_dirty_vector_low):
    AEGIS_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    xor eax, eax
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    ret

// The high half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only come through its
// fold.
.p2align 4
.global FUNC(redoubt_aegis128l_dirty_vector_high)
HIDDEN_FUNC(redoubt_aegis128l_dirty_vector_high)
FUNC(redoubt_aegis128l_dirty_vector_high):
    AEGIS_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    pslldq xmm0, 8
    xor eax, eax
    AEGIS_EACH_VECTOR AEGIS_FILL_VECTOR
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_aegis128l_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `call`
//   leaves rsp where the previous callee found it, so the return address lands
//   in the same slot and `[rsp - \size, rsp)` is the frame that callee took.
//   Asked after the registers, never before: reading the frame takes registers.
//
// void redoubt_aegis128l_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in rdi, marked and left.
//
// void redoubt_aegis128l_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro AEGIS_FRAME_PROBE name, size
.p2align 4
.global FUNC(redoubt_aegis128l_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_aegis128l_frame_is_zeroized_\name)
FUNC(redoubt_aegis128l_frame_is_zeroized_\name):
    // An x86 address cannot subtract a register, so the index runs up from
    // minus the frame to zero.
    xor eax, eax
    mov rcx, -\size
1:
    or rax, [rsp + rcx]
    add rcx, 8
    jnz 1b
    ret

.p2align 4
.global FUNC(redoubt_aegis128l_dirty_frame_\name)
HIDDEN_FUNC(redoubt_aegis128l_dirty_frame_\name)
FUNC(redoubt_aegis128l_dirty_frame_\name):
    sub rsp, \size
    // The frame is emptied before the byte goes in, so that what a verifier
    // finds is this byte and not a previous call's residue.
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
.global FUNC(redoubt_aegis128l_clean_frame_\name)
HIDDEN_FUNC(redoubt_aegis128l_clean_frame_\name)
FUNC(redoubt_aegis128l_clean_frame_\name):
    sub rsp, \size
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
3:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, \size
    jb 3b
    AEGIS_EMPTY_FRAME
    AEGIS_ZEROIZE_ALL
    ret
.endm

AEGIS_FRAME_PROBE aegis128l, FRAME

// ============================================================================
// Stack permissions
// ============================================================================
//
// An object with no .note.GNU-stack is one the linker assumes wants an
// executable stack, and one such object gives it to the whole binary. Nothing
// here needs one.
#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
