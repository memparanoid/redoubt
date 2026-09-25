// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// SHA-256, HMAC-SHA256 and HKDF-SHA256 - x86_64 (SysV ABI) Implementation
//
// The floor is SSSE3 and SSE4.1, not the x86-64 baseline: `pshufb` and
// `palignr` are SSSE3, and `pextrd`, `pinsrd` and `pextrq` are SSE4.1. Nothing
// is detected at runtime, so a processor without them raises an illegal
// instruction, and `build.rs` compiles this for every x86_64 target that is not
// Windows.
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes arguments in other registers and
//     keeps xmm6-xmm15 callee-saved. The build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// lengths, which are public. Nothing is returned.
//
// Nothing branches on a secret: the block loop and the padding branch on
// lengths only.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context to a frame on the user stack that nothing in user space wipes. The
//   same for a core dump, a page that reached swap, and anything ptrace can
//   read.
//
// References:
// - FIPS 180-4, section 6.2
// - RFC 2104 (HMAC), RFC 5869 (HKDF)

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
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through these two lists. A register added to the
// wipe and missing from the verifier is a register nothing looks at, silently.
//
// SysV AMD64 makes rax, rcx, rdx, rsi, rdi, r8-r11 and every xmm caller-saved,
// and rbx, rbp and r12-r15 callee-saved. Nothing here writes one of the second
// kind: saving one would spill the caller's value into this file's stack. What
// has to outlive a call goes in the routine's own frame instead.
//
// The compression writes xmm0-xmm13. xmm14 and xmm15 are written by nothing and
// listed anyway, so the verifier still asks about them the day somebody reaches
// for a spare.
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
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        \op xmm\reg
    .endr
.endm

.macro HKDF_CLEAR_GPR reg
    xor \reg, \reg
.endm

.macro HKDF_CLEAR_VECTOR reg
    pxor \reg, \reg
.endm

// Copies what rax and xmm0 already hold into each, themselves included. Used
// by the probe.
.macro HKDF_FILL_GPR reg
    mov \reg, rax
.endm

.macro HKDF_FILL_VECTOR reg
    movdqa \reg, xmm0
.endm

// Folds each half into rcx and xmm0, which are in their lists and so contribute
// their own values. Used by the probe.
.macro HKDF_GATHER_GPR reg
    or rcx, \reg
.endm

.macro HKDF_GATHER_VECTOR reg
    por xmm0, \reg
.endm

.macro HKDF_SHA256_ZEROIZE_ALL
    HKDF_EACH_GPR HKDF_CLEAR_GPR
    HKDF_EACH_VECTOR HKDF_CLEAR_VECTOR
.endm

// ============================================================================
// The frames
// ============================================================================
//
// One table per routine, with its size last; that size is the only place the
// number is written. Not one shared size: the compression runs once per block
// of every message, and a shared width would make it pay the HKDF frame.
//
// Every size is congruent to eight modulo sixteen: `call` leaves rsp eight
// past a boundary, and a frame of that shape puts it back on one for the
// sixteen-byte moves and the calls below.

// sha256_compress_block: the message schedule, and the caller's H pointer.
.set COMPRESS_W, 0
.set COMPRESS_HPTR, 64
.set FRAME_COMPRESS, 72

// sha256_hash: the chaining state, the padded tail, and the arguments that
// have to outlive a call to the compression.
.set HASH_H, 0
.set HASH_BLOCK1, 32
.set HASH_BLOCK2, 96
.set HASH_MSG, 160
.set HASH_LEFT, 168
.set HASH_TOTAL, 176
.set HASH_DIGEST, 184
.set FRAME_HASH, 200

// sha256_update_finalize: the same, over a state the caller hands in.
.set UPDATE_H, 0
.set UPDATE_BLOCK1, 32
.set UPDATE_BLOCK2, 96
.set UPDATE_MSG, 160
.set UPDATE_LEFT, 168
.set UPDATE_TOTAL, 176
.set UPDATE_DIGEST, 184
.set FRAME_UPDATE, 200

// hmac_sha256: the key padded to a block, the inner and outer pads, the inner
// digest, the key hashed down when it is longer than a block, the chaining
// state, and the arguments.
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

// sha256_absorb: the arguments, which have to outlive the compression.
.set ABSORB_H, 0
.set ABSORB_SRC, 8
.set ABSORB_LEFT, 16
.set ABSORB_BLOCK, 24
.set ABSORB_FILL, 32
.set FRAME_ABSORB, 40

// hkdf_sha256: the extracted key, the inner and outer pads built from it once,
// the block being filled, the chaining state, the inner digest, the block of
// output being made, the counters, and the arguments.
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

// ============================================================================
// Frame wipe
// ============================================================================

// Every qword of a frame of `size` bytes, then the frame given back. Every call
// site names the same constant its `sub rsp` did.
.macro HKDF_EMPTY_FRAME size
    xor eax, eax
    .set _empty_at, 0
    .rept \size / 8
        mov qword ptr [rsp + _empty_at], rax
        .set _empty_at, _empty_at + 8
    .endr
    add rsp, \size
.endm

// ============================================================================
// sha256_compress_block
// ============================================================================
//
// C signature:
//   void redoubt_sha256_compress_block(uint32_t H[8], const uint8_t block[64]);
//
// Parameters (SysV ABI):
//   rdi: H (read and written), rsi: block (read only, big-endian)
//
// H := H + SHA256_COMPRESS(block). The working words live in xmm2 and xmm3, the
// last sixteen schedule words in xmm4-xmm7.
.global FUNC(redoubt_sha256_compress_block)
HIDDEN_FUNC(redoubt_sha256_compress_block)
#if !defined(__APPLE__)
.type FUNC(redoubt_sha256_compress_block), @function
#endif
.p2align 4
FUNC(redoubt_sha256_compress_block):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: COMPRESS_W holds the block byte-swapped, and then each
// ║ schedule word as it is made from it — for a key, the key in the clear.
// ║ COMPRESS_HPTR holds the caller's pointer, which is no secret.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_COMPRESS

    mov [rsp + COMPRESS_HPTR], rdi

    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]

    movdqu xmm4, [rsi]
    movdqu xmm5, [rsi + 16]
    movdqu xmm6, [rsi + 32]
    movdqu xmm7, [rsi + 48]

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

    movdqa [rsp + COMPRESS_W], xmm4
    movdqa [rsp + COMPRESS_W + 16], xmm5
    movdqa [rsp + COMPRESS_W + 32], xmm6
    movdqa [rsp + COMPRESS_W + 48], xmm7

    movdqa xmm2, xmm0
    movdqa xmm3, xmm1

#if defined(__APPLE__)
    lea rcx, [rip + .LK256]
#else
    lea rcx, .LK256[rip]
#endif

    xor rdx, rdx

.Lround_0_15:

    pextrd esi, xmm3, 3
    pextrd eax, xmm3, 0
    pextrd r11d, xmm3, 1
    pextrd edi, xmm3, 2

    mov r10d, eax
    ror r10d, 6
    mov r9d, eax
    ror r9d, 11
    xor r10d, r9d
    mov r9d, eax
    ror r9d, 25
    xor r10d, r9d
    add esi, r10d

    mov r10d, eax
    not r10d
    and r10d, edi
    mov r9d, eax
    and r9d, r11d
    xor r10d, r9d
    add esi, r10d

    add esi, [rcx + rdx*4]
    add esi, [rsp + COMPRESS_W + rdx*4]

    pextrd eax, xmm2, 0
    pextrd r10d, xmm2, 1
    pextrd r11d, xmm2, 2

    mov r8d, eax
    ror r8d, 2
    mov r9d, eax
    ror r9d, 13
    xor r8d, r9d
    mov r9d, eax
    ror r9d, 22
    xor r8d, r9d

    mov edi, eax
    and edi, r10d
    mov r9d, eax
    and r9d, r11d
    xor edi, r9d
    mov r9d, r10d
    and r9d, r11d
    xor edi, r9d

    add r8d, edi

    pextrd r10d, xmm2, 3
    add r10d, esi
    add esi, r8d

    pextrd r8d, xmm3, 0
    pextrd r9d, xmm3, 1
    pextrd r11d, xmm3, 2

    pinsrd xmm3, r10d, 0
    pinsrd xmm3, r8d, 1
    pinsrd xmm3, r9d, 2
    pinsrd xmm3, r11d, 3

    pextrd r8d, xmm2, 0
    pextrd r9d, xmm2, 1
    pextrd r11d, xmm2, 2

    pinsrd xmm2, esi, 0
    pinsrd xmm2, r8d, 1
    pinsrd xmm2, r9d, 2
    pinsrd xmm2, r11d, 3

    inc rdx
    cmp rdx, 16
    jl .Lround_0_15

.Lround_16_63:

    pextrd eax, xmm4, 0
    pextrd r8d, xmm4, 1
    pextrd r9d, xmm6, 1
    pextrd r10d, xmm7, 2

    mov r11d, r8d
    ror r11d, 7
    mov esi, r8d
    ror esi, 18
    xor r11d, esi
    mov esi, r8d
    shr esi, 3
    xor r11d, esi

    mov r8d, r10d
    ror r8d, 17
    mov esi, r10d
    ror esi, 19
    xor r8d, esi
    mov esi, r10d
    shr esi, 10
    xor r8d, esi

    add eax, r11d
    add eax, r9d
    add eax, r8d

    mov [rsp + COMPRESS_W], eax
    movd xmm8, eax

    pextrd esi, xmm3, 3
    pextrd eax, xmm3, 0
    pextrd r11d, xmm3, 1
    pextrd edi, xmm3, 2

    mov r10d, eax
    ror r10d, 6
    mov r9d, eax
    ror r9d, 11
    xor r10d, r9d
    mov r9d, eax
    ror r9d, 25
    xor r10d, r9d
    add esi, r10d

    mov r10d, eax
    not r10d
    and r10d, edi
    mov r9d, eax
    and r9d, r11d
    xor r10d, r9d
    add esi, r10d

    add esi, [rcx + rdx*4]
    add esi, [rsp + COMPRESS_W]

    pextrd eax, xmm2, 0
    pextrd r10d, xmm2, 1
    pextrd r11d, xmm2, 2

    mov r8d, eax
    ror r8d, 2
    mov r9d, eax
    ror r9d, 13
    xor r8d, r9d
    mov r9d, eax
    ror r9d, 22
    xor r8d, r9d

    mov edi, eax
    and edi, r10d
    mov r9d, eax
    and r9d, r11d
    xor edi, r9d
    mov r9d, r10d
    and r9d, r11d
    xor edi, r9d

    add r8d, edi

    pextrd r10d, xmm2, 3
    add r10d, esi
    add esi, r8d

    pextrd r8d, xmm3, 0
    pextrd r9d, xmm3, 1
    pextrd r11d, xmm3, 2

    pinsrd xmm3, r10d, 0
    pinsrd xmm3, r8d, 1
    pinsrd xmm3, r9d, 2
    pinsrd xmm3, r11d, 3

    pextrd r8d, xmm2, 0
    pextrd r9d, xmm2, 1
    pextrd r11d, xmm2, 2

    pinsrd xmm2, esi, 0
    pinsrd xmm2, r8d, 1
    pinsrd xmm2, r9d, 2
    pinsrd xmm2, r11d, 3

    movdqa xmm10, xmm8
    palignr xmm10, xmm7, 4

    movdqa xmm11, xmm7
    palignr xmm11, xmm6, 4

    movdqa xmm12, xmm6
    palignr xmm12, xmm5, 4

    movdqa xmm13, xmm5
    palignr xmm13, xmm4, 4

    movdqa xmm4, xmm13
    movdqa xmm5, xmm12
    movdqa xmm6, xmm11
    movdqa xmm7, xmm10

    inc rdx
    cmp rdx, 64
    jl .Lround_16_63

    // The rounds used rdi, so the caller's H comes back out of the frame.
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

// ============================================================================
// sha256_hash
// ============================================================================
//
// C signature:
//   void redoubt_sha256_hash(const uint8_t *msg, size_t msg_len,
//                            uint8_t digest[32]);
//
// Parameters (SysV ABI):
//   rdi: msg, rsi: msg_len, rdx: digest (big-endian)
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
// ║ message with its padding, in the clear, because the caller's buffer has
// ║ no room to pad in. HASH_H holds the chaining state.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HASH

    mov [rsp + HASH_MSG], rdi
    mov [rsp + HASH_LEFT], rsi
    mov [rsp + HASH_TOTAL], rsi
    mov [rsp + HASH_DIGEST], rdx

#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HASH_H], xmm0
    movdqa [rsp + HASH_H + 16], xmm1

.Lhash_block_loop:
    cmp qword ptr [rsp + HASH_LEFT], 64
    jl .Lhash_final_block

    lea rdi, [rsp + HASH_H]
    mov rsi, [rsp + HASH_MSG]
    call FUNC(redoubt_sha256_compress_block)

    add qword ptr [rsp + HASH_MSG], 64
    sub qword ptr [rsp + HASH_LEFT], 64
    jmp .Lhash_block_loop

.Lhash_final_block:
    pxor xmm0, xmm0
    movdqa [rsp + HASH_BLOCK1], xmm0
    movdqa [rsp + HASH_BLOCK1 + 16], xmm0
    movdqa [rsp + HASH_BLOCK1 + 32], xmm0
    movdqa [rsp + HASH_BLOCK1 + 48], xmm0

    mov r8, [rsp + HASH_MSG]
    mov r9, [rsp + HASH_LEFT]
    xor rcx, rcx
.Lhash_copy_remainder:
    cmp rcx, r9
    jge .Lhash_remainder_done
    movzx eax, byte ptr [r8 + rcx]
    mov byte ptr [rsp + HASH_BLOCK1 + rcx], al
    inc rcx
    jmp .Lhash_copy_remainder

.Lhash_remainder_done:
    mov byte ptr [rsp + HASH_BLOCK1 + r9], 0x80

    cmp r9, 56
    jge .Lhash_two_blocks

    mov rax, [rsp + HASH_TOTAL]
    shl rax, 3
    bswap rax
    mov [rsp + HASH_BLOCK1 + 56], rax

    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    jmp .Lhash_finish

.Lhash_two_blocks:
    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK1]
    call FUNC(redoubt_sha256_compress_block)

    pxor xmm0, xmm0
    movdqa [rsp + HASH_BLOCK2], xmm0
    movdqa [rsp + HASH_BLOCK2 + 16], xmm0
    movdqa [rsp + HASH_BLOCK2 + 32], xmm0
    movdqa [rsp + HASH_BLOCK2 + 48], xmm0

    mov rax, [rsp + HASH_TOTAL]
    shl rax, 3
    bswap rax
    mov [rsp + HASH_BLOCK2 + 56], rax

    lea rdi, [rsp + HASH_H]
    lea rsi, [rsp + HASH_BLOCK2]
    call FUNC(redoubt_sha256_compress_block)

.Lhash_finish:
    movdqa xmm0, [rsp + HASH_H]
    movdqa xmm1, [rsp + HASH_H + 16]

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

// ============================================================================
// sha256_update_finalize
// ============================================================================
//
// C signature:
//   void sha256_update_finalize(const uint32_t H[8], const uint8_t *msg,
//                               size_t msg_len, size_t total_len,
//                               uint8_t digest[32]);
//
// Parameters (SysV ABI):
//   rdi: H (read once), rsi: msg, rdx: msg_len, rcx: total_len (every byte
//   already folded into H plus msg_len, for the padding), r8: digest
//
// No name outside this file: a symbol a linked library could collide with is
// resolved by the linker without a word. The probe reaches it by trampoline.
.p2align 4
.Lsha256_update_finalize:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: UPDATE_H holds the caller's state — for HMAC, a pad
// ║ already folded in, which is key material. UPDATE_BLOCK1 and UPDATE_BLOCK2
// ║ hold the tail of the message with its padding, in the clear.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_UPDATE

    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqa [rsp + UPDATE_H], xmm0
    movdqa [rsp + UPDATE_H + 16], xmm1

    mov [rsp + UPDATE_MSG], rsi
    mov [rsp + UPDATE_LEFT], rdx
    mov [rsp + UPDATE_TOTAL], rcx
    mov [rsp + UPDATE_DIGEST], r8

.Lupdate_block_loop:
    cmp qword ptr [rsp + UPDATE_LEFT], 64
    jl .Lupdate_final_block

    lea rdi, [rsp + UPDATE_H]
    mov rsi, [rsp + UPDATE_MSG]
    call FUNC(redoubt_sha256_compress_block)

    add qword ptr [rsp + UPDATE_MSG], 64
    sub qword ptr [rsp + UPDATE_LEFT], 64
    jmp .Lupdate_block_loop

.Lupdate_final_block:
    pxor xmm0, xmm0
    movdqa [rsp + UPDATE_BLOCK1], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 16], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 32], xmm0
    movdqa [rsp + UPDATE_BLOCK1 + 48], xmm0

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
    mov byte ptr [rsp + UPDATE_BLOCK1 + r9], 0x80

    cmp r9, 56
    jge .Lupdate_two_blocks

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

// ============================================================================
// hmac_sha256
// ============================================================================
//
// C signature:
//   void redoubt_hmac_sha256(const uint8_t *key, size_t key_len,
//                            const uint8_t *msg, size_t msg_len,
//                            uint8_t mac[32]);
//
// Parameters (SysV ABI):
//   rdi: key, rsi: key_len, rdx: msg, rcx: msg_len, r8: mac
//
// HMAC(K, M) = H(K ^ opad || H(K ^ ipad || M)), RFC 2104. A key longer than a
// block is hashed down first.
.global FUNC(redoubt_hmac_sha256)
HIDDEN_FUNC(redoubt_hmac_sha256)
#if !defined(__APPLE__)
.type FUNC(redoubt_hmac_sha256), @function
#endif
.p2align 4
FUNC(redoubt_hmac_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HMAC_KPAD holds the key padded to a block, and
// ║ HMAC_IPAD and HMAC_OPAD the key xored with public constants — each is the
// ║ key. HMAC_KHASH holds the key hashed down, HMAC_H a state with a pad
// ║ folded in, and HMAC_INNER the inner digest.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HMAC

    mov [rsp + HMAC_KEY], rdi
    mov [rsp + HMAC_KEYLEN], rsi
    mov [rsp + HMAC_MSG], rdx
    mov [rsp + HMAC_MSGLEN], rcx
    mov [rsp + HMAC_MAC], r8

    cmp qword ptr [rsp + HMAC_KEYLEN], 64
    jle .Lhmac_key_short

    mov rdi, [rsp + HMAC_KEY]
    mov rsi, [rsp + HMAC_KEYLEN]
    lea rdx, [rsp + HMAC_KHASH]
    call FUNC(redoubt_sha256_hash)

    movdqa xmm0, [rsp + HMAC_KHASH]
    movdqa xmm1, [rsp + HMAC_KHASH + 16]
    movdqa [rsp + HMAC_KPAD], xmm0
    movdqa [rsp + HMAC_KPAD + 16], xmm1

    pxor xmm0, xmm0
    movdqa [rsp + HMAC_KPAD + 32], xmm0
    movdqa [rsp + HMAC_KPAD + 48], xmm0

    jmp .Lhmac_key_ready

.Lhmac_key_short:
    pxor xmm0, xmm0
    movdqa [rsp + HMAC_KPAD], xmm0
    movdqa [rsp + HMAC_KPAD + 16], xmm0
    movdqa [rsp + HMAC_KPAD + 32], xmm0
    movdqa [rsp + HMAC_KPAD + 48], xmm0

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
#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HMAC_H], xmm0
    movdqa [rsp + HMAC_H + 16], xmm1

    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_IPAD]
    call FUNC(redoubt_sha256_compress_block)

    lea rdi, [rsp + HMAC_H]
    mov rsi, [rsp + HMAC_MSG]
    mov rdx, [rsp + HMAC_MSGLEN]
    mov rcx, rdx
    add rcx, 64
    lea r8, [rsp + HMAC_INNER]
    call .Lsha256_update_finalize

#if defined(__APPLE__)
    lea rax, [rip + .LH256_INIT]
#else
    lea rax, .LH256_INIT[rip]
#endif
    movdqu xmm0, [rax]
    movdqu xmm1, [rax + 16]
    movdqa [rsp + HMAC_H], xmm0
    movdqa [rsp + HMAC_H + 16], xmm1

    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_OPAD]
    call FUNC(redoubt_sha256_compress_block)

    lea rdi, [rsp + HMAC_H]
    lea rsi, [rsp + HMAC_INNER]
    mov rdx, 32
    mov rcx, 96
    mov r8, [rsp + HMAC_MAC]
    call .Lsha256_update_finalize

    HKDF_EMPTY_FRAME FRAME_HMAC
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    HKDF_SHA256_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_hmac_sha256), .-FUNC(redoubt_hmac_sha256)
#endif

// ============================================================================
// sha256_absorb
// ============================================================================
//
// C signature:
//   void sha256_absorb(uint32_t H[8], const uint8_t *src, size_t len,
//                      uint8_t block[64], size_t *fill);
//
// Parameters (SysV ABI):
//   rdi: H, rsi: src, rdx: len, rcx: block (filled across calls),
//   r8: fill (how much of block is used; read and written)
//
// Appends the run to the block and folds it into H each time it fills. The
// block and its count are the caller's and are not emptied here: the next call
// continues them.
//
// No name outside this file: a symbol a linked library could collide with is
// resolved by the linker without a word. The probe reaches it by trampoline.
.p2align 4
.Lsha256_absorb:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: no message bytes, only the arguments — but ABSORB_H
// ║ and ABSORB_SRC point into the caller's secrets.
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

// ============================================================================
// hkdf_sha256
// ============================================================================
//
// C signature:
//   void redoubt_hkdf_sha256(const uint8_t *salt, size_t salt_len,
//                            const uint8_t *ikm, size_t ikm_len,
//                            const uint8_t *info, size_t info_len,
//                            uint8_t *okm, size_t okm_len);
//
// Parameters (SysV ABI):
//   rdi: salt, rsi: salt_len, rdx: ikm, rcx: ikm_len, r8: info, r9: info_len,
//   [rsp + 8]: okm, [rsp + 16]: okm_len — the seventh and eighth arguments,
//   which SysV passes on the stack, read below the frame this routine takes.
//
// PRK = HMAC(salt, IKM), then T(i) = HMAC(PRK, T(i-1) || info || i), RFC 5869.
// The expansion feeds T(i-1), info and the counter to the hash where they lie
// rather than calling hmac_sha256, which would want them in one buffer sized
// from info_len — and a frame whose size is not a constant cannot be measured.
// The counter is written as one byte and never checked: the caller refuses a
// length past 255 blocks, where it would wrap.
.global FUNC(redoubt_hkdf_sha256)
HIDDEN_FUNC(redoubt_hkdf_sha256)
#if !defined(__APPLE__)
.type FUNC(redoubt_hkdf_sha256), @function
#endif
.p2align 4
FUNC(redoubt_hkdf_sha256):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: HKDF_PRK holds the extracted key every byte of output
// ║ comes from, and HKDF_IPAD and HKDF_OPAD that key xored with public
// ║ constants. HKDF_H holds a state with a pad folded in, HKDF_INNER the
// ║ inner digest, HKDF_T a block of the output, and HKDF_BLOCK the tail of
// ║ the message being hashed.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME_HKDF

    // The salt and the IKM stay where the caller put them: the extraction below
    // reads them straight from rdi-rcx, and nothing reads them again.
    mov [rsp + HKDF_INFO], r8
    mov [rsp + HKDF_INFOLEN], r9
    mov rax, [rsp + FRAME_HKDF + 8]
    mov [rsp + HKDF_OKM], rax
    mov rax, [rsp + FRAME_HKDF + 16]
    mov [rsp + HKDF_OKMLEN], rax

    lea r8, [rsp + HKDF_PRK]
    call FUNC(redoubt_hmac_sha256)

    // PRK is thirty-two bytes, inside a block, so it needs no hashing down and
    // the bytes past it pad with zeros, as RFC 2104 asks.
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
    mov qword ptr [rsp + HKDF_COUNTER], 1
    mov qword ptr [rsp + HKDF_TLEN], 0

.Lhkdf_expand_loop:
    cmp qword ptr [rsp + HKDF_OKMLEN], 0
    je .Lhkdf_done

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

    lea rdi, [rsp + HKDF_H]
    lea rsi, [rsp + HKDF_T]
    mov rdx, [rsp + HKDF_TLEN]
    lea rcx, [rsp + HKDF_BLOCK]
    lea r8, [rsp + HKDF_FILL]
    call .Lsha256_absorb

    lea rdi, [rsp + HKDF_H]
    mov rsi, [rsp + HKDF_INFO]
    mov rdx, [rsp + HKDF_INFOLEN]
    lea rcx, [rsp + HKDF_BLOCK]
    lea r8, [rsp + HKDF_FILL]
    call .Lsha256_absorb

    // The counter closes the message, so it goes into the block rather than
    // through the absorb: what is left is one partial block for the padding.
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

// uint64_t redoubt_hkdf_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because rdi is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
//
// The vectors gather first, and `por` touches no general register, so rax is
// still the caller's when the general gather reads it. Both halves of the
// vector fold reach the answer: which half a bit came from is lost, whether
// there was one is not.
.p2align 4
.globl FUNC(redoubt_hkdf_registers_are_zeroized)
HIDDEN_FUNC(redoubt_hkdf_registers_are_zeroized)
FUNC(redoubt_hkdf_registers_are_zeroized):
    HKDF_EACH_VECTOR HKDF_GATHER_VECTOR

    HKDF_EACH_GPR HKDF_GATHER_GPR

    movq rax, xmm0
    or rcx, rax
    pextrq rax, xmm0, 1
    or rcx, rax

    mov rax, rcx
    ret

// Every register in the budget filled with a pattern, both halves of each
// vector, and left that way.
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

// The low half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only be those halves.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_vector_low)
HIDDEN_FUNC(redoubt_hkdf_dirty_vector_low)
FUNC(redoubt_hkdf_dirty_vector_low):
    HKDF_SHA256_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    xor eax, eax
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    ret

// The high half of every vector register filled, and every other bit of the
// budget emptied: what reaches a verifier afterwards can only come through its
// fold.
.p2align 4
.globl FUNC(redoubt_hkdf_dirty_vector_high)
HIDDEN_FUNC(redoubt_hkdf_dirty_vector_high)
FUNC(redoubt_hkdf_dirty_vector_high):
    HKDF_SHA256_ZEROIZE_ALL
    mov rax, 0xa5a5a5a5a5a5a5a5
    movq xmm0, rax
    pslldq xmm0, 8
    xor eax, eax
    HKDF_EACH_VECTOR HKDF_FILL_VECTOR
    ret

// The frame instruments for a routine whose frame is \size bytes.
//
// uint64_t redoubt_hkdf_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `call`
//   leaves rsp where the previous callee found it, so the return address lands
//   in the same slot and `[rsp - \size, rsp)` is the frame that callee took.
//   Asked after the registers, never before: reading the frame takes registers.
//
// void redoubt_hkdf_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in rdi, marked and left.
//
// void redoubt_hkdf_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro HKDF_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_hkdf_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_hkdf_frame_is_zeroized_\name)
FUNC(redoubt_hkdf_frame_is_zeroized_\name):
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
.globl FUNC(redoubt_hkdf_dirty_frame_\name)
HIDDEN_FUNC(redoubt_hkdf_dirty_frame_\name)
FUNC(redoubt_hkdf_dirty_frame_\name):
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

// The routines with no name outside this file, given one for a measurement. A
// `jmp` and not a `call`: it leaves rsp and the return address as they arrived,
// so the routine takes its frame where the verifier will read it.
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
