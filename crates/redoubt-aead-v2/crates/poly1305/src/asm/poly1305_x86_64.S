// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Poly1305 One-Time Authenticator - x86_64 (SysV ABI) Implementation
//
// Baseline x86_64. No BMI2, no ADX, no AVX2, nothing to detect at runtime: the
// whole of it is scalar 64-bit integer arithmetic. That is not the fastest
// Poly1305 anybody has written and it is not meant to be — a vectorized one
// needs a runtime check, a second and third copy of the multiply, and a wipe
// written once per register file. This one is the same code on every machine
// that runs it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - `r` and the accumulator are five limbs of twenty-six bits each
//   - The products of one block never leave registers
//   - Any spill region is named and wiped here
//   - No callee-saved register is touched, so no prologue puts a copy of one
//     of the caller's values on the stack for an epilogue to have to remove
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes its first arguments in rcx, rdx,
//     r8 and r9 and reserves rsi, rdi and xmm6-xmm15 as callee-saved. This
//     file is SysV throughout. The build script compiles no assembly there and
//     the crate falls back to the Rust, which answers the same and promises
//     less.
//
// What crosses into here, and what does not:
//   Every argument is a pointer to storage the caller declared, and nothing is
//   returned. A returned value leaves in a register, and a register carrying
//   the answer out is a register the wipe below cannot touch — which is why
//   even how much of the buffer is used arrives and leaves through memory. A
//   length and the bit above a block arrive by value because neither is a
//   secret and both are known to anybody watching the call.
//
// What must not branch:
//   The final conditional subtraction is a mask and not a jump. Whether the
//   accumulator was above the modulus is a fact about the key that made it, and
//   a branch there is that fact on a clock.
//
// What this cannot answer for:
//   The limbs are held in registers and in the frame this file named and wiped.
//   That is a statement about this file, not about the machine. When a signal
//   is delivered the kernel writes the whole register context to a frame on the
//   user stack, and nothing in user space wipes that frame on the way back. The
//   same goes for a core dump, for a page that reached swap, and for anything
//   ptrace can read. None of those are reachable from here, and none are made
//   worse by this being assembly: the Rust has every one of them too.
//
// References:
// - RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, section 2.5
// - System V AMD64 ABI, section 3.2.3 (parameter passing)

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
// The register budget
// ============================================================================
//
// SysV AMD64 ABI:
//   - Caller-saved GPR: rax, rcx, rdx, rsi, rdi, r8-r11
//   - Callee-saved GPR: rbx, rbp, r12-r15  (DO NOT TOUCH)
//
// Every register these routines put anything in is named once, below, and
// every operation over the set goes through that one list. Emptying them and
// asking whether they are empty are the same nine registers by construction,
// not by two lists that happen to agree today.
//
// Does NOT include: rsp, rbx, rbp, r12-r15. Nothing here puts anything in
// them, so there is nothing of ours to clear — and no prologue saving them,
// which means no copy of the caller's values in memory for an epilogue to take
// back out. A routine that spilled into one of these would have to save it
// first, and that save is what writes the caller's register to the stack.
//
// Does NOT include the SIMD registers either. Nothing here writes one, so
// clearing them would be clearing registers this code never put anything in.
//
.macro POLY1305_EACH op
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

.macro POLY1305_CLEAR reg
    xor \reg, \reg
.endm

// Copies what rax already holds into each of them, rax included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro POLY1305_FILL reg
    mov \reg, rax
.endm

// Gathers into rcx, which is in the budget and therefore contributes its own
// value on its own line. What the gather leaves in rcx is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro POLY1305_GATHER reg
    or rcx, \reg
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro POLY1305_ZEROIZE_ALL
    POLY1305_EACH POLY1305_CLEAR
.endm

// ============================================================================
// Frame layout — 160 bytes, entirely above rsp
// ============================================================================
//
//   ACC      0..39    the accumulator, five limbs of twenty-six bits
//   SUMS    40..79    one block's five products, then the reduced answer
//   BLOCK   80..95    the last block of the message, padded here
//   SAID    96..103   where the message is up to
//   LEN    104..111   how much of it is left
//   RPTR   112..119   the caller's `r`, read where it lies
//   SPTR   120..127   the caller's `s`
//   OUT    128..135   where the tag goes
//   ACCPTR 136..143   the caller's accumulator, written back at the end
//
// `r` stays in the caller's array and is read thirty-two bits at a time, which
// is what keeps this frame the same size as ChaCha20's and inside the window
// the probe inspects. Nothing else about it is a secret it would not already
// be sitting in.
//
.set ACC, 0
.set SUMS, 40
.set BLOCK, 80
.set SAID, 96
.set LEN, 104
.set RPTR, 112
.set SPTR, 120
.set OUT, 128
.set ACCPTR, 136
// `update` reaches the caller's partial block and its fill mark where they
// lie, for the same reason `r` is not copied: they outlive the call and the
// caller is the one that empties them.
.set BLOCKPTR, 144
.set FILLEDPTR, 152
.set FRAME, 160

.set LIMB, 0x3ffffff

.macro POLY1305_EMPTY_FRAME
    .irp offset,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152
        mov qword ptr [rsp + \offset], 0
    .endr
    add rsp, FRAME
.endm

// One product of the twenty-five, into rax. `five` picks the limb of `r` that
// wrapped past the top and came back worth five times less a power.
.macro POLY1305_TERM at, limb, five
    mov ecx, [r11 + 4*\limb]
    .if \five
    lea rcx, [rcx + rcx*4]
    .endif
    imul rcx, qword ptr [rsp + ACC + 8*\at]
    add rax, rcx
.endm

.macro POLY1305_FIRST at, limb, five
    mov ecx, [r11 + 4*\limb]
    .if \five
    lea rcx, [rcx + rcx*4]
    .endif
    mov rax, rcx
    imul rax, qword ptr [rsp + ACC + 8*\at]
.endm

// acc = acc * r, modulo 2^130 - 5. Twenty-five products gathered by which
// power of 2^26 they land on, then every limb put back under its width.
.macro POLY1305_MULTIPLY
    mov r11, [rsp + RPTR]

    POLY1305_FIRST 0, 0, 0
    POLY1305_TERM  1, 4, 1
    POLY1305_TERM  2, 3, 1
    POLY1305_TERM  3, 2, 1
    POLY1305_TERM  4, 1, 1
    mov [rsp + SUMS], rax

    POLY1305_FIRST 0, 1, 0
    POLY1305_TERM  1, 0, 0
    POLY1305_TERM  2, 4, 1
    POLY1305_TERM  3, 3, 1
    POLY1305_TERM  4, 2, 1
    mov [rsp + SUMS + 8], rax

    POLY1305_FIRST 0, 2, 0
    POLY1305_TERM  1, 1, 0
    POLY1305_TERM  2, 0, 0
    POLY1305_TERM  3, 4, 1
    POLY1305_TERM  4, 3, 1
    mov [rsp + SUMS + 16], rax

    POLY1305_FIRST 0, 3, 0
    POLY1305_TERM  1, 2, 0
    POLY1305_TERM  2, 1, 0
    POLY1305_TERM  3, 0, 0
    POLY1305_TERM  4, 4, 1
    mov [rsp + SUMS + 24], rax

    POLY1305_FIRST 0, 4, 0
    POLY1305_TERM  1, 3, 0
    POLY1305_TERM  2, 2, 0
    POLY1305_TERM  3, 1, 0
    POLY1305_TERM  4, 0, 0
    mov [rsp + SUMS + 32], rax

    POLY1305_CARRY SUMS

    .irp offset,0,8,16,24,32
        mov rax, [rsp + SUMS + \offset]
        mov [rsp + ACC + \offset], rax
    .endr
.endm

// Every limb of the five at `at` back under twenty-six bits, and what ran off
// the top folded back in worth five.
.macro POLY1305_CARRY at
    mov r8d, LIMB

    .irp step,0,8,16,24
        mov rax, [rsp + \at + \step]
        mov rcx, rax
        shr rcx, 26
        add [rsp + \at + \step + 8], rcx
        and eax, r8d
        mov [rsp + \at + \step], rax
    .endr

    mov rax, [rsp + \at + 32]
    mov rcx, rax
    shr rcx, 26
    lea rcx, [rcx + rcx*4]
    add [rsp + \at], rcx
    and eax, r8d
    mov [rsp + \at + 32], rax

    mov rax, [rsp + \at]
    mov rcx, rax
    shr rcx, 26
    add [rsp + \at + 8], rcx
    and eax, r8d
    mov [rsp + \at], rax
.endm

// acc += the sixteen bytes at `src`, with `hibit` above them, and then acc is
// multiplied by `r`. `src` is a register and is not written.
.macro POLY1305_BLOCK src, hibit
    mov rax, [\src]
    mov rdx, [\src + 8]
    mov r8d, LIMB

    mov r9, rax
    and r9d, r8d
    add [rsp + ACC], r9

    mov r9, rax
    shr r9, 26
    and r9d, r8d
    add [rsp + ACC + 8], r9

    mov r9, rax
    shr r9, 52
    mov r10, rdx
    shl r10, 12
    or r9, r10
    and r9d, r8d
    add [rsp + ACC + 16], r9

    mov r9, rdx
    shr r9, 14
    and r9d, r8d
    add [rsp + ACC + 24], r9

    mov r9, rdx
    shr r9, 40
    .if \hibit
    or r9, 0x1000000
    .endif
    add [rsp + ACC + 32], r9

    POLY1305_MULTIPLY
.endm

// ============================================================================
// init — rdi: r, five u32 limbs out; rsi: s, sixteen bytes out;
//        rdx: key, thirty-two bytes in
// ============================================================================
//
// No frame and no callee-saved register: the whole clamp fits in the
// caller-saved ones, so there is nothing to give back and nothing to wipe but
// the registers themselves.
//
.p2align 4
.globl FUNC(redoubt_poly1305_init)
HIDDEN_FUNC(redoubt_poly1305_init)
FUNC(redoubt_poly1305_init):
    // The two halves of the key as two words each. RFC 8439 §2.5 masks the
    // top four bits of every fourth byte and the bottom two of three others,
    // which is one AND over the pair.
    mov rax, [rdx]
    mov rcx, [rdx + 8]
    mov r8,  0x0ffffffc0fffffff
    and rax, r8
    mov r8,  0x0ffffffc0ffffffc
    and rcx, r8

    // Five limbs of twenty-six bits out of the hundred and twenty-eight.
    mov r8d, 0x3ffffff

    mov r9, rax
    and r9d, r8d
    mov [rdi], r9d

    mov r9, rax
    shr r9, 26
    and r9d, r8d
    mov [rdi + 4], r9d

    mov r9, rax
    shr r9, 52
    mov r10, rcx
    shl r10, 12
    or  r9, r10
    and r9d, r8d
    mov [rdi + 8], r9d

    mov r9, rcx
    shr r9, 14
    and r9d, r8d
    mov [rdi + 12], r9d

    mov r9, rcx
    shr r9, 40
    mov [rdi + 16], r9d

    // `s` is kept as it arrived: it is added at the very end and never
    // multiplied, so there is no representation to move it into.
    mov rax, [rdx + 16]
    mov rcx, [rdx + 24]
    mov [rsi], rax
    mov [rsi + 8], rcx

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// update — rdi: acc; rsi: r; rdx: the partial block; rcx: how full it is,
//          read and written; r8: message; r9: its length
// ============================================================================
//
// What arrives is whatever the caller had. Whole blocks go by where they lie;
// only a tail that is not a block yet is copied into the caller's buffer, and
// only the block that filling it completed is counted here.
//
.p2align 4
.globl FUNC(redoubt_poly1305_update)
HIDDEN_FUNC(redoubt_poly1305_update)
FUNC(redoubt_poly1305_update):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial over everything counted so
// ║ far, and SUMS its products by `r`. The partial block is not in here —
// ║ it is the caller's, written where the caller keeps it, and emptied
// ║ there as soon as the block it completes has been counted.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + ACCPTR], rdi
    mov [rsp + RPTR], rsi
    mov [rsp + BLOCKPTR], rdx
    mov [rsp + FILLEDPTR], rcx
    mov [rsp + SAID], r8
    mov [rsp + LEN], r9

    .irp offset,0,8,16,24,32
        mov rax, [rdi + \offset]
        mov [rsp + ACC + \offset], rax
    .endr

    mov rcx, [rcx]
    test rcx, rcx
    jz Lupdate_stream

    // As much of the message as the buffer still has room for.
    mov rax, 16
    sub rax, rcx
    mov rdx, [rsp + LEN]
    cmp rax, rdx
    jbe Lupdate_fill
    mov rax, rdx
Lupdate_fill:
    test rax, rax
    jz Lupdate_flush

    mov rsi, [rsp + SAID]
    mov rdi, [rsp + BLOCKPTR]
    add rdi, rcx
    xor rdx, rdx
Lupdate_fill_byte:
    mov r8b, [rsi + rdx]
    mov [rdi + rdx], r8b
    inc rdx
    cmp rdx, rax
    jb Lupdate_fill_byte

    add rcx, rax
    mov rdx, [rsp + FILLEDPTR]
    mov [rdx], rcx
    add [rsp + SAID], rax
    sub [rsp + LEN], rax

Lupdate_flush:
    cmp rcx, 16
    jne Lupdate_stream

    mov rsi, [rsp + BLOCKPTR]
    POLY1305_BLOCK rsi, 1

    // The caller's buffer is emptied here and not left for it to do: what is
    // in it is message, and the next thing written over it is only as much
    // message as the next tail happens to be.
    mov rsi, [rsp + BLOCKPTR]
    mov qword ptr [rsi], 0
    mov qword ptr [rsi + 8], 0
    mov rdx, [rsp + FILLEDPTR]
    mov qword ptr [rdx], 0

Lupdate_stream:
    cmp qword ptr [rsp + LEN], 16
    jb Lupdate_tail
    mov rsi, [rsp + SAID]
    POLY1305_BLOCK rsi, 1
    add qword ptr [rsp + SAID], 16
    sub qword ptr [rsp + LEN], 16
    jmp Lupdate_stream

Lupdate_tail:
    mov rcx, [rsp + LEN]
    test rcx, rcx
    jz Lupdate_done

    mov rsi, [rsp + SAID]
    mov rdi, [rsp + BLOCKPTR]
    xor rdx, rdx
Lupdate_keep_byte:
    mov r8b, [rsi + rdx]
    mov [rdi + rdx], r8b
    inc rdx
    cmp rdx, rcx
    jb Lupdate_keep_byte

    mov rdx, [rsp + FILLEDPTR]
    mov [rdx], rcx

Lupdate_done:
    mov r9, [rsp + ACCPTR]
    .irp offset,0,8,16,24,32
        mov rax, [rsp + ACC + \offset]
        mov [r9 + \offset], rax
    .endr

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
    ret

// ============================================================================
// finalize — rdi: acc; rsi: r; rdx: s; rcx: message; r8: its length;
//            r9: tag out
// ============================================================================
//
// One call and not a loop the caller drives: a message handed over whole goes
// through every block of itself without the bytes coming back to Rust in
// between.
//
.p2align 4
.globl FUNC(redoubt_poly1305_finalize)
HIDDEN_FUNC(redoubt_poly1305_finalize)
FUNC(redoubt_poly1305_finalize):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: ACC holds the polynomial and then the number the tag
// ║ is made from, SUMS its products by `r`, and BLOCK the last bytes of the
// ║ message with the marker written after them. That last one is message in
// ║ the clear, and it is here rather than in the caller's buffer because a
// ║ caller that handed over a whole message has no buffer to pad.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + ACCPTR], rdi
    mov [rsp + RPTR], rsi
    mov [rsp + SPTR], rdx
    mov [rsp + SAID], rcx
    mov [rsp + LEN], r8
    mov [rsp + OUT], r9

    .irp offset,0,8,16,24,32
        mov rax, [rdi + \offset]
        mov [rsp + ACC + \offset], rax
    .endr

Lwhole:
    cmp qword ptr [rsp + LEN], 16
    jb Ltail
    mov rsi, [rsp + SAID]
    POLY1305_BLOCK rsi, 1
    add qword ptr [rsp + SAID], 16
    sub qword ptr [rsp + LEN], 16
    jmp Lwhole

Ltail:
    mov rcx, [rsp + LEN]
    test rcx, rcx
    jz Lwritten_back

    mov qword ptr [rsp + BLOCK], 0
    mov qword ptr [rsp + BLOCK + 8], 0
    mov rsi, [rsp + SAID]
    xor edx, edx
Lcopy:
    mov al, [rsi + rdx]
    mov [rsp + rdx + BLOCK], al
    inc rdx
    cmp rdx, rcx
    jb Lcopy

    // The one bit above the message, which is what keeps a tail of zeros from
    // reading as a shorter message that ended sooner.
    mov byte ptr [rsp + rcx + BLOCK], 1
    lea rsi, [rsp + BLOCK]
    POLY1305_BLOCK rsi, 0

Lwritten_back:
    // The accumulator the caller gets back is the polynomial, before the
    // reduction below turns it into a tag.
    mov r9, [rsp + ACCPTR]
    .irp offset,0,8,16,24,32
        mov rax, [rsp + ACC + \offset]
        mov [r9 + \offset], rax
    .endr

    POLY1305_CARRY ACC

    // The accumulator is now below 2^130 but may still be at or above the
    // modulus, and there is exactly one subtraction that could be owed. Adding
    // five says whether it is: if the sum carries past the hundred and
    // thirtieth bit, the accumulator was at least 2^130 - 5.
    mov r8d, LIMB

    mov rax, [rsp + ACC]
    add rax, 5
    mov rcx, rax
    shr rcx, 26
    and eax, r8d
    mov [rsp + SUMS], rax

    .irp offset,8,16,24
        mov rax, [rsp + ACC + \offset]
        add rax, rcx
        mov rcx, rax
        shr rcx, 26
        and eax, r8d
        mov [rsp + SUMS + \offset], rax
    .endr

    // All ones where the accumulator was already below the modulus, and all
    // zeros where it was not. A comparison instead of a mask would be a branch
    // on the tag, which is a branch on the key that made it.
    mov rax, [rsp + ACC + 32]
    add rax, rcx
    shr rax, 26
    sub rax, 1
    mov r10, rax
    mov r11, rax
    not r11

    .irp offset,0,8,16,24
        mov rax, [rsp + ACC + \offset]
        and rax, r10
        mov rcx, [rsp + SUMS + \offset]
        and rcx, r11
        or rax, rcx
        mov [rsp + ACC + \offset], rax
    .endr

    // The sum has no fifth limb, so where it is taken the fifth goes.
    mov rax, [rsp + ACC + 32]
    and rax, r10
    mov [rsp + ACC + 32], rax

    // Five limbs of twenty-six into four words of thirty-two.
    mov rax, [rsp + ACC]
    mov rcx, [rsp + ACC + 8]
    mov rdx, rcx
    and edx, 0x3f
    shl rdx, 26
    or rax, rdx

    mov rsi, rcx
    shr rsi, 6
    mov rcx, [rsp + ACC + 16]
    mov rdx, rcx
    and edx, 0xfff
    shl rdx, 20
    or rsi, rdx

    mov rdi, rcx
    shr rdi, 12
    mov rcx, [rsp + ACC + 24]
    mov rdx, rcx
    and edx, 0x3ffff
    shl rdx, 14
    or rdi, rdx

    mov r8, rcx
    shr r8, 18
    mov rcx, [rsp + ACC + 32]
    and ecx, 0xffffff
    shl rcx, 8
    or r8, rcx

    // `s` added, carrying between the words, and the low half of each is the
    // tag. What runs off the top of the fourth is the modulo 2^128.
    mov r9, [rsp + SPTR]
    mov ecx, [r9]
    add rax, rcx
    mov ecx, [r9 + 4]
    add rsi, rcx
    mov rdx, rax
    shr rdx, 32
    add rsi, rdx
    mov ecx, [r9 + 8]
    add rdi, rcx
    mov rdx, rsi
    shr rdx, 32
    add rdi, rdx
    mov ecx, [r9 + 12]
    add r8, rcx
    mov rdx, rdi
    shr rdx, 32
    add r8, rdx

    mov r9, [rsp + OUT]
    mov [r9], eax
    mov [r9 + 4], esi
    mov [r9 + 8], edi
    mov [r9 + 12], r8d

    POLY1305_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    POLY1305_ZEROIZE_ALL
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
// What it costs is a few hundred bytes of instructions that ship unused. What
// it buys is that the only `160` in the measurement, and the only list of
// registers, are the ones at the top of this file.
//
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own list
//   frame_is_zeroized        asks the stack, with the file's own FRAME
//   dirty_registers          fills the budget and leaves it that way
//   dirty_frame              one byte of the frame, at an offset given
//   clean_frame              the frame written and emptied, with no arithmetic

// uint64_t redoubt_poly1305_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost rdi, and
// rdi is one of the registers being asked about — it would arrive holding our
// own pointer rather than the caller's value. With nothing passed, `call` is
// the whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_poly1305_registers_are_zeroized)
HIDDEN_FUNC(redoubt_poly1305_registers_are_zeroized)
FUNC(redoubt_poly1305_registers_are_zeroized):
    POLY1305_EACH POLY1305_GATHER
    mov rax, rcx
    ret

// uint64_t redoubt_poly1305_frame_is_zeroized(void)
//
// Whether any byte of the frame the call before it used is still holding
// something. Zero when it is all empty, and the bits of whatever was not.
//
// Reads below its own rsp, and that is the whole of it: `call` leaves rsp
// where the routine before had it, so what sits under this one's return
// address is what sat under that one's — the frame it took and gave back.
//
// Asked after the registers, never before: reading a hundred and sixty bytes
// takes registers, and the answer about those has to be taken first.
.p2align 4
.globl FUNC(redoubt_poly1305_frame_is_zeroized)
HIDDEN_FUNC(redoubt_poly1305_frame_is_zeroized)
FUNC(redoubt_poly1305_frame_is_zeroized):
    // The index counts up from minus the frame to zero. x86 addresses with a
    // base plus an index, never a base minus one, so what reaches below rsp is
    // an index holding a negative number rather than a subtraction.
    xor eax, eax
    mov rcx, -FRAME
Lframe_scan:
    or rax, [rsp + rcx]
    add rcx, 8
    jnz Lframe_scan
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_registers)
HIDDEN_FUNC(redoubt_poly1305_dirty_registers)
FUNC(redoubt_poly1305_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    POLY1305_EACH POLY1305_FILL
    ret

// One byte of the frame, dirtied and left. rdi says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// the return address sitting next door would show.
.p2align 4
.globl FUNC(redoubt_poly1305_dirty_frame)
HIDDEN_FUNC(redoubt_poly1305_dirty_frame)
FUNC(redoubt_poly1305_dirty_frame):
    sub rsp, FRAME
    mov byte ptr [rsp + rdi], 0x5c
    add rsp, FRAME
    ret

// The whole frame written and then emptied: what a routine above does, without
// the arithmetic in between.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.globl FUNC(redoubt_poly1305_clean_frame)
HIDDEN_FUNC(redoubt_poly1305_clean_frame)
FUNC(redoubt_poly1305_clean_frame):
    sub rsp, FRAME
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
Lclean_write:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, FRAME
    jb Lclean_write
    POLY1305_EMPTY_FRAME
    POLY1305_ZEROIZE_ALL
    ret

