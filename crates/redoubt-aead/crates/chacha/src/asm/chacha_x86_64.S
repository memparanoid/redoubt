// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ChaCha20, HChaCha20 and XChaCha20 - x86_64 (SysV ABI) Implementation
//
// Baseline x86_64. No SSE, no AVX, no AVX-512, nothing to detect at runtime:
// the whole of it is scalar 32-bit integer arithmetic. That is not the fastest
// ChaCha20 anybody has written and it is not meant to be — a vectorized one
// needs a runtime check, a second and third copy of the rounds, and a wipe
// written once per register file. This one is the same code on every machine
// that runs it, which is what makes the promise below checkable.
//
// Register-budgeted design goal:
//   - Four working words at a time in caller-saved GPRs
//   - One explicit 160-byte frame, wiped on every exit
//   - No callee-saved register is touched
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
//   the answer out is a register the wipe below cannot touch. A length and a
//   counter arrive by value because neither is a secret and both are known to
//   anybody watching the call.
//
// What this cannot answer for:
//   The state words are written to the frame this file named and wiped. That
//   is a statement about this file, not about the machine. When a signal is
//   delivered the kernel writes the whole register context to a frame on the
//   user stack, wherever in the rounds that happens, and nothing in user space
//   wipes that frame on the way back. The same goes for a core dump, for a page
//   that reached swap, and for anything ptrace can read. None of those are
//   reachable from here, and none are made worse by this being assembly: the
//   Rust has every one of them too.
//
// References:
// - RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, sections 2.1 to 2.4
// - draft-irtf-cfrg-xchacha, XChaCha: eXtended-nonce ChaCha, section 2.2
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
// The flags are overwritten by the final xor too. No register leaves carrying
// a result: outputs are pointers.
//
.macro CHACHA_EACH op
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

.macro CHACHA_CLEAR reg
    xor \reg, \reg
.endm

// Copies what rax already holds into each of them, rax included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro CHACHA_FILL reg
    mov \reg, rax
.endm

// Gathers into rcx, which is in the budget and therefore contributes its own
// value on its own line. What the gather leaves in rcx is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro CHACHA_GATHER reg
    or rcx, \reg
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro CHACHA_ZEROIZE_ALL
    CHACHA_EACH CHACHA_CLEAR
.endm

// ============================================================================
// Frame layout — 160 bytes, entirely above rsp
// ============================================================================
//
//   INITIAL   0..63    state before the rounds, including an XChaCha subkey
//   WORK     64..127   state during the rounds, then one keystream block
//   OUTPUT  128..135   destination pointer
//   LENGTH  136..143   remaining byte count
//   MODE    144..151   nonce length; temporarily the XChaCha nonce pointer
//   COUNTER 152..159   starting counter, needed across HChaCha for XChaCha
//
// Four working words at a time fit in eax, ecx, edx and r8d. Everything else
// lives here. No pushes, calls, red-zone writes or implicit spills.
//
.set INITIAL, 0
.set WORK, 64
.set OUTPUT, 128
.set LENGTH, 136
.set MODE, 144
.set COUNTER, 152
.set FRAME, 160

.macro CHACHA_EMPTY_FRAME
    .irp offset,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152
        mov qword ptr [rsp + \offset], 0
    .endr
    add rsp, FRAME
.endm

// RFC 8439 §2.1. Addresses and rotations are fixed, independent of the state.
.macro CHACHA_QUARTER a,b,c,d
    mov eax, [rsp + WORK + 4*\a]
    mov ecx, [rsp + WORK + 4*\b]
    mov edx, [rsp + WORK + 4*\c]
    mov r8d, [rsp + WORK + 4*\d]

    add eax, ecx
    xor r8d, eax
    rol r8d, 16
    add edx, r8d
    xor ecx, edx
    rol ecx, 12
    add eax, ecx
    xor r8d, eax
    rol r8d, 8
    add edx, r8d
    xor ecx, edx
    rol ecx, 7

    mov [rsp + WORK + 4*\a], eax
    mov [rsp + WORK + 4*\b], ecx
    mov [rsp + WORK + 4*\c], edx
    mov [rsp + WORK + 4*\d], r8d
.endm

.macro CHACHA_ROUNDS
    mov r9d, 10
Lrounds\@:
    CHACHA_QUARTER 0,4,8,12
    CHACHA_QUARTER 1,5,9,13
    CHACHA_QUARTER 2,6,10,14
    CHACHA_QUARTER 3,7,11,15
    CHACHA_QUARTER 0,5,10,15
    CHACHA_QUARTER 1,6,11,12
    CHACHA_QUARTER 2,7,8,13
    CHACHA_QUARTER 3,4,9,14
    dec r9d
    jnz Lrounds\@
.endm

.macro CHACHA_CONSTANTS at
    mov dword ptr [rsp + \at],      0x61707865
    mov dword ptr [rsp + \at + 4],  0x3320646e
    mov dword ptr [rsp + \at + 8],  0x79622d32
    mov dword ptr [rsp + \at + 12], 0x6b206574
.endm

// key and nonce are pointer registers; only rax is scratch.
.macro CHACHA_HSTATE key,nonce
    CHACHA_CONSTANTS WORK
    .irp offset,0,8,16,24
        mov rax, [\key + \offset]
        mov [rsp + WORK + 16 + \offset], rax
    .endr
    mov rax, [\nonce]
    mov [rsp + WORK + 48], rax
    mov rax, [\nonce + 8]
    mov [rsp + WORK + 56], rax
.endm

// ============================================================================
// Twenty rounds — rdi: state in/out, sixteen u32 words
// ============================================================================

.p2align 4
.globl FUNC(redoubt_chacha_rounds)
HIDDEN_FUNC(redoubt_chacha_rounds)
FUNC(redoubt_chacha_rounds):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: WORK holds the caller's state through the rounds. It is
// ║ the caller's own words, and it is here because four of them at a time are
// ║ all the budget has room for.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + OUTPUT], rdi
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rdi + \offset]
        mov [rsp + WORK + \offset], rax
    .endr

    CHACHA_ROUNDS

    mov rdi, [rsp + OUTPUT]
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rsp + WORK + \offset]
        mov [rdi + \offset], rax
    .endr

    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// HChaCha20 — rdi: out, rsi: key, rdx: sixteen-byte nonce
// ============================================================================

.p2align 4
.globl FUNC(redoubt_hchacha_subkey)
HIDDEN_FUNC(redoubt_hchacha_subkey)
FUNC(redoubt_hchacha_subkey):
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: WORK holds the key spread into words, the state through
// ║ the rounds, and then the subkey itself. All of it is the long-term key or
// ║ something derived from it in one step.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + OUTPUT], rdi
    CHACHA_HSTATE rsi,rdx
    CHACHA_ROUNDS

    mov rdi, [rsp + OUTPUT]
    mov rax, [rsp + WORK]
    mov [rdi], rax
    mov rax, [rsp + WORK + 8]
    mov [rdi + 8], rax
    mov rax, [rsp + WORK + 48]
    mov [rdi + 16], rax
    mov rax, [rsp + WORK + 56]
    mov [rdi + 24], rax

    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
    ret

// ============================================================================
// ChaCha20 — rdi: key, rsi: nonce, rdx: counter, rcx: data,
//            r8: length, r9: nonce length (8 or 12)
// ============================================================================
//
// The safe backend wrapper validates the public counter range before entry.
//
.p2align 4
.globl FUNC(redoubt_chacha_xor)
HIDDEN_FUNC(redoubt_chacha_xor)
FUNC(redoubt_chacha_xor):
    // Nothing to encipher is answered here and not in the loop: no frame is
    // taken, so there is none to wipe, and the registers are the whole of what
    // this call touched.
    test r8, r8
    jnz Lchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

Lchacha_xor_body:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: INITIAL holds the key spread into words and the counter
// ║ it is streamed from; WORK, in the shared loop below, holds the state
// ║ through the rounds and then one keystream block.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced. This routine leaves through the loop's wipe, and only through it.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + OUTPUT], rcx
    mov [rsp + LENGTH], r8
    mov [rsp + MODE], r9

    CHACHA_CONSTANTS INITIAL
    .irp offset,0,8,16,24
        mov rax, [rdi + \offset]
        mov [rsp + INITIAL + 16 + \offset], rax
    .endr
    mov [rsp + INITIAL + 48], edx
    cmp r9, 8
    je Lbernstein_nonce

    mov eax, [rsi]
    mov [rsp + INITIAL + 52], eax
    mov rax, [rsi + 4]
    mov [rsp + INITIAL + 56], rax
    jmp Lblock

Lbernstein_nonce:
    shr rdx, 32
    mov [rsp + INITIAL + 52], edx
    mov rax, [rsi]
    mov [rsp + INITIAL + 56], rax
    jmp Lblock

// ============================================================================
// XChaCha20 — rdi: key, rsi: nonce, rdx: counter, rcx: data, r8: length
// ============================================================================

.p2align 4
.globl FUNC(redoubt_xchacha_xor)
HIDDEN_FUNC(redoubt_xchacha_xor)
FUNC(redoubt_xchacha_xor):
    // As above: nothing to encipher takes no frame, so the register wipe is
    // the whole of the cleanup.
    test r8, r8
    jnz Lxchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

Lxchacha_xor_body:
// ║ ⚠️  SPILL REGION BEGIN ═══════════════════════════════════════════════
// ║
// ║ SECURITY WARNING: WORK holds the key and the HChaCha state it is put
// ║ through, and INITIAL then holds the subkey that comes out of it — which is
// ║ what the whole message is enciphered with. The subkey never leaves the
// ║ frame: there is no intermediate output and no call back into Rust.
// ║
// ║ Frame is written before it is read, and zeroized in full before rsp is
// ║ advanced. This routine leaves through the loop's wipe, and only through it.
// ║
// ║═══════════════════════════════════════════════════════════════════════
    sub rsp, FRAME
    mov [rsp + OUTPUT], rcx
    mov [rsp + LENGTH], r8
    mov [rsp + MODE], rsi
    mov [rsp + COUNTER], rdx

    CHACHA_HSTATE rdi,rsi
    CHACHA_ROUNDS

    // Keep the subkey inside the frame. No Rust call or intermediate output.
    CHACHA_CONSTANTS INITIAL
    mov rax, [rsp + WORK]
    mov [rsp + INITIAL + 16], rax
    mov rax, [rsp + WORK + 8]
    mov [rsp + INITIAL + 24], rax
    mov rax, [rsp + WORK + 48]
    mov [rsp + INITIAL + 32], rax
    mov rax, [rsp + WORK + 56]
    mov [rsp + INITIAL + 40], rax
    mov eax, [rsp + COUNTER]
    mov [rsp + INITIAL + 48], eax
    mov dword ptr [rsp + INITIAL + 52], 0
    mov rsi, [rsp + MODE]
    mov rax, [rsi + 16]
    mov [rsp + INITIAL + 56], rax
    mov qword ptr [rsp + MODE], 12

// ============================================================================
// Shared stream loop — branches depend only on public lengths and counters
// ============================================================================
//
// Not a function and not called: the two routines above reach here and become
// it, one by jumping and one by running out of instructions before it. There
// is no way back to either.
//
// ENTERED WITH: INITIAL holding the sixteen state words, OUTPUT the next byte
//   to write, LENGTH what is left of the message, and MODE the nonce length.
//   Whoever jumps here has filled all four.
//
// LEFT BY: `jz Lempty_frame` below, and nothing else. The other two jumps come
//   back to the top. A branch out of here that skipped that one would skip the
//   frame wipe and the register wipe with it, and the assembler would not say
//   a word about it.
//
Lblock:
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rsp + INITIAL + \offset]
        mov [rsp + WORK + \offset], rax
    .endr
    CHACHA_ROUNDS
    .irp offset,0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60
        mov eax, [rsp + INITIAL + \offset]
        add [rsp + WORK + \offset], eax
    .endr

    mov rdi, [rsp + OUTPUT]
    mov rcx, [rsp + LENGTH]
    mov edx, 64
    cmp rcx, rdx
    cmova rcx, rdx
    xor esi, esi
Lbytes:
    movzx eax, byte ptr [rsp + WORK + rsi]
    xor byte ptr [rdi + rsi], al
    inc rsi
    cmp rsi, rcx
    jb Lbytes

    add [rsp + OUTPUT], rcx
    sub [rsp + LENGTH], rcx
    jz Lempty_frame

    cmp qword ptr [rsp + MODE], 8
    je Lbernstein_step
    add dword ptr [rsp + INITIAL + 48], 1
    jmp Lblock
Lbernstein_step:
    add dword ptr [rsp + INITIAL + 48], 1
    adc dword ptr [rsp + INITIAL + 52], 0
    jmp Lblock

// The loop's one exit, and the end of both spill regions that reach it.
Lempty_frame:
    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
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
//   clean_frame              the frame written and emptied, with no rounds

// uint64_t redoubt_chacha_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost rdi, and
// rdi is one of the registers being asked about — it would arrive holding our
// own pointer rather than the caller's value. With nothing passed, `call` is
// the whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_chacha_registers_are_zeroized)
HIDDEN_FUNC(redoubt_chacha_registers_are_zeroized)
FUNC(redoubt_chacha_registers_are_zeroized):
    // rcx gathers and rax is written last: rax's own value went in on the
    // first line, before anything here overwrote it, which is what lets it
    // carry the answer out.
    CHACHA_EACH CHACHA_GATHER
    mov rax, rcx
    ret

// uint64_t redoubt_chacha_frame_is_zeroized(void)
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
.globl FUNC(redoubt_chacha_frame_is_zeroized)
HIDDEN_FUNC(redoubt_chacha_frame_is_zeroized)
FUNC(redoubt_chacha_frame_is_zeroized):
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
.globl FUNC(redoubt_chacha_dirty_registers)
HIDDEN_FUNC(redoubt_chacha_dirty_registers)
FUNC(redoubt_chacha_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    CHACHA_EACH CHACHA_FILL
    ret

// One byte of the frame, dirtied and left. rdi says which.
//
// Swept over every offset, this is what establishes that the verifier above
// reads the whole frame and not the first word of it — and that the byte it
// reaches is the byte that was written, which is where an off-by-one against
// the return address sitting next door would show.
.p2align 4
.globl FUNC(redoubt_chacha_dirty_frame)
HIDDEN_FUNC(redoubt_chacha_dirty_frame)
FUNC(redoubt_chacha_dirty_frame):
    sub rsp, FRAME
    // Isolate this byte from every previous call's residue. Keep rdi, the
    // requested offset, intact until the whole frame is empty.
    xor ecx, ecx
Ldirty_clear:
    mov qword ptr [rsp + rcx], 0
    add rcx, 8
    cmp rcx, FRAME
    jb Ldirty_clear
    mov byte ptr [rsp + rdi], 0x5c
    add rsp, FRAME
    ret

// The whole frame written and then emptied: what a routine above does, without
// the rounds in between.
//
// The positive control. Without it, "the frame came back zero" is only ever
// asserted about routines whose correctness is what is in question.
.p2align 4
.globl FUNC(redoubt_chacha_clean_frame)
HIDDEN_FUNC(redoubt_chacha_clean_frame)
FUNC(redoubt_chacha_clean_frame):
    sub rsp, FRAME
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
Lclean_write:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, FRAME
    jb Lclean_write
    CHACHA_EMPTY_FRAME
    CHACHA_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
