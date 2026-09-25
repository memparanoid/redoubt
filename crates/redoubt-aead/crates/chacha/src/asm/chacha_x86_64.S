// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// ChaCha20, HChaCha20 and XChaCha20 - x86_64 (SysV ABI) Implementation
//
// The floor is the x86-64 baseline: scalar integer instructions only, nothing
// detected at runtime.
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes arguments in other registers and
//     keeps rsi and rdi callee-saved. The build script compiles no assembly there.
//
// Every argument is a pointer to storage the caller declared, except the
// counter and the lengths, which are public. Nothing is returned.
//
// Nothing branches on a secret: the stream loop and the nonce layout branch on
// lengths only.
//
// What this cannot answer for:
//   A signal delivered mid-routine has the kernel write the whole register
//   context to a frame on the user stack that nothing in user space wipes. The
//   same for a core dump, a page that reached swap, and anything ptrace can
//   read.
//
// References:
// - RFC 8439, sections 2.1 to 2.4
// - draft-irtf-cfrg-xchacha, section 2.2
// - System V AMD64 ABI, section 3.2.3

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
// Every register these routines put anything in is named once, here, and every
// operation over the set goes through this list. A register added to the wipe
// and missing from the verifier is a register nothing looks at, silently.
//
// SysV AMD64 makes rax, rcx, rdx, rsi, rdi and r8-r11 caller-saved, and rbx,
// rbp and r12-r15 callee-saved. Nothing here writes one of the second kind:
// saving one would spill the caller's value into this file's stack. Nothing
// here writes a vector register.
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

// Copies what rax already holds into each, itself included. Used by the probe.
.macro CHACHA_FILL reg
    mov \reg, rax
.endm

// Folds each into rcx, which is in the list and so contributes its own value.
// Used by the probe.
.macro CHACHA_GATHER reg
    or rcx, \reg
.endm

.macro CHACHA_ZEROIZE_ALL
    CHACHA_EACH CHACHA_CLEAR
.endm

// ============================================================================
// Frame layout
// ============================================================================
//
//   INITIAL   0..63    the state before the rounds, the XChaCha subkey in it
//   WORK     64..127   the state through the rounds, then one keystream block
//   OUTPUT  128..135   the caller's pointer, then the next byte of data
//   LENGTH  136..143   how much of the data is left
//   MODE    144..151   the nonce length; XChaCha's nonce address until then
//   COUNTER 152..159   the XChaCha counter, held across HChaCha
//           160..167   padding
//
// Four state words at a time fit in the budget, in eax, ecx, edx and r8d; the
// rest stay in WORK. FRAME is congruent to eight modulo sixteen, which puts rsp
// back on a boundary after `call`.
.set INITIAL, 0
.set WORK, 64
.set OUTPUT, 128
.set LENGTH, 136
.set MODE, 144
.set COUNTER, 152
.set FRAME, 168

// ============================================================================
// Frame wipe
// ============================================================================

// Every qword of the frame, padding included, then the frame given back.
.macro CHACHA_EMPTY_FRAME
    .set _empty_at, 0
    .rept FRAME / 8
        mov qword ptr [rsp + _empty_at], 0
        .set _empty_at, _empty_at + 8
    .endr
    add rsp, FRAME
.endm

// RFC 8439's quarter round over four words of WORK. The addresses and the
// rotations are fixed: nothing here depends on the state.
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

// Twenty rounds over WORK, as ten double rounds: the columns, then the
// diagonals.
.macro CHACHA_ROUNDS
    mov r9d, 10
.Lrounds\@:
    CHACHA_QUARTER 0,4,8,12
    CHACHA_QUARTER 1,5,9,13
    CHACHA_QUARTER 2,6,10,14
    CHACHA_QUARTER 3,7,11,15
    CHACHA_QUARTER 0,5,10,15
    CHACHA_QUARTER 1,6,11,12
    CHACHA_QUARTER 2,7,8,13
    CHACHA_QUARTER 3,4,9,14
    dec r9d
    jnz .Lrounds\@
.endm

// "expand 32-byte k", the first four words of a state at `at`.
.macro CHACHA_CONSTANTS at
    mov dword ptr [rsp + \at],      0x61707865
    mov dword ptr [rsp + \at + 4],  0x3320646e
    mov dword ptr [rsp + \at + 8],  0x79622d32
    mov dword ptr [rsp + \at + 12], 0x6b206574
.endm

// The HChaCha state in WORK: the constants, the key and the first sixteen bytes
// of the nonce. Writes only rax, so `key` and `nonce` may be any other register.
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
// chacha_rounds
// ============================================================================
//
// C signature:
//   void redoubt_chacha_rounds(uint32_t state[16]);
//
// Parameters (SysV ABI):
//   rdi: state (read and written)
//
// The rounds alone, with no feed-forward: the block function's core, reached
// only by the tests.
.p2align 4
.globl FUNC(redoubt_chacha_rounds)
HIDDEN_FUNC(redoubt_chacha_rounds)
#if !defined(__APPLE__)
.type FUNC(redoubt_chacha_rounds), @function
#endif
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

#if !defined(__APPLE__)
.size FUNC(redoubt_chacha_rounds), .-FUNC(redoubt_chacha_rounds)
#endif

// ============================================================================
// hchacha_subkey
// ============================================================================
//
// C signature:
//   void redoubt_hchacha_subkey(uint8_t out[32], const uint8_t key[32],
//                               const uint8_t nonce[16]);
//
// Parameters (SysV ABI):
//   rdi: out (written), rsi: key (read only), rdx: nonce (read only)
//
// The subkey is words 0-3 and 12-15 of the state after the rounds.
.p2align 4
.globl FUNC(redoubt_hchacha_subkey)
HIDDEN_FUNC(redoubt_hchacha_subkey)
#if !defined(__APPLE__)
.type FUNC(redoubt_hchacha_subkey), @function
#endif
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

#if !defined(__APPLE__)
.size FUNC(redoubt_hchacha_subkey), .-FUNC(redoubt_hchacha_subkey)
#endif

// ============================================================================
// chacha_xor
// ============================================================================
//
// C signature:
//   void redoubt_chacha_xor(const uint8_t key[32], const uint8_t *nonce,
//                           uint64_t counter, uint8_t *data, size_t len,
//                           size_t nonce_len);
//
// Parameters (SysV ABI):
//   rdi: key (read only), rsi: nonce (read only), rdx: counter, rcx: data
//   (read and written), r8: len, r9: nonce_len (8 or 12)
//
// The counter is not checked here: the Rust caller refuses one the data would
// run past.
.p2align 4
.globl FUNC(redoubt_chacha_xor)
HIDDEN_FUNC(redoubt_chacha_xor)
#if !defined(__APPLE__)
.type FUNC(redoubt_chacha_xor), @function
#endif
FUNC(redoubt_chacha_xor):
    // Nothing to encipher returns here: no frame is taken, and the register
    // wipe is the whole of the cleanup.
    test r8, r8
    jnz .Lchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

.Lchacha_xor_body:
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
    // RFC 8439's layout, a 32-bit counter and a twelve-byte nonce, unless the
    // nonce is eight bytes: then Bernstein's, a 64-bit counter in words 12 and
    // 13.
    mov [rsp + INITIAL + 48], edx
    cmp r9, 8
    je .Lbernstein_nonce

    mov eax, [rsi]
    mov [rsp + INITIAL + 52], eax
    mov rax, [rsi + 4]
    mov [rsp + INITIAL + 56], rax
    jmp .Lblock

.Lbernstein_nonce:
    shr rdx, 32
    mov [rsp + INITIAL + 52], edx
    mov rax, [rsi]
    mov [rsp + INITIAL + 56], rax
    jmp .Lblock

#if !defined(__APPLE__)
.size FUNC(redoubt_chacha_xor), .-FUNC(redoubt_chacha_xor)
#endif

// ============================================================================
// xchacha_xor
// ============================================================================
//
// C signature:
//   void redoubt_xchacha_xor(const uint8_t key[32], const uint8_t nonce[24],
//                            uint64_t counter, uint8_t *data, size_t len);
//
// Parameters (SysV ABI):
//   rdi: key (read only), rsi: nonce (read only), rdx: counter, rcx: data
//   (read and written), r8: len
//
// The subkey is made and used inside one frame, and never written out. The
// counter is not checked here: the Rust caller refuses one the data would run
// past.
.p2align 4
.globl FUNC(redoubt_xchacha_xor)
HIDDEN_FUNC(redoubt_xchacha_xor)
#if !defined(__APPLE__)
.type FUNC(redoubt_xchacha_xor), @function
#endif
FUNC(redoubt_xchacha_xor):
    // Nothing to encipher returns here: no frame is taken, and the register
    // wipe is the whole of the cleanup.
    test r8, r8
    jnz .Lxchacha_xor_body
    CHACHA_ZEROIZE_ALL
    ret

.Lxchacha_xor_body:
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

    // RFC 8439's layout over the subkey: the counter, four zero bytes and the
    // last eight bytes of the nonce. MODE is twelve from here on.
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
// The shared stream loop
// ============================================================================
//
// Not a function and not called: `chacha_xor` reaches here by jumping and
// `xchacha_xor` by running out of instructions before it, and both become it.
// There is no way back to either.
//
// ENTERED WITH: INITIAL holding the state words, OUTPUT the next byte to write,
//   LENGTH what is left of the data, and MODE the nonce length. Whoever reaches
//   here has filled them.
//
// LEFT BY: `jz .Lempty_frame` below, and nothing else; every other jump goes
//   back to the top. A branch out of here that skipped it would skip the frame
//   wipe and the register wipe with it, and the assembler would not say a word
//   about it.
.Lblock:
    .irp offset,0,8,16,24,32,40,48,56
        mov rax, [rsp + INITIAL + \offset]
        mov [rsp + WORK + \offset], rax
    .endr
    CHACHA_ROUNDS
    .irp offset,0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60
        mov eax, [rsp + INITIAL + \offset]
        add [rsp + WORK + \offset], eax
    .endr

    // At most one block of the data, a byte at a time: nothing is read or
    // written past the caller's slice.
    mov rdi, [rsp + OUTPUT]
    mov rcx, [rsp + LENGTH]
    mov edx, 64
    cmp rcx, rdx
    cmova rcx, rdx
    xor esi, esi
.Lbytes:
    movzx eax, byte ptr [rsp + WORK + rsi]
    xor byte ptr [rdi + rsi], al
    inc rsi
    cmp rsi, rcx
    jb .Lbytes

    add [rsp + OUTPUT], rcx
    sub [rsp + LENGTH], rcx
    jz .Lempty_frame

    cmp qword ptr [rsp + MODE], 8
    je .Lbernstein_step
    add dword ptr [rsp + INITIAL + 48], 1
    jmp .Lblock
.Lbernstein_step:
    // The 64-bit counter, carried from word 12 into word 13.
    add dword ptr [rsp + INITIAL + 48], 1
    adc dword ptr [rsp + INITIAL + 52], 0
    jmp .Lblock

// The loop's one exit, and the end of every spill region that reaches it.
.Lempty_frame:
    CHACHA_EMPTY_FRAME
// ║ ⚠️  SPILL REGION END (ZEROIZED) ══════════════════════════════════════

    CHACHA_ZEROIZE_ALL
    ret

#if !defined(__APPLE__)
.size FUNC(redoubt_xchacha_xor), .-FUNC(redoubt_xchacha_xor)
#endif

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routines above
// ============================================================================

// uint64_t redoubt_chacha_registers_are_zeroized(void)
//
// Zero when every register in the budget is empty, the bits of whatever was not
// otherwise. It takes no argument because rdi is one of the registers asked
// about, and a pointer passed in would arrive where the caller's value was.
.p2align 4
.globl FUNC(redoubt_chacha_registers_are_zeroized)
HIDDEN_FUNC(redoubt_chacha_registers_are_zeroized)
FUNC(redoubt_chacha_registers_are_zeroized):
    CHACHA_EACH CHACHA_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled with a pattern, and left that way.
.p2align 4
.globl FUNC(redoubt_chacha_dirty_registers)
HIDDEN_FUNC(redoubt_chacha_dirty_registers)
FUNC(redoubt_chacha_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    CHACHA_EACH CHACHA_FILL
    ret

// The frame instruments for a frame of \size bytes.
//
// uint64_t redoubt_chacha_frame_is_zeroized_\name(void)
//
//   Zero when every byte of the frame the previous call used is empty. `call`
//   leaves rsp where the previous callee found it, so the return address lands
//   in the same slot and `[rsp - \size, rsp)` is the frame that callee took.
//   Asked after the registers, never before: reading the frame takes registers.
//
// void redoubt_chacha_dirty_frame_\name(size_t at)
//
//   One byte of the frame, at the offset in rdi, marked and left.
//
// void redoubt_chacha_clean_frame_\name(void)
//
//   The whole frame written and emptied, which is what a routine does without
//   the work in between.
.macro CHACHA_FRAME_PROBE name, size
.p2align 4
.globl FUNC(redoubt_chacha_frame_is_zeroized_\name)
HIDDEN_FUNC(redoubt_chacha_frame_is_zeroized_\name)
FUNC(redoubt_chacha_frame_is_zeroized_\name):
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
.globl FUNC(redoubt_chacha_dirty_frame_\name)
HIDDEN_FUNC(redoubt_chacha_dirty_frame_\name)
FUNC(redoubt_chacha_dirty_frame_\name):
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
.globl FUNC(redoubt_chacha_clean_frame_\name)
HIDDEN_FUNC(redoubt_chacha_clean_frame_\name)
FUNC(redoubt_chacha_clean_frame_\name):
    sub rsp, \size
    mov rax, 0x5c5c5c5c5c5c5c5c
    xor ecx, ecx
3:
    mov [rsp + rcx], rax
    add rcx, 8
    cmp rcx, \size
    jb 3b
    CHACHA_EMPTY_FRAME
    CHACHA_ZEROIZE_ALL
    ret
.endm

CHACHA_FRAME_PROBE chacha, FRAME

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
