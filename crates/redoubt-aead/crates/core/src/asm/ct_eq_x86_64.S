// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Constant-time byte comparison - x86_64 (SysV ABI) Implementation
//
// Baseline x86_64. No SSE, no AVX, nothing to detect at runtime: one byte at a
// time through the general registers. That is slower than what the compiler
// writes for the same loop, and the whole point.
//
// Why this is not left to Rust:
//   The portable version folds the differences into an accumulator and hands
//   it to `core::hint::black_box` so the optimizer cannot prove the loop away.
//   What `black_box` does is materialize the value and forbid reasoning about
//   it — so the one instruction there to protect the timing is the one that
//   guarantees the fold survives somewhere nothing wipes. And at sixteen bytes
//   the loop above it vectorizes: both operands land in xmm registers, which
//   every register budget in this workspace deliberately excludes, because
//   until now nothing here wrote one.
//
// What is being protected:
//   The computed tag. On a verification that fails, that tag is the forgery for
//   that key, nonce and message, and it is exactly the case where the caller
//   goes on to do something else with the machine.
//
// No frame, and it is not an optimization:
//   An accumulator, an index and one byte of each operand is everything held at
//   once, and the budget below has room. So nothing is written to the stack and
//   there is nothing to wipe there — checkable by reading, since `sub rsp`,
//   `push` and `pop` appear nowhere in this file. That is also why the probe at
//   the end asks only about registers: a spill here cannot arrive without
//   somebody typing one, which is not the silent kind of failure a probe is for.
//
// Platform Support:
//   - Linux x86_64 (SysV ABI)
//   - macOS x86_64 (SysV ABI)
//   - Windows x86_64 EXCLUDED: Win64 passes its first arguments in rcx, rdx,
//     r8 and r9. This file is SysV throughout. The build script compiles no
//     assembly there and the crate falls back to the Rust, which answers the
//     same and promises less.
//
// What crosses into here, and what does not:
//   Every argument is a pointer to storage the caller declared, except the
//   length, which is the width of a tag and public. Nothing is returned: the
//   answer is written through the pointer the caller named, and it is one byte
//   holding one or zero. The folded accumulator is not that byte and never
//   leaves — it is the exclusive-or of the two tags, and a caller has no use
//   for it that is not an attack.
//
// What must not branch:
//   The loop runs the full length whatever it finds, and the fold to one or
//   zero is `sete`, which reads the flags rather than jumping on them. The only
//   branches are on the length, which is public.
//
// What this cannot answer for:
//   The bytes are held in registers this file named and wiped. That is a
//   statement about this file, not about the machine. When a signal is
//   delivered the kernel writes the whole register context to a frame on the
//   user stack, and nothing in user space wipes that frame on the way back. The
//   same goes for a core dump, for a page that reached swap, and for anything
//   ptrace can read.
//
// References:
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
// The comparison writes seven of the nine, and r10 and r11 are in the list
// anyway. Two `xor` are cheaper than the day somebody reaches for a spare
// register here and the verifier, asked about seven, says nothing about it.
//
// Does NOT include: rsp, rbx, rbp, r12-r15. Nothing here puts anything in
// them, so there is nothing of ours to clear — and no prologue saving them,
// which means no copy of the caller's values in memory for an epilogue to take
// back out.
//
// Does NOT include the SIMD registers, and that is the reason this file
// exists: nothing here writes one, so there is nothing of ours in them. The
// compiler's version of this loop puts both tags there and nothing clears them.
//
.macro CT_EACH op
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

.macro CT_CLEAR reg
    xor \reg, \reg
.endm

// Copies what rax already holds into each of them, rax included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro CT_FILL reg
    mov \reg, rax
.endm

// Gathers into rcx, which is in the budget and therefore contributes its own
// value on its own line. What the gather leaves in rcx is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro CT_GATHER reg
    or rcx, \reg
.endm

// ============================================================================
// Catastrophic Register Zeroization Macro (caller-saved only)
// ============================================================================
.macro CT_ZEROIZE_ALL
    CT_EACH CT_CLEAR
.endm

// ============================================================================
// Constant-time comparison — rdi: a, rsi: b, rdx: length, rcx: out
// ============================================================================
//
// Writes one to the byte at rcx when the two runs of `length` bytes are equal,
// and zero when they are not. A length of zero writes one: nothing differs.
//
// The caller checks that the two lengths agree. Two runs of different length
// are not a timing question, they are a public fact about the message.
//
.p2align 4
.globl FUNC(redoubt_ct_eq)
HIDDEN_FUNC(redoubt_ct_eq)
FUNC(redoubt_ct_eq):
    // r8 accumulates the differences and r9 indexes. Both start empty, which
    // is also the answer for a length of zero.
    xor r8d, r8d
    xor r9d, r9d
    test rdx, rdx
    jz Lfold

Lbyte:
    mov al, [rdi + r9]
    xor al, [rsi + r9]
    or r8b, al
    inc r9
    cmp r9, rdx
    jb Lbyte

Lfold:
    // One when nothing differed, zero otherwise. `sete` reads the flags the
    // test set; it does not jump on them, so neither answer is a shorter path
    // than the other.
    test r8b, r8b
    sete al
    mov [rcx], al

    CT_ZEROIZE_ALL
    ret

// ============================================================================
// THE ZEROIZATION PROBE — everything below measures the routine above
// ============================================================================
//
// Nothing in production calls any of it. It is here and not in a file of its
// own because a reader asking whether the measurement is right should not have
// to find a second file and check that the register list in it still matches
// the one the wipe uses.
//
// There is no stack half of it. Nothing above takes a frame, and in a file
// this size a spill cannot arrive without somebody typing `sub rsp` — which a
// diff shows and a probe is not needed for.
//
// What asks comes first, then what is asked about:
//
//   registers_are_zeroized   asks the machine, with the budget's own list
//   dirty_registers          fills the budget and leaves it that way

// uint64_t redoubt_ct_registers_are_zeroized(void)
//
// Whether any register in the budget is still holding something. Zero when
// they are all empty, and the bits of whatever was not otherwise.
//
// Takes no argument on purpose. A destination passed in would cost rdi, and
// rdi is one of the registers being asked about — it would arrive holding our
// own pointer rather than the caller's value. With nothing passed, `call` is
// the whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_ct_registers_are_zeroized)
HIDDEN_FUNC(redoubt_ct_registers_are_zeroized)
FUNC(redoubt_ct_registers_are_zeroized):
    // rcx gathers and rax is written last: rax's own value went in on the
    // first line, before anything here overwrote it, which is what lets it
    // carry the answer out.
    CT_EACH CT_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_ct_dirty_registers)
HIDDEN_FUNC(redoubt_ct_dirty_registers)
FUNC(redoubt_ct_dirty_registers):
    mov rax, 0xa5a5a5a5a5a5a5a5
    CT_EACH CT_FILL
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
