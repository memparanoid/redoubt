// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// The kernel's random bytes written straight into the caller's buffer, and
// nothing of them left in a register — x86-64.
//
// Platforms: Linux, SysV. The syscall number is Linux's; nothing else is built.
// No runtime feature detection: baseline x86-64, general registers and
//   `syscall`. `endbr64` is a NOP where CET is off.
// No vector register is written, and `syscall` preserves them, so none is in
//   the budget.
// Crossing: a pointer to the caller's buffer, its length (public, at most 256,
//   which the caller keeps it to), and a pointer to one byte for the answer.
//   Nothing is returned.
// Branches: on what the kernel answers, never on the bytes.
// Not answered for: what the kernel keeps in its own memory, what other code
//   left in registers, the buffer itself, a signal frame, a core dump, swap,
//   ptrace.
// The routine takes no frame, so the probe has no stack half.

.intel_syntax noprefix
.text

#if !defined(__x86_64__) || !defined(__linux__)
#error "Requires Linux x86-64"
#endif

// The whole caller-saved set, the caller's pointers included: the probe asks
// about this list, and a shorter one would stop covering a register the day the
// routine reaches for it. `syscall` itself writes rcx and r11.
.macro RAND_EACH op
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

.macro RAND_CLEAR reg
    xor \reg, \reg
.endm

.macro RAND_FILL reg
    mov \reg, rax
.endm

.macro RAND_GATHER reg
    or rcx, \reg
.endm

.macro RAND_ZEROIZE_ALL
    RAND_EACH RAND_CLEAR
.endm

.set SYS_GETRANDOM, 318
.set EINTR, 4

// ============================================================================
// redoubt_rand_fill
// ============================================================================
//
// void redoubt_rand_fill(uint8_t *dst, size_t len, uint8_t *answer)
// rdi = dst, rsi = len, rdx = answer.

.global redoubt_rand_fill
.hidden redoubt_rand_fill
.type redoubt_rand_fill, @function
.p2align 4
redoubt_rand_fill:
    .cfi_startproc
    endbr64
    // The answer's pointer leaves rdx first: rdx is the syscall's flags.
    mov r8, rdx
.Lfill_ask:
    mov eax, SYS_GETRANDOM
    xor edx, edx
    syscall
    cmp rax, rsi
    je .Lfill_filled
    // Only an interruption is asked again. Up to 256 bytes the kernel returns
    // all of them once its pool is ready, and a signal can cut only the wait
    // before that.
    cmp rax, -EINTR
    je .Lfill_ask
    xor ecx, ecx
    jmp .Lfill_answer
.Lfill_filled:
    mov ecx, 1
    // The answer goes out through r8 before the wipe empties it.
.Lfill_answer:
    mov byte ptr [r8], cl
    RAND_ZEROIZE_ALL
    ret
    .cfi_endproc
.size redoubt_rand_fill, .-redoubt_rand_fill

// ============================================================================
// THE ZEROIZATION PROBE
// ============================================================================

// uint64_t redoubt_rand_registers_are_zeroized(void)
// Zero when every register in the budget is empty. rax is folded first, before
// it carries the answer; no argument, because rdi is one of the registers asked
// about.
.global redoubt_rand_registers_are_zeroized
.hidden redoubt_rand_registers_are_zeroized
.p2align 4
redoubt_rand_registers_are_zeroized:
    RAND_EACH RAND_GATHER
    mov rax, rcx
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global redoubt_rand_dirty_registers
.hidden redoubt_rand_dirty_registers
.p2align 4
redoubt_rand_dirty_registers:
    mov rax, 0xa5a5a5a5a5a5a5a5
    RAND_EACH RAND_FILL
    ret

.section .note.GNU-stack,"",@progbits
