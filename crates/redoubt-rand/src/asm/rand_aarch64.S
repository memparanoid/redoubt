// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// The kernel's random bytes written straight into the caller's buffer, and
// nothing of them left in a register — AArch64.
//
// Platforms: Linux, AAPCS64. The syscall number is Linux's; nothing else is
//   built.
// No runtime feature detection: base A64, general registers and `svc`.
//   `hint #34` is BTI c, a NOP where branch targets are not enforced.
// No vector register is written, and `svc` preserves them, so none is in the
//   budget.
// Crossing: a pointer to the caller's buffer, its length (public, at most 256,
//   which the caller keeps it to), and a pointer to one byte for the answer.
//   Nothing is returned.
// Branches: on what the kernel answers, never on the bytes.
// Not answered for: what the kernel keeps in its own memory, what other code
//   left in registers, the buffer itself, a signal frame, a core dump, swap,
//   ptrace.
// The routine takes no frame, so the probe has no stack half.

.text

#if !defined(__aarch64__) || !defined(__linux__)
#error "Requires Linux AArch64"
#endif

// The whole caller-saved set, the caller's pointers included: the probe asks
// about this list, and a shorter one would stop covering a register the day the
// routine reaches for it. Not x18 (the platform register), not x30 (every `bl`
// writes it).
.macro RAND_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro RAND_CLEAR reg
    mov \reg, xzr
.endm

.macro RAND_FILL reg
    mov \reg, x0
.endm

.macro RAND_GATHER reg
    orr x1, x1, \reg
.endm

.macro RAND_ZEROIZE_ALL
    RAND_EACH RAND_CLEAR
.endm

.set SYS_GETRANDOM, 278
.set EINTR, 4

// ============================================================================
// redoubt_rand_fill
// ============================================================================
//
// void redoubt_rand_fill(uint8_t *dst, size_t len, uint8_t *answer)
// x0 = dst, x1 = len, x2 = answer.

.global redoubt_rand_fill
.hidden redoubt_rand_fill
.type redoubt_rand_fill, %function
.p2align 4
redoubt_rand_fill:
    .cfi_startproc
    hint #34
    // Both pointers leave their registers first: the kernel answers in x0, and
    // x2 is the syscall's flags.
    mov x3, x0
    mov x4, x2
.Lfill_ask:
    mov x0, x3
    mov x2, #0
    mov x8, #SYS_GETRANDOM
    svc #0
    cmp x0, x1
    b.eq .Lfill_filled
    // Only an interruption is asked again. Up to 256 bytes the kernel returns
    // all of them once its pool is ready, and a signal can cut only the wait
    // before that.
    cmn x0, #EINTR
    b.eq .Lfill_ask
    mov w5, #0
    b .Lfill_answer
.Lfill_filled:
    mov w5, #1
    // The answer goes out through x4 before the wipe empties it.
.Lfill_answer:
    strb w5, [x4]
    RAND_ZEROIZE_ALL
    ret
    .cfi_endproc
.size redoubt_rand_fill, .-redoubt_rand_fill

// ============================================================================
// THE ZEROIZATION PROBE
// ============================================================================

// uint64_t redoubt_rand_registers_are_zeroized(void)
// Zero when every register in the budget is empty. x0 is folded first, before
// it carries the answer; no argument, because x0 is one of the registers asked
// about.
.global redoubt_rand_registers_are_zeroized
.hidden redoubt_rand_registers_are_zeroized
.p2align 4
redoubt_rand_registers_are_zeroized:
    RAND_EACH RAND_GATHER
    mov x0, x1
    ret

// Every register in the budget filled with 0xa5, and left that way.
.global redoubt_rand_dirty_registers
.hidden redoubt_rand_dirty_registers
.p2align 4
redoubt_rand_dirty_registers:
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    RAND_EACH RAND_FILL
    ret

.section .note.GNU-stack,"",%progbits
