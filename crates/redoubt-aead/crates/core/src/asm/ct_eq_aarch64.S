// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Constant-time byte comparison - AArch64 (AAPCS) Implementation
//
// Baseline AArch64. No NEON, no SVE, nothing to detect at runtime: one byte at
// a time through the general registers. That is slower than what the compiler
// writes for the same loop, and the whole point.
//
// Why this is not left to Rust:
//   The portable version folds the differences into an accumulator and hands
//   it to `core::hint::black_box` so the optimizer cannot prove the loop away.
//   What `black_box` does is materialize the value and forbid reasoning about
//   it — so the one instruction there to protect the timing is the one that
//   guarantees the fold survives somewhere nothing wipes. At sixteen bytes the
//   loop around it vectorizes, and both operands land in vector registers that
//   nothing then clears.
//
// What is being protected:
//   The computed tag. On a verification that fails, that tag is the forgery for
//   that key, nonce and message, and it is exactly the case where the caller
//   goes on to do something else with the machine.
//
// No frame, and it is not an optimization:
//   An accumulator, an index and one byte of each operand is everything held at
//   once, and the budget below has room. So nothing is written to the stack and
//   there is nothing to wipe there — checkable by reading, since `sub sp`,
//   `stp` and `str` to the stack appear nowhere in this file. That is also why
//   the probe at the end asks only about registers: a spill here cannot arrive
//   without somebody typing one, which is not the silent kind of failure a
//   probe is for.
//
// Platform Support:
//   - Linux aarch64 (AAPCS)
//   - macOS aarch64 (AAPCS, with the leading underscore below)
//   - Windows aarch64 EXCLUDED: the build script compiles no assembly there
//     and the crate falls back to the Rust, which answers the same and promises
//     less.
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
//   zero is `cset`, which reads the flags rather than branching on them. The
//   only branches are on the length, which is public.
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
// - Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64)

.text

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// The register budget
// ============================================================================
//
// AAPCS:
//   - Caller-saved GPR: x0-x17
//   - Platform register: x18            (DO NOT TOUCH)
//   - Callee-saved GPR: x19-x28, x29 (FP), x30 (LR)  (DO NOT TOUCH)
//
// Every register this file puts anything in is named once, below, and every
// operation over the set goes through that one list. A register added to the
// wipe and missing from the verifier is a register nothing looks at, silently.
//
// The list is the whole caller-saved set, including registers the comparison
// never writes, so the verifier still asks about them the day somebody reaches
// for a spare.
//
// Does NOT include: x18 is the platform register, and x19 upward are the
// caller's. x30 is where `bl` puts the return address, so asking a verifier
// about it would be asking about the call that reached the verifier.
//
// Does NOT include the vector registers, and that is the reason this file
// exists: nothing here writes one, so there is nothing of ours in them. The
// compiler's version of this loop puts both tags there and nothing clears them.
//
.macro CT_EACH op
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        \op x\reg
    .endr
.endm

.macro CT_CLEAR reg
    mov \reg, xzr
.endm

// Copies what x0 already holds into each of them, x0 included and harmless.
// Only the probe below uses it, and it is here rather than there so that the
// budget has one list and every operation over it sits beside that list.
.macro CT_FILL reg
    mov \reg, x0
.endm

// Gathers into x1, which is in the list and therefore contributes its own
// value on its own line. What the gather leaves in x1 is the bits of anything
// that was not empty. The probe below is its only caller, and it is here for
// the same reason FILL is.
.macro CT_GATHER reg
    orr x1, x1, \reg
.endm

// The `cmp` is not a register: `mov` leaves the flags alone, so without it the
// flags would still say whether the two runs were equal.
.macro CT_ZEROIZE_ALL
    CT_EACH CT_CLEAR
    cmp xzr, xzr
.endm

// ============================================================================
// ct_eq
// ============================================================================
//
// C signature:
//   void redoubt_ct_eq(const uint8_t *a, const uint8_t *b, size_t len,
//                      uint8_t *out);
//
// Parameters (AAPCS):
//   x0: a, x1: b, x2: len, x3: out
//
// Writes one to `out` when the two runs of `len` bytes are equal, and zero when
// they are not. A length of zero writes one: nothing differs.
//
// The caller checks that the two lengths agree. Two runs of different length
// are not a timing question, they are a public fact about the message.
.p2align 4
.globl FUNC(redoubt_ct_eq)
HIDDEN_FUNC(redoubt_ct_eq)
FUNC(redoubt_ct_eq):
    // w4 accumulates the differences and x5 indexes. Both start empty, which
    // is also the answer for a length of zero.
    mov w4, wzr
    mov x5, xzr
    cbz x2, .Lfold

.Lbyte:
    ldrb w6, [x0, x5]
    ldrb w7, [x1, x5]
    eor w6, w6, w7
    orr w4, w4, w6
    add x5, x5, #1
    cmp x5, x2
    b.lo .Lbyte

.Lfold:
    // One when nothing differed, zero otherwise. `cset` reads the flags the
    // compare set; it does not branch on them, so neither answer is a shorter
    // path than the other.
    cmp w4, wzr
    cset w6, eq
    strb w6, [x3]

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
// this size a spill cannot arrive without somebody typing `sub sp` — which a
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
// Takes no argument on purpose. A destination passed in would cost x0, and x0
// is one of the registers being asked about — it would arrive holding our own
// pointer rather than the caller's value. With nothing passed, `bl` is the
// whole call sequence and every register read here is the caller's own.
.p2align 4
.globl FUNC(redoubt_ct_registers_are_zeroized)
HIDDEN_FUNC(redoubt_ct_registers_are_zeroized)
FUNC(redoubt_ct_registers_are_zeroized):
    CT_EACH CT_GATHER
    mov x0, x1
    ret

// Every register in the budget filled, and left that way.
//
// What answers whether anything runs between one call and the next: called
// straight before the verifier, every register it filled has to still be full.
.p2align 4
.globl FUNC(redoubt_ct_dirty_registers)
HIDDEN_FUNC(redoubt_ct_dirty_registers)
FUNC(redoubt_ct_dirty_registers):
    // The pattern does not fit in one instruction, so it is built sixteen bits
    // at a time before anything is copied out of x0.
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    CT_EACH CT_FILL
    ret

// ============================================================================
// Stack permissions
// ============================================================================
//
// An object with no .note.GNU-stack is one the linker assumes wants an
// executable stack, and one such object gives it to the whole binary. Nothing
// here needs one.
#if !defined(__APPLE__)
.section .note.GNU-stack,"",%progbits
#endif
