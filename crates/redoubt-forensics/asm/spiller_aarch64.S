// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Every register, written where a sweep of memory can read it.
//
// The aarch64 half of the same idea as `x86_64.S`: a register is in no
// mapping, so nothing that reads memory can see one. Write them out and they
// are memory like anything else.
//
// # What is different here
//
// Two things, and both cost a register that the x86 form does not.
//
// A store on aarch64 has no PC-relative form. The address of the room has to
// be built into a register first, with `adrp` and `add`, so one general
// register is unavoidably in use for the whole capture. It is `x0`, saved on
// the stack before anything else and put back at the end, so the capture
// still leaves the register file exactly as it found it.
//
// And the indirect branch through the dispatch slot needs a register to hold
// the destination. That one is `x16` — `IP0`, the intra-procedure-call
// scratch register. The ABI lets a linker-inserted veneer clobber it between
// any caller and callee, so nothing may hold a live value there across a
// call, and it is the one register whose contents are already meaningless at
// this point.
//
// So `x0` reads back true and `x16`/`x17` do not. They are the aarch64
// equivalent of `rdi` on the other side: transit, not a resting place.
//
// # What is captured
//
// `x0-x30`, the stack pointer, and `v0-v31` at NEON's 128 bits.
//
// **Not SVE.** `z0-z31` are up to 2048 bits each and their width is not known
// until run time, which is a different capture and not a wider version of
// this one. Until it exists, nothing here says anything about what an SVE
// `memcpy` leaves behind — and on a machine with SVE that is most of the
// register file.
//
// # Layout
//
//     0     x0-x30, in order, eight bytes each
//     248   sp
//     256   one 64-byte slot per vector register, of which 16 are written

    .bss
    .globl redoubt_spill_room
    .type  redoubt_spill_room,@object
    .p2align 6
redoubt_spill_room:
    .zero 2304
    .size redoubt_spill_room, 2304

    .data
    .globl redoubt_spill_which
    .type  redoubt_spill_which,@object
    .p2align 3
redoubt_spill_which:
    .quad redoubt_spill_neon
    .size redoubt_spill_which, 8

    .text

// void redoubt_spill(void)
//
// Whichever form the slot holds. One form exists today; the slot is here so
// that an SVE capture can be added without moving the call sites, which is
// the one thing that cannot be moved.
    .globl redoubt_spill
    .type  redoubt_spill,@function
    .p2align 4
redoubt_spill:
    hint    #38                              // bti jc
    adrp    x16, redoubt_spill_which
    ldr     x16, [x16, :lo12:redoubt_spill_which]
    br      x16
    .size redoubt_spill, .-redoubt_spill

// void redoubt_spill_neon(void)
//
// The general registers, the stack pointer, and v0-v31.
    .globl redoubt_spill_neon
    .type  redoubt_spill_neon,@function
    .p2align 4
redoubt_spill_neon:
    hint    #38                              // bti jc

    // `x0` out of the way, and the room's address into it. This is the one
    // push: sixteen bytes, so the stack stays aligned, and undone at the end.
    str     x0, [sp, #-16]!
    adrp    x0, redoubt_spill_room
    add     x0, x0, :lo12:redoubt_spill_room

    // x1 through x30, which is fifteen pairs and no register left over.
    stp     x1,  x2,  [x0, #8]
    stp     x3,  x4,  [x0, #24]
    stp     x5,  x6,  [x0, #40]
    stp     x7,  x8,  [x0, #56]
    stp     x9,  x10, [x0, #72]
    stp     x11, x12, [x0, #88]
    stp     x13, x14, [x0, #104]
    stp     x15, x16, [x0, #120]
    stp     x17, x18, [x0, #136]
    stp     x19, x20, [x0, #152]
    stp     x21, x22, [x0, #168]
    stp     x23, x24, [x0, #184]
    stp     x25, x26, [x0, #200]
    stp     x27, x28, [x0, #216]
    stp     x29, x30, [x0, #232]

    // One slot per vector register and not a run of them, so that the room
    // reads the same way it does on the other architecture.
    str     q0,  [x0, #256]
    str     q1,  [x0, #320]
    str     q2,  [x0, #384]
    str     q3,  [x0, #448]
    str     q4,  [x0, #512]
    str     q5,  [x0, #576]
    str     q6,  [x0, #640]
    str     q7,  [x0, #704]
    str     q8,  [x0, #768]
    str     q9,  [x0, #832]
    str     q10, [x0, #896]
    str     q11, [x0, #960]
    str     q12, [x0, #1024]
    str     q13, [x0, #1088]
    str     q14, [x0, #1152]
    str     q15, [x0, #1216]
    str     q16, [x0, #1280]
    str     q17, [x0, #1344]
    str     q18, [x0, #1408]
    str     q19, [x0, #1472]
    str     q20, [x0, #1536]
    str     q21, [x0, #1600]
    str     q22, [x0, #1664]
    str     q23, [x0, #1728]
    str     q24, [x0, #1792]
    str     q25, [x0, #1856]
    str     q26, [x0, #1920]
    str     q27, [x0, #1984]
    str     q28, [x0, #2048]
    str     q29, [x0, #2112]
    str     q30, [x0, #2176]
    str     q31, [x0, #2240]

    // `x1` is safe to borrow now that its own value is written down. The
    // caller's `x0` comes back off the stack, and the caller's `sp` is where
    // the stack pointer was before the push.
    ldr     x1, [sp]
    str     x1, [x0, #0]
    add     x1, sp, #16
    str     x1, [x0, #248]

    // And both borrowed registers back to what they were, so that what this
    // leaves behind is the copy in the room and nothing else.
    ldr     x1, [x0, #8]
    ldr     x0, [sp], #16
    ret
    .size redoubt_spill_neon, .-redoubt_spill_neon

    .section .note.GNU-stack,"",@progbits
