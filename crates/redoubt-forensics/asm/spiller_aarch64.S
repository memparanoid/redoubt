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
// `x0-x30`, the stack pointer, and the vector registers — `v0-v31` at NEON's
// 128 bits, or `z0-z31` at whatever this machine's SVE vector length is.
//
// The width is not a detail. `v0-v31` **are** the low 128 bits of `z0-z31`,
// and ordinary compiled code writes those constantly. Past 128 bits nothing
// but SVE reaches, and a compiler emits no SVE unless it was asked to — so on
// a machine whose vector length is wider than that, the far end of any `z` is
// somewhere a secret can rest and nothing will write over it. That is the
// same shape as `zmm16-31` on the other architecture, and it is why the SVE
// form is a different capture rather than a wider version of this one.
//
// **Not the predicates.** `p0-p15` and the `FFR` hold masks worked out from a
// length, not bytes that came from anywhere, so a secret does not land in one.
//
// # Layout
//
//     0     x0-x30, in order, eight bytes each
//     248   sp
//     256   one 256-byte slot per vector register
//
// A slot is as wide as the widest vector this architecture defines, whatever
// this machine's happens to be, so the layout does not move when the form
// does. `redoubt_spill_width` says how much of each slot was written.

    .bss
    .globl redoubt_spill_room
    .type  redoubt_spill_room,@object
    .p2align 6
redoubt_spill_room:
    .zero 8448
    .size redoubt_spill_room, 8448

// How many bytes of each vector slot the last capture wrote: sixteen from the
// NEON form, this machine's vector length from the SVE one. Without it a
// reader cannot tell a register captured narrow from one captured wide that
// happened to be empty past its sixteenth byte.
    .globl redoubt_spill_width
    .type  redoubt_spill_width,@object
    .p2align 3
redoubt_spill_width:
    .zero 8
    .size redoubt_spill_width, 8

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
// Whichever form the slot holds, entered without touching anything but `x16`
// — `IP0`, which the ABI already lets a linker veneer clobber between any
// caller and callee, so nothing may keep a live value there.
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
    // reads the same way whichever form wrote it.
    str     q0,  [x0, #256]
    str     q1,  [x0, #512]
    str     q2,  [x0, #768]
    str     q3,  [x0, #1024]
    str     q4,  [x0, #1280]
    str     q5,  [x0, #1536]
    str     q6,  [x0, #1792]
    str     q7,  [x0, #2048]
    str     q8,  [x0, #2304]
    str     q9,  [x0, #2560]
    str     q10, [x0, #2816]
    str     q11, [x0, #3072]
    str     q12, [x0, #3328]
    str     q13, [x0, #3584]
    str     q14, [x0, #3840]
    str     q15, [x0, #4096]
    str     q16, [x0, #4352]
    str     q17, [x0, #4608]
    str     q18, [x0, #4864]
    str     q19, [x0, #5120]
    str     q20, [x0, #5376]
    str     q21, [x0, #5632]
    str     q22, [x0, #5888]
    str     q23, [x0, #6144]
    str     q24, [x0, #6400]
    str     q25, [x0, #6656]
    str     q26, [x0, #6912]
    str     q27, [x0, #7168]
    str     q28, [x0, #7424]
    str     q29, [x0, #7680]
    str     q30, [x0, #7936]
    str     q31, [x0, #8192]

    // `x1` and `x2` are safe to borrow now that their own values are written
    // down. The caller's `x0` comes back off the stack, and the caller's `sp`
    // is where the stack pointer was before the push.
    ldr     x1, [sp]
    str     x1, [x0, #0]
    add     x1, sp, #16
    str     x1, [x0, #248]

    mov     x1, #16
    adrp    x2, redoubt_spill_width
    str     x1, [x2, #:lo12:redoubt_spill_width]

    // And every borrowed register back to what it was, so that what this
    // leaves behind is the copy in the room and nothing else.
    ldr     x2, [x0, #16]
    ldr     x1, [x0, #8]
    ldr     x0, [sp], #16
    ret
    .size redoubt_spill_neon, .-redoubt_spill_neon

// void redoubt_spill_sve(void)
//
// The general registers, the stack pointer, and the whole of z0-z31.
//
// `str z` reaches its slot through a base register rather than a constant
// offset — its only addressing form is a multiple of the vector length, and
// the layout here is in bytes on purpose, so that a reader does not have to
// know the machine's width to find a register. `x1` walks the slots instead.
//
// Requires SVE. The caller checks.
    .arch armv8-a+sve
    .globl redoubt_spill_sve
    .type  redoubt_spill_sve,@function
    .p2align 4
redoubt_spill_sve:
    hint    #38                              // bti jc

    str     x0, [sp, #-16]!
    adrp    x0, redoubt_spill_room
    add     x0, x0, :lo12:redoubt_spill_room

    stp     x1,   x2,  [x0, #8]
    stp     x3,   x4,  [x0, #24]
    stp     x5,   x6,  [x0, #40]
    stp     x7,   x8,  [x0, #56]
    stp     x9,   x10, [x0, #72]
    stp     x11,  x12, [x0, #88]
    stp     x13,  x14, [x0, #104]
    stp     x15,  x16, [x0, #120]
    stp     x17,  x18, [x0, #136]
    stp     x19,  x20, [x0, #152]
    stp     x21,  x22, [x0, #168]
    stp     x23,  x24, [x0, #184]
    stp     x25,  x26, [x0, #200]
    stp     x27,  x28, [x0, #216]
    stp     x29,  x30, [x0, #232]

    add     x1, x0, #256
    str     z0, [x1]
    add     x1, x1, #256
    str     z1, [x1]
    add     x1, x1, #256
    str     z2, [x1]
    add     x1, x1, #256
    str     z3, [x1]
    add     x1, x1, #256
    str     z4, [x1]
    add     x1, x1, #256
    str     z5, [x1]
    add     x1, x1, #256
    str     z6, [x1]
    add     x1, x1, #256
    str     z7, [x1]
    add     x1, x1, #256
    str     z8, [x1]
    add     x1, x1, #256
    str     z9, [x1]
    add     x1, x1, #256
    str     z10, [x1]
    add     x1, x1, #256
    str     z11, [x1]
    add     x1, x1, #256
    str     z12, [x1]
    add     x1, x1, #256
    str     z13, [x1]
    add     x1, x1, #256
    str     z14, [x1]
    add     x1, x1, #256
    str     z15, [x1]
    add     x1, x1, #256
    str     z16, [x1]
    add     x1, x1, #256
    str     z17, [x1]
    add     x1, x1, #256
    str     z18, [x1]
    add     x1, x1, #256
    str     z19, [x1]
    add     x1, x1, #256
    str     z20, [x1]
    add     x1, x1, #256
    str     z21, [x1]
    add     x1, x1, #256
    str     z22, [x1]
    add     x1, x1, #256
    str     z23, [x1]
    add     x1, x1, #256
    str     z24, [x1]
    add     x1, x1, #256
    str     z25, [x1]
    add     x1, x1, #256
    str     z26, [x1]
    add     x1, x1, #256
    str     z27, [x1]
    add     x1, x1, #256
    str     z28, [x1]
    add     x1, x1, #256
    str     z29, [x1]
    add     x1, x1, #256
    str     z30, [x1]
    add     x1, x1, #256
    str     z31, [x1]

    // What was borrowed, written down, and put back. `rdvl` is the machine's
    // vector length in bytes, which is how much of each slot above is real.
    ldr     x1, [sp]
    str     x1, [x0, #0]
    add     x1, sp, #16
    str     x1, [x0, #248]

    rdvl    x1, #1
    adrp    x2, redoubt_spill_width
    str     x1, [x2, #:lo12:redoubt_spill_width]

    ldr     x2, [x0, #16]
    ldr     x1, [x0, #8]
    ldr     x0, [sp], #16
    ret
    .size redoubt_spill_sve, .-redoubt_spill_sve

    .section .note.GNU-stack,"",@progbits
