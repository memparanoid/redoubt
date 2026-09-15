// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Test-only caller. Snapshot: x0-x17, x19-x29, x18 before and after,
// 32 guard bytes, then the 160 bytes the production frame occupies. All
// inspected memory is reserved again before reading it. x18 is never changed.
//
// The guard sits under the frame rather than in it: a routine that reached
// past the bottom of what it declared is what those four words are there to
// catch, and they are the reason the poisoned window is wider than the frame.

.text
.p2align 4
.globl {probe}
{probe}:
    sub sp, sp, #128
    stp x1, x0, [sp]
    str x18, [sp, #16]
    stp x19, x20, [sp, #32]
    stp x21, x22, [sp, #48]
    stp x23, x24, [sp, #64]
    stp x25, x26, [sp, #80]
    stp x27, x28, [sp, #96]
    stp x29, x30, [sp, #112]

    sub sp, sp, #192
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    .irp offset,0,16,32,48,64,80,96,112,128,144,160,176
        stp x0, x0, [sp, #\offset]
    .endr
    add sp, sp, #192

    mov x19, #19
    mov x20, #20
    mov x21, #21
    mov x22, #22
    mov x23, #23
    mov x24, #24
    mov x25, #25
    mov x26, #26
    mov x27, #27
    mov x28, #28
    mov x29, #29

    // x0-x5 and x16-x17 are about to carry the call. The rest are poisoned
    // here so that a zero in the snapshot is something the callee did, and
    // not a register nobody ever wrote.
    .irp reg,6,7,8,9,10,11,12,13,14,15
        mov x\reg, x0
    .endr

    ldr x17, [sp, #8]
    ldr x16, [x17]
    ldp x0, x1, [x17, #8]
    ldp x2, x3, [x17, #24]
    ldp x4, x5, [x17, #40]
    blr x16

    str x0, [sp, #24]
    ldr x0, [sp]
    stp x1, x2, [x0, #8]
    stp x3, x4, [x0, #24]
    stp x5, x6, [x0, #40]
    stp x7, x8, [x0, #56]
    stp x9, x10, [x0, #72]
    stp x11, x12, [x0, #88]
    stp x13, x14, [x0, #104]
    stp x15, x16, [x0, #120]
    str x17, [x0, #136]
    stp x19, x20, [x0, #144]
    stp x21, x22, [x0, #160]
    stp x23, x24, [x0, #176]
    stp x25, x26, [x0, #192]
    stp x27, x28, [x0, #208]
    str x29, [x0, #224]
    ldr x1, [sp, #16]
    stp x1, x18, [x0, #232]
    ldr x1, [sp, #24]
    str x1, [x0]

    sub sp, sp, #192
    add x0, x0, #248
    .irp offset,0,16,32,48,64,80,96,112,128,144,160,176
        ldp x1, x2, [sp, #\offset]
        stp x1, x2, [x0, #\offset]
        stp xzr, xzr, [sp, #\offset]
    .endr
    add sp, sp, #192

    ldp x19, x20, [sp, #32]
    ldp x21, x22, [sp, #48]
    ldp x23, x24, [sp, #64]
    ldp x25, x26, [sp, #80]
    ldp x27, x28, [sp, #96]
    ldp x29, x30, [sp, #112]
    .irp offset,0,16,32,48,64,80,96,112
        stp xzr, xzr, [sp, #\offset]
    .endr
    add sp, sp, #128
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    ret

// A target that leaves the machine exactly as the probe handed it over.
//
// What the other tests assert is that a register came back empty. That says
// nothing unless the probe can also report one that did not, which is what
// calling this one establishes: every caller-saved register is poisoned above,
// and after this returns the snapshot has to show it.
.p2align 4
.globl {untouched}
{untouched}:
    ret
