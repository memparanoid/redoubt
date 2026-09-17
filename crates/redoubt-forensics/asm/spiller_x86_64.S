// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Every register, written where a sweep of memory can read it.
//
// A register is not in any mapping, so nothing that reads memory can see one —
// which is the one gap this crate cannot close by looking harder. It can be
// closed by making the registers stop being registers: write them out, and
// they are memory like anything else.
//
// Written as a `.S` and not as inline asm on purpose. A separate symbol is an
// ABI boundary: the compiler must set up the call and may not reorder into it,
// and nothing here is at the mercy of what the register allocator decided
// around the call site.
//
// # Nothing is passed in
//
// These take no argument, and that is the point. A destination passed in costs
// `rdi` and whatever the caller used to work out the address, so the general
// registers arrived a moment late and the `rdi` slot held our own pointer
// rather than the caller's. The destination is a static instead, reached
// RIP-relative, so the call setup is one `call` instruction and every register
// below is the caller's own.
//
// A static also solves where to put it. The room has to be somewhere the stack
// cannot reach, because what writes over the stack next is exactly what this is
// trying to catch, and `.bss` is as far from the stack as memory gets while
// still being swept — it is `rw-p`, like any other anonymous mapping.

// # Which form, decided once
//
// Asking the machine what it supports is a branch and an atomic load, and both
// need a register — at the one point where nothing may run. So the question is
// answered long before, and what is left at the capture is a jump through a
// slot:
//
//     redoubt_spill:  jmp *redoubt_spill_which(%rip)
//
// A RIP-relative indirect jump needs no register to work out the address and
// none to hold the destination. The slot starts on the SSE form, which every
// `x86_64` has, and `Forensics` writes the widest one the machine supports
// into it when it is built. At the call site this is one `call` instruction
// and nothing else.

// # Two ways in
//
// Every form can be entered at its start, which writes the general registers
// and then the vectors, or at its vector half, which writes the vectors alone.
// The second entry is its own symbol with its own dispatch slot, and both
// slots name the same form.
//
// It is there for a caller that has already written the general registers down
// itself, with stores it placed where it wanted them, and reaches here only
// for the vectors — which have no encoding a caller can place, because a `movq`
// to a static is three bytes of opcode and a `vmovdqu64` is a form the machine
// may not have.
//
// What that caller buys is the order. A `call` pushes eight bytes below `rsp`,
// and eight bytes below `rsp` is where the deepest of what an operation left
// is. Entering here last, after the caller has copied that region somewhere
// else, puts the return address on top of something already read.

    .bss
    .globl redoubt_spill_room
    .type  redoubt_spill_room,@object
    .p2align 6
redoubt_spill_room:
    .zero 2176
    .size redoubt_spill_room, 2176

// How many bytes of each vector slot the last capture wrote: 16, 32 or 64,
// depending on which form ran. Without it a reader cannot tell a register
// captured narrow from one captured wide that happened to be empty past its
// sixteenth byte. An immediate straight to memory, so it costs no register.
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
    .quad redoubt_spill_sse
    .size redoubt_spill_which, 8

// The same choice, for the entry that writes the vectors alone. Two slots and
// not one, because a jump cannot be told which half to start at.
    .globl redoubt_spill_vectors_which
    .type  redoubt_spill_vectors_which,@object
    .p2align 3
redoubt_spill_vectors_which:
    .quad redoubt_spill_vectors_sse
    .size redoubt_spill_vectors_which, 8

    .text

// void redoubt_spill(void)
//
// Whichever form the slot holds, entered without touching anything. The `jmp`
// leaves our return address in place, so the form's own `ret` goes back to
// whoever called this.
    .globl redoubt_spill
    .type  redoubt_spill,@function
    .p2align 4
redoubt_spill:
    endbr64
    jmp *redoubt_spill_which(%rip)
    .size redoubt_spill, .-redoubt_spill

// void redoubt_spill_vectors(void)
//
// The vector half of whichever form the slot holds, for a caller that wrote
// the general registers itself.
    .globl redoubt_spill_vectors
    .type  redoubt_spill_vectors,@function
    .p2align 4
redoubt_spill_vectors:
    endbr64
    jmp *redoubt_spill_vectors_which(%rip)
    .size redoubt_spill_vectors, .-redoubt_spill_vectors

// void redoubt_spill_sse(void)
//
// 128 bytes of general registers, then the lower 16 of each of the first
// sixteen vector slots.
    .globl redoubt_spill_sse
    .type  redoubt_spill_sse,@function
    .p2align 4
redoubt_spill_sse:
    // Reached by the indirect jump above, so it needs a landing pad where
    // branch tracking is enforced. It changes nothing a capture can see.
    endbr64
    movq  %rax, redoubt_spill_room+0(%rip)
    movq  %rbx, redoubt_spill_room+8(%rip)
    movq  %rcx, redoubt_spill_room+16(%rip)
    movq  %rdx, redoubt_spill_room+24(%rip)
    movq  %rsi, redoubt_spill_room+32(%rip)
    movq  %rdi, redoubt_spill_room+40(%rip)
    movq  %rbp, redoubt_spill_room+48(%rip)
    movq  %rsp, redoubt_spill_room+56(%rip)
    movq  %r8,  redoubt_spill_room+64(%rip)
    movq  %r9,  redoubt_spill_room+72(%rip)
    movq  %r10, redoubt_spill_room+80(%rip)
    movq  %r11, redoubt_spill_room+88(%rip)
    movq  %r12, redoubt_spill_room+96(%rip)
    movq  %r13, redoubt_spill_room+104(%rip)
    movq  %r14, redoubt_spill_room+112(%rip)
    movq  %r15, redoubt_spill_room+120(%rip)

// void redoubt_spill_vectors_sse(void)
//
// The vector half on its own. Reached by the second dispatch, so it needs a
// landing pad of its own; the form above falls through it, where it is a nop.
    .globl redoubt_spill_vectors_sse
    .type  redoubt_spill_vectors_sse,@function
redoubt_spill_vectors_sse:
    endbr64

    // One slot per register, 64 bytes wide, whatever this form can fill of
    // it. The layout does not depend on which form ran, because which form
    // ran is decided at run time and a reader cannot be asked to know.
    movups %xmm0,  redoubt_spill_room+128(%rip)
    movups %xmm1,  redoubt_spill_room+192(%rip)
    movups %xmm2,  redoubt_spill_room+256(%rip)
    movups %xmm3,  redoubt_spill_room+320(%rip)
    movups %xmm4,  redoubt_spill_room+384(%rip)
    movups %xmm5,  redoubt_spill_room+448(%rip)
    movups %xmm6,  redoubt_spill_room+512(%rip)
    movups %xmm7,  redoubt_spill_room+576(%rip)
    movups %xmm8,  redoubt_spill_room+640(%rip)
    movups %xmm9,  redoubt_spill_room+704(%rip)
    movups %xmm10, redoubt_spill_room+768(%rip)
    movups %xmm11, redoubt_spill_room+832(%rip)
    movups %xmm12, redoubt_spill_room+896(%rip)
    movups %xmm13, redoubt_spill_room+960(%rip)
    movups %xmm14, redoubt_spill_room+1024(%rip)
    movups %xmm15, redoubt_spill_room+1088(%rip)
    movq    $16, redoubt_spill_width(%rip)
    ret
    .size redoubt_spill_sse, .-redoubt_spill_sse

// void redoubt_spill_avx(void)
//
// The same, with the whole of ymm0-15 rather than their lower quarters. A
// thirty-two byte secret moved by a modern `memcpy` is one `ymm`, and its
// upper half is invisible to the SSE form above.
//
// Requires AVX. The caller checks.
    .globl redoubt_spill_avx
    .type  redoubt_spill_avx,@function
    .p2align 4
redoubt_spill_avx:
    endbr64
    movq  %rax, redoubt_spill_room+0(%rip)
    movq  %rbx, redoubt_spill_room+8(%rip)
    movq  %rcx, redoubt_spill_room+16(%rip)
    movq  %rdx, redoubt_spill_room+24(%rip)
    movq  %rsi, redoubt_spill_room+32(%rip)
    movq  %rdi, redoubt_spill_room+40(%rip)
    movq  %rbp, redoubt_spill_room+48(%rip)
    movq  %rsp, redoubt_spill_room+56(%rip)
    movq  %r8,  redoubt_spill_room+64(%rip)
    movq  %r9,  redoubt_spill_room+72(%rip)
    movq  %r10, redoubt_spill_room+80(%rip)
    movq  %r11, redoubt_spill_room+88(%rip)
    movq  %r12, redoubt_spill_room+96(%rip)
    movq  %r13, redoubt_spill_room+104(%rip)
    movq  %r14, redoubt_spill_room+112(%rip)
    movq  %r15, redoubt_spill_room+120(%rip)

// void redoubt_spill_vectors_avx(void)
//
// The vector half on its own.
    .globl redoubt_spill_vectors_avx
    .type  redoubt_spill_vectors_avx,@function
redoubt_spill_vectors_avx:
    endbr64

    // 64 bytes apart, the same slots the AVX-512 form fills. Half of each is
    // written and half is left as it was.
    vmovups %ymm0,  redoubt_spill_room+128(%rip)
    vmovups %ymm1,  redoubt_spill_room+192(%rip)
    vmovups %ymm2,  redoubt_spill_room+256(%rip)
    vmovups %ymm3,  redoubt_spill_room+320(%rip)
    vmovups %ymm4,  redoubt_spill_room+384(%rip)
    vmovups %ymm5,  redoubt_spill_room+448(%rip)
    vmovups %ymm6,  redoubt_spill_room+512(%rip)
    vmovups %ymm7,  redoubt_spill_room+576(%rip)
    vmovups %ymm8,  redoubt_spill_room+640(%rip)
    vmovups %ymm9,  redoubt_spill_room+704(%rip)
    vmovups %ymm10, redoubt_spill_room+768(%rip)
    vmovups %ymm11, redoubt_spill_room+832(%rip)
    vmovups %ymm12, redoubt_spill_room+896(%rip)
    vmovups %ymm13, redoubt_spill_room+960(%rip)
    vmovups %ymm14, redoubt_spill_room+1024(%rip)
    vmovups %ymm15, redoubt_spill_room+1088(%rip)
    movq    $32, redoubt_spill_width(%rip)
    ret
    .size redoubt_spill_avx, .-redoubt_spill_avx

// void redoubt_spill_avx512(void)
//
// The general registers, then the whole of zmm0-31: 128 bytes, then 2048.
//
// `vzeroall` reaches ymm0-15 and stops there — zmm16-31 are outside every form
// of it, and nothing in ordinary compiled code touches them, so whatever a
// wide `memcpy` leaves in one stays until the process ends. That makes them
// the one part of the register file worth capturing on its own.
//
// Requires AVX-512F. The caller checks.
    .globl redoubt_spill_avx512
    .type  redoubt_spill_avx512,@function
    .p2align 4
redoubt_spill_avx512:
    endbr64
    movq  %rax, redoubt_spill_room+0(%rip)
    movq  %rbx, redoubt_spill_room+8(%rip)
    movq  %rcx, redoubt_spill_room+16(%rip)
    movq  %rdx, redoubt_spill_room+24(%rip)
    movq  %rsi, redoubt_spill_room+32(%rip)
    movq  %rdi, redoubt_spill_room+40(%rip)
    movq  %rbp, redoubt_spill_room+48(%rip)
    movq  %rsp, redoubt_spill_room+56(%rip)
    movq  %r8,  redoubt_spill_room+64(%rip)
    movq  %r9,  redoubt_spill_room+72(%rip)
    movq  %r10, redoubt_spill_room+80(%rip)
    movq  %r11, redoubt_spill_room+88(%rip)
    movq  %r12, redoubt_spill_room+96(%rip)
    movq  %r13, redoubt_spill_room+104(%rip)
    movq  %r14, redoubt_spill_room+112(%rip)
    movq  %r15, redoubt_spill_room+120(%rip)

// void redoubt_spill_vectors_avx512(void)
//
// The vector half on its own.
    .globl redoubt_spill_vectors_avx512
    .type  redoubt_spill_vectors_avx512,@function
redoubt_spill_vectors_avx512:
    endbr64

    vmovdqu64 %zmm0,  redoubt_spill_room+128(%rip)
    vmovdqu64 %zmm1,  redoubt_spill_room+192(%rip)
    vmovdqu64 %zmm2,  redoubt_spill_room+256(%rip)
    vmovdqu64 %zmm3,  redoubt_spill_room+320(%rip)
    vmovdqu64 %zmm4,  redoubt_spill_room+384(%rip)
    vmovdqu64 %zmm5,  redoubt_spill_room+448(%rip)
    vmovdqu64 %zmm6,  redoubt_spill_room+512(%rip)
    vmovdqu64 %zmm7,  redoubt_spill_room+576(%rip)
    vmovdqu64 %zmm8,  redoubt_spill_room+640(%rip)
    vmovdqu64 %zmm9,  redoubt_spill_room+704(%rip)
    vmovdqu64 %zmm10, redoubt_spill_room+768(%rip)
    vmovdqu64 %zmm11, redoubt_spill_room+832(%rip)
    vmovdqu64 %zmm12, redoubt_spill_room+896(%rip)
    vmovdqu64 %zmm13, redoubt_spill_room+960(%rip)
    vmovdqu64 %zmm14, redoubt_spill_room+1024(%rip)
    vmovdqu64 %zmm15, redoubt_spill_room+1088(%rip)
    vmovdqu64 %zmm16, redoubt_spill_room+1152(%rip)
    vmovdqu64 %zmm17, redoubt_spill_room+1216(%rip)
    vmovdqu64 %zmm18, redoubt_spill_room+1280(%rip)
    vmovdqu64 %zmm19, redoubt_spill_room+1344(%rip)
    vmovdqu64 %zmm20, redoubt_spill_room+1408(%rip)
    vmovdqu64 %zmm21, redoubt_spill_room+1472(%rip)
    vmovdqu64 %zmm22, redoubt_spill_room+1536(%rip)
    vmovdqu64 %zmm23, redoubt_spill_room+1600(%rip)
    vmovdqu64 %zmm24, redoubt_spill_room+1664(%rip)
    vmovdqu64 %zmm25, redoubt_spill_room+1728(%rip)
    vmovdqu64 %zmm26, redoubt_spill_room+1792(%rip)
    vmovdqu64 %zmm27, redoubt_spill_room+1856(%rip)
    vmovdqu64 %zmm28, redoubt_spill_room+1920(%rip)
    vmovdqu64 %zmm29, redoubt_spill_room+1984(%rip)
    vmovdqu64 %zmm30, redoubt_spill_room+2048(%rip)
    vmovdqu64 %zmm31, redoubt_spill_room+2112(%rip)
    movq    $64, redoubt_spill_width(%rip)
    ret
    .size redoubt_spill_avx512, .-redoubt_spill_avx512

    .section .note.GNU-stack,"",@progbits
