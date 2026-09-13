/* void redoubt_copy_bytes(const void *src, void *dst, size_t bytes);
 *
 * A copy that does not leave the bytes it moved in a register. The aarch64
 * half of `copy_x86_64.S`, which carries the whole argument for why.
 *
 * # What it promises
 *
 * On a normal return, every architectural temporary **this routine** put
 * copied bytes into is zero. Payload lives in `v0-v3` and `x3`, and every exit
 * goes through the same erasure. A leaf: nothing on the stack, no calls, no
 * callee-saved register touched.
 *
 * The erasure is `movi v, #0` and not a narrower write, because a write to
 * `v0` is a write to the low 128 bits of `z0` and leaves the rest of the SVE
 * register alone. This routine never writes past 128 bits, so there is no
 * "rest" of it holding anything — which is the reason the loop is Advanced
 * SIMD and not SVE, and it is the same reason the x86 side stays on legacy
 * SSE.
 *
 * # What it does not promise
 *
 * Residue somebody else left in other registers, the source, the destination,
 * the pointers and length themselves, state saved by a signal or a context
 * switch before the epilogue, or anything microarchitectural. And nothing at
 * all if a fault stops the epilogue from being reached.
 *
 * Branches are on the length only, never on the bytes.
 *
 * AAPCS64 / Apple ARM64: x0=src, x1=dst, x2=bytes. Ordinary cacheable memory,
 * ranges that do not overlap, Advanced SIMD enabled. Not for MMIO, and not for
 * a kernel context that forbids SIMD.
 *
 * Preprocess this file (cc/clang -c); it is not `global_asm!` material,
 * because the `#if` below is what picks the object format.
 */
#if !defined(__aarch64__) || defined(_WIN32)
#error "Requires non-Windows AArch64"
#endif
#ifdef __APPLE__
#define COPY _redoubt_copy_bytes
#else
#define COPY redoubt_copy_bytes
#endif
.text
.p2align 4
.globl COPY
#ifndef __APPLE__
.type COPY, %function
#endif
COPY:
    .cfi_startproc
    hint #34 /* BTI c; a NOP where branch tracking is not enforced. */
    cmp x2, #64
    b.lo .Ltail32
.Lloop64:
    ldp q0, q1, [x0]
    ldp q2, q3, [x0, #32]
    add x0, x0, #64
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    add x1, x1, #64
    sub x2, x2, #64
    cmp x2, #64
    b.hs .Lloop64
    /* What is left is under 64 bytes, and the tail below spends it one bit of
     * the length at a time: 32, 16, 8, 4, 2, 1. Each step is taken or not by
     * a bit of `x2`, so the path depends on the length and never on a byte,
     * and nothing is read or written outside the range. */
.Ltail32:
    tbz x2, #5, .Ltail16
    ldp q0, q1, [x0], #32
    stp q0, q1, [x1], #32
.Ltail16:
    tbz x2, #4, .Ltail8
    ldr q0, [x0], #16
    str q0, [x1], #16
.Ltail8:
    tbz x2, #3, .Ltail4
    ldr x3, [x0], #8
    str x3, [x1], #8
.Ltail4:
    tbz x2, #2, .Ltail2
    ldr w3, [x0], #4
    str w3, [x1], #4
.Ltail2:
    tbz x2, #1, .Ltail1
    ldrh w3, [x0], #2
    strh w3, [x1], #2
.Ltail1:
    tbz x2, #0, .Lwipe
    ldrb w3, [x0]
    strb w3, [x1]
.Lwipe:
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    mov x3, xzr
    ret
    .cfi_endproc
#ifndef __APPLE__
.size COPY, .-COPY
.section .note.GNU-stack,"",%progbits
#endif
