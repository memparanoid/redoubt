/* void redoubt_mem_swap(void *a, void *b, size_t bytes);
 *
 * An exchange that does not leave either side's bytes in a register. The
 * aarch64 half of `swap_x86_64.S`, and the companion of `copy_aarch64.S`,
 * which carries the whole argument for why.
 *
 * # Why this and not two copies
 *
 * A swap built out of copies needs somewhere to hold the first value while the
 * second is written over it, and that somewhere is as wide as the value. This
 * holds one chunk at a time in registers it then erases, so neither side is
 * ever anywhere but the two places that already held it.
 *
 * # What it promises
 *
 * On a normal return, every architectural temporary **this routine** put
 * exchanged bytes into is zero. Payload lives in `v0-v3` and `x3-x4`, and
 * every exit goes through the same erasure. A leaf: nothing on the stack, no
 * calls, no callee-saved register touched.
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
 * Residue somebody else left in other registers, either range, the pointers
 * and length themselves, state saved by a signal or a context switch before
 * the epilogue, or anything microarchitectural. And nothing at all if a fault
 * stops the epilogue from being reached.
 *
 * Branches are on the length only, never on the bytes.
 *
 * AAPCS64 / Apple ARM64: x0=a, x1=b, x2=bytes. Ordinary cacheable memory,
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
#define SWAP _redoubt_mem_swap
#else
#define SWAP redoubt_mem_swap
#endif
.text
.p2align 4
.globl SWAP
#ifndef __APPLE__
.type SWAP, %function
#endif
SWAP:
    .cfi_startproc
    hint #34 /* BTI c; a NOP where branch tracking is not enforced. */
    cmp x2, #32
    b.lo .Ltail16
.Lloop32:
    ldp q0, q1, [x0]
    ldp q2, q3, [x1]
    stp q2, q3, [x0], #32
    stp q0, q1, [x1], #32
    sub x2, x2, #32
    cmp x2, #32
    b.hs .Lloop32
    /* What is left is under 32 bytes, and the tail below spends it one bit of
     * the length at a time: 16, 8, 4, 2, 1. Each step is taken or not by a bit
     * of `x2`, so the path depends on the length and never on a byte, and
     * nothing is read or written outside either range. */
.Ltail16:
    tbz x2, #4, .Ltail8
    ldr q0, [x0]
    ldr q2, [x1]
    str q2, [x0], #16
    str q0, [x1], #16
.Ltail8:
    tbz x2, #3, .Ltail4
    ldr x3, [x0]
    ldr x4, [x1]
    str x4, [x0], #8
    str x3, [x1], #8
.Ltail4:
    tbz x2, #2, .Ltail2
    ldr w3, [x0]
    ldr w4, [x1]
    str w4, [x0], #4
    str w3, [x1], #4
.Ltail2:
    tbz x2, #1, .Ltail1
    ldrh w3, [x0]
    ldrh w4, [x1]
    strh w4, [x0], #2
    strh w3, [x1], #2
.Ltail1:
    tbz x2, #0, .Lwipe
    ldrb w3, [x0]
    ldrb w4, [x1]
    strb w4, [x0], #1
    strb w3, [x1], #1
.Lwipe:
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    mov x3, xzr
    mov x4, xzr
    ret
    .cfi_endproc
#ifndef __APPLE__
.size SWAP, .-SWAP
.section .note.GNU-stack,"",%progbits
#endif
