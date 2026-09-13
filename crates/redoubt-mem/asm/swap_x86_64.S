/* void redoubt_mem_swap(void *a, void *b, size_t bytes);
 *
 * An exchange that does not leave either side's bytes in a register.
 *
 * # Why this exists
 *
 * `copy_nonoverlapping` answers the question this crate was written for, and
 * leaves one it cannot: exchanging two values needs somewhere to hold the
 * first while the second is written over it, and a swap built out of copies
 * makes that somewhere as wide as the value. This holds one chunk at a time in
 * registers it then erases, so neither side is ever anywhere but the two
 * places that already held it.
 *
 * It is also the only shape that works for a value that owns something. Moving
 * the bytes of a `Vec` copies its pointer and leaves two owners of one
 * allocation; an exchange leaves exactly one owner at each address.
 *
 * `copy_x86_64.S` carries the argument for why a routine like this has to
 * exist at all, and it is the same argument.
 *
 * # What it promises
 *
 * On a normal return, every architectural temporary **this routine** put
 * exchanged bytes into is zero. Payload lives in `rax`/`rcx`, and in the low
 * 128 bits of `xmm0-3`. Nothing goes on the stack, nothing is called, and no
 * callee-saved register is touched.
 *
 * Every SSE instruction here is legacy-encoded, which is the point: a legacy
 * SSE write leaves the upper lanes of the corresponding `ymm`/`zmm` alone and
 * never reaches registers 16-31 at all. So no exchanged byte can be anywhere
 * `pxor` does not reach, and the erasure does not depend on `vzeroupper`.
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
 * SysV x86-64: rdi=a, rsi=b, rdx=bytes. The ranges must not overlap, and DF is
 * clear, as the ABI requires.
 *
 * Preprocess this file (cc/clang -c); it is not `global_asm!` material,
 * because the `#if` below is what picks the object format.
 */
#if !defined(__x86_64__) || defined(_WIN32)
#error "Requires non-Windows x86-64"
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
.type SWAP, @function
#endif
SWAP:
    .cfi_startproc
    endbr64
    cmpq $32, %rdx
    jb .Ltail16
.Lloop32:
    movdqu (%rdi), %xmm0
    movdqu 16(%rdi), %xmm1
    movdqu (%rsi), %xmm2
    movdqu 16(%rsi), %xmm3
    movdqu %xmm2, (%rdi)
    movdqu %xmm3, 16(%rdi)
    movdqu %xmm0, (%rsi)
    movdqu %xmm1, 16(%rsi)
    addq $32, %rdi
    addq $32, %rsi
    subq $32, %rdx
    cmpq $32, %rdx
    jae .Lloop32
    /* What is left is under 32 bytes, and the tail below spends it one bit of
     * the length at a time: 16, 8, 4, 2, 1. Each step is taken or not by a bit
     * of `dl`, so the path depends on the length and never on a byte, and
     * nothing is read or written outside either range. */
.Ltail16:
    testb $16, %dl
    jz .Ltail8
    movdqu (%rdi), %xmm0
    movdqu (%rsi), %xmm2
    movdqu %xmm2, (%rdi)
    movdqu %xmm0, (%rsi)
    addq $16, %rdi
    addq $16, %rsi
.Ltail8:
    testb $8, %dl
    jz .Ltail4
    movq (%rdi), %rax
    movq (%rsi), %rcx
    movq %rcx, (%rdi)
    movq %rax, (%rsi)
    addq $8, %rdi
    addq $8, %rsi
.Ltail4:
    testb $4, %dl
    jz .Ltail2
    movl (%rdi), %eax
    movl (%rsi), %ecx
    movl %ecx, (%rdi)
    movl %eax, (%rsi)
    addq $4, %rdi
    addq $4, %rsi
.Ltail2:
    testb $2, %dl
    jz .Ltail1
    movw (%rdi), %ax
    movw (%rsi), %cx
    movw %cx, (%rdi)
    movw %ax, (%rsi)
    addq $2, %rdi
    addq $2, %rsi
.Ltail1:
    testb $1, %dl
    jz .Lwipe
    movb (%rdi), %al
    movb (%rsi), %cl
    movb %cl, (%rdi)
    movb %al, (%rsi)
.Lwipe:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    xorl %eax, %eax
    xorl %ecx, %ecx
    ret
    .cfi_endproc
#ifndef __APPLE__
.size SWAP, .-SWAP
.section .note.GNU-stack,"",@progbits
#endif
