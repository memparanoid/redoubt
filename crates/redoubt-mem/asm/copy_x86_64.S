/* void redoubt_copy_bytes(const void *src, void *dst, size_t bytes);
 *
 * A copy that does not leave the bytes it moved in a register.
 *
 * # Why this exists
 *
 * `core::ptr::copy_nonoverlapping` over a runtime length cannot be unrolled,
 * so it compiles to a jump into the C library's `memcpy`. glibc's, on a
 * machine with AVX-512, moves the bytes through `zmm16` and `zmm17` — and
 * `zmm16-31` are outside every form of `vzeroall` and are never touched by
 * compiled Rust, so what lands there stays until the process dies. A signal
 * arriving at any point after that writes the whole register file onto the
 * stack.
 *
 * So the copy has to be one whose temporaries are known, and that erases them
 * before it returns. That is the whole of what this is.
 *
 * # What it promises
 *
 * On a normal return, every architectural temporary **this routine** put
 * copied bytes into is zero. Payload lives in `rax`/`rcx`, and in the low 128
 * bits of `xmm0`/`xmm1` on the medium path. Nothing goes on the stack, nothing
 * is called, and no callee-saved register is touched.
 *
 * Every SSE instruction here is legacy-encoded, which is the point: a legacy
 * SSE write leaves the upper lanes of the corresponding `ymm`/`zmm` alone and
 * never reaches registers 16-31 at all. So no copied byte can be anywhere
 * `pxor` does not reach, and the erasure does not depend on `vzeroupper`.
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
 * SysV x86-64: rdi=src, rsi=dst, rdx=bytes. The ranges must not overlap, and
 * DF is clear, as the ABI requires.
 *
 * Preprocess this file (cc/clang -c); it is not `global_asm!` material,
 * because the `#if` below is what picks the object format.
 */
#if !defined(__x86_64__) || defined(_WIN32)
#error "Requires non-Windows x86-64"
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
.type COPY, @function
#endif
COPY:
    .cfi_startproc
    endbr64
    cmpq $32, %rdx
    ja .Lbulk
    cmpq $16, %rdx
    jbe .Lsmall16
    /* 17..32: both ends loaded before either is stored, so the two halves may
     * overlap in the middle without a store clobbering unread source. */
    movq (%rdi), %rax
    movq 8(%rdi), %rcx
    movq %rax, (%rsi)
    movq %rcx, 8(%rsi)
    movq -16(%rdi,%rdx), %rax
    movq -8(%rdi,%rdx), %rcx
    movq %rax, -16(%rsi,%rdx)
    movq %rcx, -8(%rsi,%rdx)
    jmp .Lwipe
.Lsmall16:
    cmpq $8, %rdx
    jb .Lsmall8
    movq (%rdi), %rax
    movq -8(%rdi,%rdx), %rcx
    movq %rax, (%rsi)
    movq %rcx, -8(%rsi,%rdx)
    jmp .Lwipe
.Lsmall8:
    cmpq $4, %rdx
    jb .Lsmall4
    movl (%rdi), %eax
    movl -4(%rdi,%rdx), %ecx
    movl %eax, (%rsi)
    movl %ecx, -4(%rsi,%rdx)
    jmp .Lwipe
.Lsmall4:
    cmpq $2, %rdx
    jb .Lsmall2
    movzwl (%rdi), %eax
    movzwl -2(%rdi,%rdx), %ecx
    movw %ax, (%rsi)
    movw %cx, -2(%rsi,%rdx)
    jmp .Lwipe
.Lsmall2:
    testq %rdx, %rdx
    jz .Lwipe
    movzbl (%rdi), %eax
    movb %al, (%rsi)
    jmp .Lwipe
.Lbulk:
    cmpq $512, %rdx
    ja .Lrep
    cmpq $64, %rdx
    jbe .Lmedium
.Lmedium64:
    movdqu (%rdi), %xmm0
    movdqu 16(%rdi), %xmm1
    movdqu %xmm0, (%rsi)
    movdqu %xmm1, 16(%rsi)
    movdqu 32(%rdi), %xmm0
    movdqu 48(%rdi), %xmm1
    movdqu %xmm0, 32(%rsi)
    movdqu %xmm1, 48(%rsi)
    addq $64, %rdi
    addq $64, %rsi
    subq $64, %rdx
    cmpq $64, %rdx
    ja .Lmedium64
    cmpq $32, %rdx
    jbe .Llast32
.Lmedium:
    movdqu (%rdi), %xmm0
    movdqu 16(%rdi), %xmm1
    movdqu %xmm0, (%rsi)
    movdqu %xmm1, 16(%rsi)
    addq $32, %rdi
    addq $32, %rsi
    subq $32, %rdx
.Llast32:
    /* The last 32 bytes, which may recopy part of the chunk before them. In
     * bounds either way, and never a read or a write outside the range. */
    movdqu -32(%rdi,%rdx), %xmm0
    movdqu -16(%rdi,%rdx), %xmm1
    movdqu %xmm0, -32(%rsi,%rdx)
    movdqu %xmm1, -16(%rsi,%rdx)
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    jmp .Lwipe
.Lrep:
    /* Past 512 bytes the string move wins, and it carries no payload of its
     * own: the bytes go straight from memory to memory. The threshold is a
     * measurement on one machine, not a constant of nature. */
    movq %rdi, %rax
    movq %rsi, %rdi
    movq %rax, %rsi
    movq %rdx, %rcx
    rep movsb
.Lwipe:
    xorl %eax, %eax
    xorl %ecx, %ecx
    ret
    .cfi_endproc
#ifndef __APPLE__
.size COPY, .-COPY
.section .note.GNU-stack,"",@progbits
#endif
