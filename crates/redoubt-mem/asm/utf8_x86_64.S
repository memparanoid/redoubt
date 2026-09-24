/* void redoubt_mem_utf8_valid(const uint8_t *bytes, size_t len, uint8_t *answer);
 *
 * Whether `len` bytes spell UTF-8, written to `*answer` as one or zero, with
 * none of the bytes left in a register.
 *
 * # Why this exists
 *
 * Decoding a string that holds a secret has to check the bytes are UTF-8, and
 * the standard library's check reads them through registers it never empties:
 * on aarch64 the decoded text was found whole after it returned. This reads
 * one byte at a time into registers it then erases.
 *
 * # What it promises
 *
 * On a normal return, every register in the budget below is zero: the bytes
 * read, the bounds a second byte is held to, and the caller's pointers and
 * length. General registers only, no vector register is written, nothing goes
 * on the stack, nothing is called, and no callee-saved register is touched.
 *
 * # What it does not promise
 *
 * Constant time. The path branches on the bytes and stops at the first one
 * that is not UTF-8, so how long it takes says where the multibyte sequences
 * are and where the first error is. The answer itself, one bit, is public.
 * Nor residue somebody else left, the range itself, state saved by a signal
 * or a context switch before the epilogue, or anything microarchitectural.
 *
 * What is UTF-8 is RFC 3629: no overlong forms (C0, C1, E0 80..9F, F0
 * 80..8F), no surrogates (ED A0..BF), nothing past U+10FFFF (F4 90..BF, F5..FF),
 * and no sequence cut short by the end of the range.
 *
 * SysV x86-64: rdi=bytes, rsi=len, rdx=answer. Baseline x86-64, no feature
 * detection.
 *
 * Preprocess this file (cc/clang -c); it is not `global_asm!` material,
 * because the `#if` below is what picks the object format.
 */
#if !defined(__x86_64__) || defined(_WIN32)
#error "Requires non-Windows x86-64"
#endif
#ifdef __APPLE__
#define FUNC(name) _##name
#else
#define FUNC(name) name
#endif

/* ============================================================================
 * The register budget
 * ============================================================================
 *
 * Every register this routine puts anything in is named once, here, and every
 * operation over the set goes through this one list. It is the whole
 * caller-saved general set, the pointers the caller handed over included,
 * whether or not the routine writes each one.
 */
.macro UTF8_EACH op
    \op %rax
    \op %rcx
    \op %rdx
    \op %rsi
    \op %rdi
    \op %r8
    \op %r9
    \op %r10
    \op %r11
.endm

.macro UTF8_CLEAR reg
    xorq \reg, \reg
.endm

.macro UTF8_FILL reg
    movq %rax, \reg
.endm

.macro UTF8_GATHER reg
    orq \reg, %rcx
.endm

.macro UTF8_ZEROIZE_ALL
    UTF8_EACH UTF8_CLEAR
.endm

/* ============================================================================
 * redoubt_mem_utf8_valid
 * ============================================================================
 *
 * ecx holds the lead byte, r8d a byte after it, and r9d and r10d the lowest
 * and highest the second byte may be. A continuation byte is 80..BF: less
 * 0x80, at most 0x3F.
 */
.text
.p2align 4
.globl FUNC(redoubt_mem_utf8_valid)
#ifndef __APPLE__
.type FUNC(redoubt_mem_utf8_valid), @function
#endif
FUNC(redoubt_mem_utf8_valid):
    .cfi_startproc
    endbr64
    testq %rsi, %rsi
    jz .Lvalid

.Lnext:
    movzbl (%rdi), %ecx
    cmpl $0x80, %ecx
    jb .Lone
    cmpl $0xC2, %ecx
    jb .Linvalid
    cmpl $0xE0, %ecx
    jb .Ltwo
    cmpl $0xF0, %ecx
    jb .Lthree
    cmpl $0xF5, %ecx
    jb .Lfour
    jmp .Linvalid

.Lone:
    addq $1, %rdi
    subq $1, %rsi
    jnz .Lnext
    jmp .Lvalid

.Ltwo:
    cmpq $2, %rsi
    jb .Linvalid
    movzbl 1(%rdi), %r8d
    subl $0x80, %r8d
    cmpl $0x3F, %r8d
    ja .Linvalid
    addq $2, %rdi
    subq $2, %rsi
    jnz .Lnext
    jmp .Lvalid

.Lthree:
    cmpq $3, %rsi
    jb .Linvalid
    /* E0 is followed by A0..BF, ED by 80..9F, and every other by 80..BF. */
    movl $0x80, %r9d
    movl $0xBF, %r10d
    cmpl $0xE0, %ecx
    jne 1f
    movl $0xA0, %r9d
1:  cmpl $0xED, %ecx
    jne 2f
    movl $0x9F, %r10d
2:  movzbl 1(%rdi), %r8d
    cmpl %r9d, %r8d
    jb .Linvalid
    cmpl %r10d, %r8d
    ja .Linvalid
    movzbl 2(%rdi), %r8d
    subl $0x80, %r8d
    cmpl $0x3F, %r8d
    ja .Linvalid
    addq $3, %rdi
    subq $3, %rsi
    jnz .Lnext
    jmp .Lvalid

.Lfour:
    cmpq $4, %rsi
    jb .Linvalid
    /* F0 is followed by 90..BF, F4 by 80..8F, and F1..F3 by 80..BF. */
    movl $0x80, %r9d
    movl $0xBF, %r10d
    cmpl $0xF0, %ecx
    jne 1f
    movl $0x90, %r9d
1:  cmpl $0xF4, %ecx
    jne 2f
    movl $0x8F, %r10d
2:  movzbl 1(%rdi), %r8d
    cmpl %r9d, %r8d
    jb .Linvalid
    cmpl %r10d, %r8d
    ja .Linvalid
    movzbl 2(%rdi), %r8d
    subl $0x80, %r8d
    cmpl $0x3F, %r8d
    ja .Linvalid
    movzbl 3(%rdi), %r8d
    subl $0x80, %r8d
    cmpl $0x3F, %r8d
    ja .Linvalid
    addq $4, %rdi
    subq $4, %rsi
    jnz .Lnext

.Lvalid:
    movb $1, (%rdx)
    jmp .Lwipe

.Linvalid:
    movb $0, (%rdx)

    /* The one way out: the answer is written through `rdx` before the budget,
     * `rdx` with it, is emptied. */
.Lwipe:
    UTF8_ZEROIZE_ALL
    ret
    .cfi_endproc
#ifndef __APPLE__
.size FUNC(redoubt_mem_utf8_valid), .-FUNC(redoubt_mem_utf8_valid)
.section .note.GNU-stack,"",@progbits
#endif
