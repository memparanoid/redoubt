// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// Test-only caller. It owns the memory before poisoning or inspecting it;
// no load or store happens below rsp. The production return address is public.
// Snapshot: nine caller-saved GPRs, six callee-saved GPRs, 24 guard bytes,
// then the production function's 160-byte frame.

.text
.p2align 4
.globl {probe}
{probe}:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rsi
    mov [rsp + 16], rdi

    sub rsp, 192
    mov rax, 0xa5a5a5a5a5a5a5a5
    .irp offset,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184
        mov [rsp + \offset], rax
    .endr
    add rsp, 192

    mov rbx, 19
    mov rbp, 20
    mov r12, 21
    mov r13, 22
    mov r14, 23
    mov r15, 24

    mov r10, [rsp + 16]
    mov r11, [r10]
    mov rdi, [r10 + 8]
    mov rsi, [r10 + 16]
    mov rdx, [r10 + 24]
    mov rcx, [r10 + 32]
    mov r8, [r10 + 40]
    mov r9, [r10 + 48]
    call r11

    // Preserve rax before borrowing it as the snapshot pointer.
    mov [rsp + 8], rax
    mov rax, [rsp]
    mov [rax + 8], rcx
    mov [rax + 16], rdx
    mov [rax + 24], rsi
    mov [rax + 32], rdi
    mov [rax + 40], r8
    mov [rax + 48], r9
    mov [rax + 56], r10
    mov [rax + 64], r11
    mov [rax + 72], rbx
    mov [rax + 80], rbp
    mov [rax + 88], r12
    mov [rax + 96], r13
    mov [rax + 104], r14
    mov [rax + 112], r15
    mov rdx, [rsp + 8]
    mov [rax], rdx

    sub rsp, 192
    xor ecx, ecx
Lprobe_copy:
    mov rdx, [rsp + rcx]
    mov [rax + rcx + 120], rdx
    mov qword ptr [rsp + rcx], 0
    add rcx, 8
    cmp rcx, 184
    jb Lprobe_copy
    mov qword ptr [rsp + 184], 0
    add rsp, 192

    mov qword ptr [rsp], 0
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    add rsp, 24
    mov r15, [rsp]
    mov r14, [rsp + 8]
    mov r13, [rsp + 16]
    mov r12, [rsp + 24]
    mov rbp, [rsp + 32]
    mov rbx, [rsp + 40]
    .irp offset,0,8,16,24,32,40
        mov qword ptr [rsp + \offset], 0
    .endr
    add rsp, 48
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    ret
