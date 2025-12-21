# HKDF-SHA256 Register Allocation Strategy (x86_64)

## Overview

This document defines the register allocation strategy for x86_64 implementation, adapted from the AArch64 version with constraints imposed by x86_64's smaller register set.

---

## x86_64 Register Budget vs AArch64

### Available Registers

| Category | x86_64 | AArch64 | Constraint |
|----------|--------|---------|------------|
| Total GPR | 16 (rax-r15, rbp, rsp) | 31 (x0-x30) | x86_64 has HALF the GPRs |
| Caller-saved GPR | 10 (rax, rcx, rdx, rsi, rdi, r8-r11) | 18 (x0-x15, x16-x17) | Fewer temps |
| Callee-saved GPR | 6 (rbx, r12-r15, rbp) | 11 (x19-x29) | **CRITICAL: 6 vs 11** |
| Total SIMD | 16 (xmm0-xmm15) | 32 (v0-v31) | Half the SIMD |
| Caller-saved SIMD | 16 (all xmm) SysV / 10 (xmm0-xmm5) Windows | 24 (v0-v7, v16-v31) | OK for our usage |

### Key Constraint: Callee-Saved GPR

**Problem:** AArch64 implementation uses up to 10 callee-saved registers (x19-x28), but x86_64 only has 6.

**Solution Strategy:**
1. **All functions use 5-6 callee-saved registers** - fits perfectly in x86_64 budget
2. **sha256_compress_block:** Uses 5 (rbx, r12-r15) to preserve H_ptr and block_ptr
3. **Other functions:** Use all 6 (rbx, r12-r15, rbp) for loop values and pointers
4. **No stack spilling needed** - careful selection of which values to preserve

---

## Register Allocation Strategy

### Design Principles (Adapted for x86_64)

1. **Callee-saved strategy for all non-trivial functions**
   - **sha256_compress_block:** 5 callee-saved (rbx, r12-r15)
   - **All others:** 6 callee-saved (rbx, r12-r15, rbp)
   - Prologue/epilogue overhead acceptable for security-critical code

2. **No stack spilling required**
   - All functions fit within 6 callee-saved register budget
   - Careful selection of which values to preserve across calls
   - No performance penalty from memory access

3. **Temporary scratch always caller-saved**
   - rax, rcx, rdx, rsi, rdi, r8-r11: function parameters + local temps
   - eax, ecx, edx, r8d-r11d: 32-bit word operations (compression rounds)

4. **Register preservation contracts**
   - sha256_compress_block preserves H_ptr (r13) and block_ptr (r14) internally
   - All callee-saved registers restored by epilogue as per SysV ABI

---

## Register Mapping: AArch64 → x86_64

### sha256_compress_block

**Strategy:** Uses 5 callee-saved registers to preserve pointers across rounds

| AArch64 | x86_64 | Purpose | Storage |
|---------|--------|---------|---------|
| x0 | rdi → r13 | H_ptr (input/output) | Callee-saved (must preserve for final H update) |
| x1 | rsi → r14 | block_ptr (input) | Callee-saved (preserved) |
| x2 | rdx | Loop counter t | Caller-saved temp |
| x3 | rcx | K_ptr | Caller-saved temp |
| w4-w10 | eax, r8d-r12d, r15d, ebx, esi | Round temporaries | Caller-saved (7+ temps available) |
| v16-v19 | xmm0-xmm3 | H state + working vars | SIMD state |
| v20-v24 | xmm4-xmm8 | Message schedule window | SIMD sliding window |
| - | xmm9-xmm13 | Temps for PALIGNR rotation | SIMD temps |

**Callee-saved used:** rbx, r12, r13, r14, r15 (5 registers)

**Stack:** 72 bytes (64 for W[0..15] + 8 alignment), zeroized before return

**Peak Usage:** 15 GPR + 14 SIMD (FITS)

**Why callee-saved here:** Need to preserve H_ptr and block_ptr for final H := H + working_vars update after 64 rounds

---

### sha256_hash

**Strategy:** Use 6 callee-saved registers (including rbp) for main loop values

| AArch64 | x86_64 | Purpose | Storage |
|---------|--------|---------|---------|
| x12 | r12 | msg_ptr_current | Callee-saved (advances through message) |
| x13 | r13 | msg_remaining | Callee-saved (decrements as blocks processed) |
| x14 | r14 | original_msg_len | Callee-saved (constant, for padding) |
| x15 | r15 | digest_ptr | Callee-saved (preserved for final output) |
| x16-x17 | rax, rcx, r8-r9 | Copy loops, temps | Caller-saved |
| x0-x2 | rdi, rsi | compress_block params | Caller-saved |
| v0-v1 | xmm0-xmm2 | H state, bswap mask | SIMD |

**Callee-saved used:** rbp (frame pointer), rbx, r12, r13, r14, r15 (6 registers)

**Note:** rbx is saved/restored but not used in the function body (slight inefficiency, but harmless)

**Stack:**
- 160 bytes (32 H state + 64 block1 + 64 block2)
- + 8 bytes alignment
- **Total:** 168 bytes, zeroized before return

**Peak Usage:** 14 GPR + 3 SIMD (FITS)

---

### sha256_update_finalize

**Strategy:** Use 6 callee-saved registers (including rbp), similar to sha256_hash

| AArch64 | x86_64 | Purpose | Storage |
|---------|--------|---------|---------|
| x19 | rbx | H_ptr (survives `call`) | Callee-saved (needed to reload H state) |
| x12 | r12 | msg_ptr_current | Callee-saved |
| x13 | r13 | msg_remaining | Callee-saved |
| x14 | r14 | total_len (for padding) | Callee-saved |
| x15 | r15 | digest_ptr | Callee-saved |
| x16-x17 | rax, rcx, r8-r9 | Temporaries | Caller-saved |
| v0-v1 | xmm0-xmm2 | H state, bswap mask | SIMD |

**Callee-saved used:** rbp, rbx, r12, r13, r14, r15 (6 registers)

**Stack:** 168 bytes (160 + 8 alignment), zeroized before return

**Peak Usage:** 14 GPR + 3 SIMD (FITS)

---

### hmac_sha256

**Strategy:** Callee-saved for main params (no stack spilling needed)

**Callee-saved allocation (6 registers):**

| AArch64 | x86_64 | Purpose | Priority |
|---------|--------|---------|----------|
| x19 | rbx | key_ptr | HIGH - used frequently |
| x20 | r12 | key_len | HIGH - used frequently |
| x21 | r13 | msg_ptr | HIGH - used frequently |
| x22 | r14 | msg_len | HIGH - used frequently |
| x23 | r15 | mac_ptr | HIGH - used frequently |
| - | rbp | frame pointer | Standard (used for stack frame) |

**Temporary allocation:**

| AArch64 | x86_64 | Purpose | Notes |
|---------|--------|---------|-------|
| x0-x7 | rdi, rsi, rdx, rcx, r8, r9, rax, r10-r11 | Setup params for sha256_hash calls | Caller-saved |
| v0-v1 | xmm0-xmm1 | Transient data movement | SIMD |

**Stack:**
- 256 bytes (K_padded, ipad, opad, inner_hash, temp)
- + 32 bytes for H state workspace
- + 8 bytes alignment
- **Total:** 296 bytes, zeroized before return

**Peak Usage:** 14 GPR (6 callee + 8 temps) + 2 SIMD (FITS)

**Zeroization:** Stack + caller-saved registers via HKDF_SHA256_ZEROIZE_ALL

---

### hkdf_sha256 (Top-Level)

**Strategy:** Callee-saved for critical loop values, stack for setup/temps

**Callee-saved allocation (6 registers - includes rbp as frame pointer):**

| AArch64 | x86_64 | Purpose | Priority |
|---------|--------|---------|----------|
| x19 | rbx | info_ptr | CRITICAL - used every iteration |
| x20 | r12 | info_len | CRITICAL - used every iteration |
| x21 | r13 | okm_ptr (cursor) | CRITICAL - updated every iteration |
| x22 | r14 | okm_len (remaining) | CRITICAL - updated every iteration |
| x23 | r15 | Counter (1..255) | CRITICAL - loop counter |
| - | rbp | frame pointer | Standard (for stack addressing) |

**Stack slots (6 values - using rbp for addressing):**

| AArch64 | x86_64 | Purpose | Access Pattern |
|---------|--------|---------|----------------|
| x24 | [rbp-8] | T_len | HIGH - used every iteration |
| x25 | (computed) | msg_base pointer | MEDIUM - computed per iteration as rsp+64 |
| x26 | (inline) | Loop index | MEDIUM - inline in copy loops |
| x27 | (inline) | msg_cap_aligned | LOW - used once during setup |
| x28 | [rbp-16] | locals_size | LOW - saved for cleanup |
| - | r10, r11 | Temps for calculations | Caller-saved scratch |

**Temporary allocation:**

| AArch64 | x86_64 | Purpose | Notes |
|---------|--------|---------|-------|
| x0-x7 | rdi, rsi, rdx, rcx, r8, r9, rax, r10 | Setup params for hmac_sha256 calls | Caller-saved |
| x15-x17 | r11, r8, r9 | Byte copy scratch | Caller-saved (reused) |

**Stack:**
- Variable (64 + align16(32 + info_len + 1)) - same as AArch64
- + 16 bytes for saved values (T_len, locals_size via rbp)
- **Total:** variable + 16, fully zeroized before return

**Peak Usage:** 14 GPR (6 callee + 8 temps) + 0 SIMD (FITS)

**Zeroization:** Stack + ALL caller-saved registers via HKDF_SHA256_ZEROIZE_ALL

**Note:** rbp is used as standard frame pointer (not as general-purpose register):
- Setup frame pointer at entry: `mov rbp, rsp`
- Access stack via `[rbp - offset]` for saved values (T_len, locals_size)
- Access locals via `[rsp + offset]` for variable-size buffer
- This hybrid approach allows both fixed (rbp-relative) and variable (rsp-relative) addressing

---

## Zeroization Strategy (Adapted for x86_64)

### Responsibility Model (Same as AArch64)

Each function is responsible for:
1. **Zeroizing its own stack allocation** before deallocation
2. **Top-level functions only:** Zeroize all caller-saved registers

### HKDF_SHA256_ZEROIZE_ALL Macro (x86_64 Version)

**What it clears:**
- GPR: rax, rcx, rdx, rsi, rdi, r8-r11 (10 caller-saved)
- SIMD: xmm0-xmm15 (all 16 registers - SysV calling convention)

**What it does NOT clear:**
- rbx, r12-r15, rbp (callee-saved, restored by epilogue)
- rsp (stack pointer)

**Implementation:**
```asm
.macro HKDF_SHA256_ZEROIZE_ALL
    // Zeroize caller-saved GPRs
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

    // Zeroize all SIMD registers (xmm0-xmm15)
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
.endm
```

**Why this is sufficient (same reasoning as AArch64):**
- All SECRET data flows through caller-saved registers
- Callee-saved registers only hold non-secret metadata (pointers, lengths)
- Stack already zeroized before macro invocation
- Macro called after stack cleanup, before epilogue

---

## Performance Considerations

### Register Allocation Efficiency

**AArch64 version:** 11 callee-saved registers available, uses up to 10 in hkdf_sha256

**x86_64 version:** 6 callee-saved registers available, uses all 6 in most functions

**Impact:**
- **All functions fit in 6 callee-saved registers** - no stack spilling needed
- **sha256_compress_block:** Uses only 5 callee-saved (rbx, r12-r15)
- **sha256_hash, sha256_update_finalize, hmac_sha256, hkdf_sha256:** All use 6 (+ rbp)

**Performance:**
- No extra memory accesses for preserved values
- Same efficiency as AArch64 despite smaller register set
- Careful register allocation allows full port without performance loss

---

## Implementation Checklist

When porting each function to x86_64:

1. **Prologue:**
   - [ ] Save rbp and set frame pointer (if using rbp as GP reg, skip frame pointer)
   - [ ] Save callee-saved registers (rbx, r12-r15, rbp if used)
   - [ ] Allocate stack (original size + spill slots)
   - [ ] Document saved registers in comment

2. **Body:**
   - [ ] Load spilled values from stack when needed
   - [ ] Use caller-saved temps for intermediate values
   - [ ] Store back to stack if value must survive `call`

3. **Epilogue:**
   - [ ] Zeroize entire stack (original + spill slots)
   - [ ] Call HKDF_SHA256_ZEROIZE_ALL (top-level only)
   - [ ] Restore callee-saved in reverse order
   - [ ] Restore rbp
   - [ ] Return

4. **Verification:**
   - [ ] Peak register usage <= 16 GPR, <= 16 SIMD
   - [ ] All stack accesses use correct offsets
   - [ ] Zeroization covers all sensitive data
   - [ ] Prologue/epilogue symmetry verified

---

## Summary

### Key Differences from AArch64

| Aspect | AArch64 | x86_64 | Impact |
|--------|---------|--------|--------|
| Callee-saved GPR | 11 (x19-x29) | 6 (rbx, r12-r15, rbp) | All functions use 5-6 callee-saved |
| Total GPR | 31 | 16 | Tighter register budget |
| Register pressure | Low | Moderate | Careful allocation required |
| Stack usage | Minimal | Same (no spilling needed) | Functions fit in 6 callee-saved |

### Portability Status

**All functions fit within x86_64 budget:**
- sha256_compress_block: 15 GPR + 14 SIMD (FITS) - uses 5 callee-saved
- sha256_hash: 14 GPR + 3 SIMD (FITS) - uses 6 callee-saved
- sha256_update_finalize: 14 GPR + 3 SIMD (FITS) - uses 6 callee-saved
- hmac_sha256: 14 GPR + 2 SIMD (FITS) - uses 6 callee-saved
- hkdf_sha256: 14 GPR + 0 SIMD (FITS) - uses 6 callee-saved

**Security:** Same guarantees as AArch64 (stack + registers zeroized)

**Performance:** Slightly slower due to stack reloads (acceptable for security-critical code)
