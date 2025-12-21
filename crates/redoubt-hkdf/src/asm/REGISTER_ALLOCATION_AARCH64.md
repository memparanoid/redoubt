# HKDF-SHA256 Register Allocation Strategy

## Overview

This document defines the register allocation strategy for HKDF-SHA256 assembly implementation, ensuring consistency across functions and portability to x86_64.

---

## Register Allocation Strategy

### Design Principles

1. **Caller-saved only for leaf functions** (sha256_compress_block)
   - No prologue/epilogue overhead
   - Registers zeroized by caller if needed

2. **Callee-saved for parameters across calls** (sha256_hash, hmac_sha256, hkdf_sha256)
   - x19-x28 hold long-lived values (pointers, lengths)
   - Survives `bl` calls to child functions

3. **Temporary scratch always caller-saved**
   - x0-x7: function parameters + local temps
   - x16-x17: inline operations (NOT preserved across `bl`)
   - w4-w10, w17: 32-bit word operations (compression rounds)

4. **Special contracts**
   - sha256_compress_block preserves x12-x15 (allows callers to avoid save/restore)

---

## Per-Function Register Usage

### sha256_compress_block (Leaf Function)

**Caller-Saved Only - No Prologue/Epilogue**

| Type | Registers | Purpose |
|------|-----------|---------|
| GPR  | x0, x1 | H_ptr, block_ptr (NEVER MODIFIED - preserved for caller) |
| GPR  | x2, x3 | Loop counter, K_ptr |
| GPR  | w4-w10, w17 | Round temporaries (T1, T2, Ch, Maj, Σ, σ) |
| SIMD | v16-v19 | H state + working variables |
| SIMD | v20-v24 | Message schedule sliding window |

**Stack:** 64 bytes for W[0..15], zeroized before return

**Peak Usage:** 12 GPR + 9 SIMD

---

### sha256_hash

**Saves:** x29 (FP), x30 (LR) - for `bl` calls

| Type | Registers | Purpose |
|------|-----------|---------|
| GPR  | x12-x15 | msg_ptr, msg_remaining, original_msg_len, digest_ptr |
| GPR  | x16-x17 | Copy loops, temporaries |
| GPR  | x0-x2 | Setup parameters for compress_block calls |
| SIMD | v0-v1 | Transient H state load/store |

**Stack:** 160 bytes (32 H state + 64 block1 + 64 block2), zeroized before return

**Peak Usage:** 11 GPR + 2 SIMD

**Contract:** Relies on sha256_compress_block preserving x12-x15 across `bl` calls

---

### sha256_update_finalize

**Saves:** x29 (FP), x30 (LR), x19

| Type | Registers | Purpose |
|------|-----------|---------|
| GPR  | x12-x15 | msg_ptr, msg_remaining, total_len, digest_ptr |
| GPR  | x19 | H_ptr (callee-saved, survives `bl`) |
| GPR  | x16-x17 | Temporaries |
| SIMD | v0-v1 | Transient H state load/store |

**Stack:** 160 bytes, zeroized before return

**Peak Usage:** 12 GPR + 2 SIMD

---

### hmac_sha256

**Saves:** x29 (FP), x30 (LR), x19-x27

| Type | Registers | Purpose |
|------|-----------|---------|
| GPR  | x19-x23 | key_ptr, key_len, msg_ptr, msg_len, mac_ptr (preserved across all calls) |
| GPR  | x24-x27 | Scratch for address calculation |
| GPR  | x0-x7, x16-x17 | Setup parameters for sha256_hash calls |
| SIMD | v0-v1 | Transient data movement |

**Stack:** 256 bytes (64 K_padded + 64 ipad + 64 opad + 32 inner_hash + 32 temp), zeroized before return

**Peak Usage:** 15 GPR + 2 SIMD

**Zeroization:** Stack + caller-saved registers (x0-x7, x16-x17) via HKDF_SHA256_ZEROIZE_ALL

---

### hkdf_sha256 (Top-Level)

**Saves:** x29 (FP), x30 (LR), x19-x28

| Type | Registers | Purpose |
|------|-----------|---------|
| GPR  | x19-x22 | info_ptr, info_len, okm_ptr, okm_len (preserved across expand loop) |
| GPR  | x23-x24 | Counter (1..255), T_len |
| GPR  | x25-x26 | msg_base pointer, loop index |
| GPR  | x27-x28 | msg_cap_aligned, locals_size (stack allocation size) |
| GPR  | x0-x7, x15-x17 | Setup parameters for hmac_sha256 calls |

**Stack:** Variable size (64 + align16(32 + info_len + 1)), zeroized before return

**Peak Usage:** 16 GPR

**Zeroization:** Stack + ALL caller-saved registers (x0-x17, v0-v7, v16-v31) via HKDF_SHA256_ZEROIZE_ALL

---

## Zeroization Strategy

### Responsibility Model

Each function is responsible for:
1. **Zeroizing its own stack allocation** before deallocation
2. **Top-level functions only:** Zeroize all caller-saved registers

### Why This Works

#### Call Chain
```
hkdf_sha256 (top-level)
  └─> hmac_sha256
       └─> sha256_hash / sha256_update_finalize
            └─> sha256_compress_block (leaf)
```

#### Zeroization Flow (Bottom-Up)

1. **sha256_compress_block** (leaf)
   - Zeroizes W[0..15] stack (64 bytes)
   - Returns to caller with modified v16-v19 (H state)
   - Caller-saved temps (x2-x3, w4-w10, w17, v20-v24) overwritten by caller

2. **sha256_hash / sha256_update_finalize**
   - Zeroizes own stack (160 bytes: H state + block buffers)
   - Returns H state in output buffer (intentional)
   - x12-x15 preserved (contract with compress_block)

3. **hmac_sha256**
   - Zeroizes own stack (256 bytes: K_padded, ipad, opad, inner_hash)
   - Calls HKDF_SHA256_ZEROIZE_ALL to clear x0-x7, x16-x17, v0-v7, v16-v31
   - Restores callee-saved x19-x27 from prologue (NOT zeroized)
   - Returns with all caller-saved registers clean

4. **hkdf_sha256** (top-level)
   - Zeroizes own stack (PRK + T(i) + msg buffer, variable size)
   - Calls HKDF_SHA256_ZEROIZE_ALL to clear ALL caller-saved (x0-x17, v0-v7, v16-v31)
   - Restores callee-saved x19-x28 from prologue (NOT zeroized)
   - Returns to Rust wrapper with all secrets erased

### HKDF_SHA256_ZEROIZE_ALL Macro

**What it clears:**
- GPR: x0-x17 (caller-saved, except x18 which is platform register)
- SIMD: v0-v7, v16-v31 (caller-saved)

**What it does NOT clear:**
- x19-x28 (callee-saved, restored by epilogue)
- x29 (FP), x30 (LR) (restored by epilogue)
- v8-v15 (callee-saved, not used by implementation)

**Why this is sufficient:**
- All SECRET data flows through caller-saved registers
- Callee-saved registers only hold non-secret metadata (pointers, lengths)
- Stack already zeroized before macro invocation
- Macro called after stack cleanup, before epilogue

---

## x86_64 Portability

### Register Budget

| Architecture | GPR Available | SIMD Available | Peak Used (GPR) | Peak Used (SIMD) | Status |
|--------------|---------------|----------------|-----------------|------------------|--------|
| AArch64      | x0-x28 (29)   | v0-v31 (32)    | 16              | 9                | Native |
| x86_64       | 16 registers  | 16 registers   | 16              | 9                | **FITS** |

### Portability Constraints

**x86_64 has fewer registers than AArch64, but our implementation fits:**

1. **GPR:** Peak usage is 16 (hkdf_sha256), exactly matches x86_64 budget
2. **SIMD:** Peak usage is 9 (sha256_compress_block), well within 16 XMMs
3. **Callee-saved strategy translates:** rbx, r12-r15 ≈ x19-x23 (5 registers, we use up to 10)

**Action required for x86_64 port:**
- Use more stack spilling in hmac/hkdf for parameters (x86 has 6 callee-saved vs AArch64's 10)
- Compression function can use same register strategy (fits in budget)

---

## Consistency Requirements

### Temporary Register Conventions

**Standard allocation (to be enforced):**

| Registers | Usage Pattern | Can Cross `bl`? |
|-----------|---------------|-----------------|
| x0-x7     | Function params + local scratch | NO |
| x16-x17   | Inline operations only | NO |
| w4-w10, w17 | 32-bit word ops (compression) | NO |
| x12-x15   | sha256_compress_block preserved | YES (special contract) |
| x19-x28   | Long-lived values across calls | YES (callee-saved) |

**Current status:** Mostly consistent, minor variations in scratch register choice

---

## Summary

### Strengths
- All functions properly zeroize their stack
- Prologue/epilogue pairs verified correct
- Top-level functions clear all caller-saved registers
- Fits within x86_64 register budget

### Requirements for Maintenance
- Keep temporary register allocation consistent (follow table above)
- HKDF_SHA256_ZEROIZE_ALL only used by hmac_sha256 and hkdf_sha256
- Document any new function's register usage in this file
- Verify x86_64 port follows same allocation strategy
