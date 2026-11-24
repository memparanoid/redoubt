<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-11-23 21:48</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.88%** | 860 | 861 |
| **Line** | **99.62%** | 6,310 | 6,334 |
| **Region** | **99.52%** | 9,097 | 9,141 |
| **Branch** | **97.67%** | 502 | 514 |

## Security Audit

**No vulnerabilities found** — scanned 200 crates against 1563 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 11,280 | 58,277 | 69,557 |
| **Total Lines** | 15,712 | 80,107 | 95,819 |
| **Files** | 191 | 359 | 550 |
| **Comments** | 1,513 | - | 9,010 |

> **Test/Code Ratio:** `5.17x` — 58,277 test lines / 11,280 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 3,461 |
| **Total Assertions** | 2,945 |
| **Assertions/Test** | 0.9 |
| **Lines/Test** | 3.3 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,652 |
| `assert_eq!` | 1,284 |
| `debug_assert!` | 6 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 34 | 0 |
| `redoubt-aead` | 694 | 193 |
| `redoubt-aead/aegis128l` | 174 | 119 |
| `redoubt-aead/chacha` | 453 | 140 |
| `redoubt-aead/core` | 95 | 2 |
| `redoubt-aead/poly1305` | 350 | 68 |
| `redoubt-aead/xchachapoly1305` | 142 | 67 |
| `redoubt-alloc` | 788 | 466 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 308 | 127 |
| `redoubt-codec` | 3 | 0 |
| `redoubt-codec/core` | 1,639 | 378 |
| `redoubt-codec/derive` | 288 | 87 |
| `redoubt-eq` | 84 | 29 |
| `redoubt-forensics` | 10 | 0 |
| `redoubt-forensics/allocator` | 295 | 20 |
| `redoubt-forensics/core` | 1,617 | 526 |
| `redoubt-forensics/macros` | 92 | 22 |
| `redoubt-hex` | 159 | 67 |
| `redoubt-hkdf` | 820 | 184 |
| `redoubt-mem` | 7 | 0 |
| `redoubt-mem/core` | 247 | 152 |
| `redoubt-mem/forensics` | 1 | 66 |
| `redoubt-rand` | 354 | 69 |
| `redoubt-secret` | 84 | 22 |
| `redoubt-test-utils` | 166 | 31 |
| `redoubt-util` | 32 | 41 |
| `redoubt-vault` | 3 | 71 |
| `redoubt-vault/core` | 844 | 226 |
| `redoubt-vault/derive` | 489 | 52 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 597 | 157 |
| `redoubt-zero/derive` | 393 | 70 |
| **Total** | **11,280** | **3453** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>