<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-10-02 12:40</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **100.00%** | 838 | 838 |
| **Line** | **99.84%** | 6,132 | 6,142 |
| **Region** | **99.58%** | 8,793 | 8,830 |
| **Branch** | **97.79%** | 487 | 498 |

## Security Audit

**No vulnerabilities found** — scanned 202 crates against 1280 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,957 | 57,251 | 68,208 |
| **Total Lines** | 15,324 | 78,567 | 93,891 |
| **Files** | 190 | 350 | 540 |
| **Comments** | 1,509 | - | 8,851 |

> **Test/Code Ratio:** `5.23x` — 57,251 test lines / 10,957 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 3,378 |
| **Total Assertions** | 2,915 |
| **Assertions/Test** | 0.9 |
| **Lines/Test** | 3.2 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,638 |
| `assert_eq!` | 1,268 |
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
| `redoubt-codec/core` | 1,598 | 370 |
| `redoubt-codec/derive` | 118 | 47 |
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
| `redoubt-vault` | 3 | 63 |
| `redoubt-vault/core` | 844 | 226 |
| `redoubt-vault/derive` | 489 | 52 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 597 | 157 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **10,957** | **3370** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>