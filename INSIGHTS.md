<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-09-28 04:29</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **100.00%** | 817 | 817 |
| **Line** | **99.83%** | 5,914 | 5,924 |
| **Region** | **99.59%** | 8,420 | 8,455 |
| **Branch** | **97.50%** | 468 | 480 |

## Security Audit

**No vulnerabilities found** — scanned 200 crates against 1271 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,672 | 56,592 | 67,264 |
| **Total Lines** | 14,933 | 77,405 | 92,338 |
| **Files** | 187 | 343 | 530 |
| **Comments** | 1,489 | - | 8,444 |

> **Test/Code Ratio:** `5.30x` — 56,592 test lines / 10,672 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 3,271 |
| **Total Assertions** | 2,903 |
| **Assertions/Test** | 0.9 |
| **Lines/Test** | 3.3 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,669 |
| `assert_eq!` | 1,225 |
| `debug_assert!` | 6 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 33 | 0 |
| `redoubt-aead` | 694 | 193 |
| `redoubt-aead/aegis128l` | 175 | 119 |
| `redoubt-aead/chacha` | 453 | 140 |
| `redoubt-aead/core` | 170 | 31 |
| `redoubt-aead/poly1305` | 350 | 68 |
| `redoubt-aead/xchachapoly1305` | 143 | 67 |
| `redoubt-alloc` | 788 | 466 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 308 | 127 |
| `redoubt-codec` | 3 | 0 |
| `redoubt-codec/core` | 1,598 | 370 |
| `redoubt-codec/derive` | 118 | 47 |
| `redoubt-forensics` | 10 | 0 |
| `redoubt-forensics/allocator` | 295 | 20 |
| `redoubt-forensics/core` | 1,422 | 436 |
| `redoubt-forensics/macros` | 92 | 22 |
| `redoubt-hex` | 159 | 67 |
| `redoubt-hkdf` | 820 | 184 |
| `redoubt-mem` | 7 | 0 |
| `redoubt-mem/core` | 247 | 152 |
| `redoubt-mem/forensics` | 1 | 66 |
| `redoubt-rand` | 280 | 55 |
| `redoubt-secret` | 84 | 22 |
| `redoubt-test-utils` | 166 | 31 |
| `redoubt-util` | 32 | 41 |
| `redoubt-vault` | 3 | 63 |
| `redoubt-vault/core` | 836 | 223 |
| `redoubt-vault/derive` | 489 | 52 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 597 | 157 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **10,672** | **3263** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>