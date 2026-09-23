<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-09-23 13:06</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.87%** | 779 | 780 |
| **Line** | **99.63%** | 5,934 | 5,956 |
| **Region** | **99.41%** | 8,294 | 8,343 |
| **Branch** | **97.43%** | 493 | 506 |

## Security Audit

**No vulnerabilities found** — scanned 196 crates against 1267 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,299 | 41,026 | 51,325 |
| **Total Lines** | 14,253 | 53,489 | 67,742 |
| **Files** | 157 | 212 | 369 |
| **Comments** | 1,372 | - | 5,383 |

> **Test/Code Ratio:** `3.98x` — 41,026 test lines / 10,299 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 2,142 |
| **Total Assertions** | 2,726 |
| **Assertions/Test** | 1.3 |
| **Lines/Test** | 4.8 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,568 |
| `assert_eq!` | 1,149 |
| `debug_assert!` | 6 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 31 | 0 |
| `redoubt-aead` | 692 | 150 |
| `redoubt-aead/aegis128l` | 171 | 71 |
| `redoubt-aead/chacha` | 476 | 121 |
| `redoubt-aead/core` | 142 | 26 |
| `redoubt-aead/poly1305` | 447 | 51 |
| `redoubt-aead/xchachapoly1305` | 238 | 33 |
| `redoubt-alloc` | 795 | 324 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 320 | 90 |
| `redoubt-codec` | 3 | 0 |
| `redoubt-codec/core` | 1,554 | 191 |
| `redoubt-codec/derive` | 118 | 21 |
| `redoubt-forensics` | 1,420 | 369 |
| `redoubt-hkdf` | 788 | 135 |
| `redoubt-mem` | 86 | 73 |
| `redoubt-rand` | 230 | 32 |
| `redoubt-secret` | 86 | 15 |
| `redoubt-test-utils` | 87 | 5 |
| `redoubt-util` | 171 | 85 |
| `redoubt-vault` | 3 | 53 |
| `redoubt-vault/core` | 833 | 115 |
| `redoubt-vault/derive` | 717 | 54 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 592 | 76 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **10,299** | **2134** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>