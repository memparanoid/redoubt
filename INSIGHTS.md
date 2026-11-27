<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-11-27 08:17</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.89%** | 887 | 888 |
| **Line** | **99.74%** | 6,490 | 6,507 |
| **Region** | **99.53%** | 9,356 | 9,400 |
| **Branch** | **97.51%** | 509 | 522 |

## Security Audit

**No vulnerabilities found** — scanned 198 crates against 1571 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 11,514 | 58,955 | 70,469 |
| **Total Lines** | 15,988 | 81,107 | 97,095 |
| **Files** | 191 | 367 | 558 |
| **Comments** | 1,519 | - | 9,135 |

> **Test/Code Ratio:** `5.12x` — 58,955 test lines / 11,514 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 3,558 |
| **Total Assertions** | 2,999 |
| **Assertions/Test** | 0.8 |
| **Lines/Test** | 3.2 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,678 |
| `assert_eq!` | 1,313 |
| `debug_assert!` | 5 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 34 | 0 |
| `redoubt-aead` | 735 | 203 |
| `redoubt-aead/aegis128l` | 174 | 119 |
| `redoubt-aead/chacha` | 453 | 140 |
| `redoubt-aead/core` | 106 | 14 |
| `redoubt-aead/poly1305` | 350 | 68 |
| `redoubt-aead/xchachapoly1305` | 142 | 67 |
| `redoubt-alloc` | 795 | 472 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 340 | 142 |
| `redoubt-codec` | 3 | 0 |
| `redoubt-codec/core` | 1,693 | 388 |
| `redoubt-codec/derive` | 288 | 88 |
| `redoubt-eq` | 84 | 29 |
| `redoubt-forensics` | 10 | 0 |
| `redoubt-forensics/allocator` | 295 | 20 |
| `redoubt-forensics/core` | 1,636 | 538 |
| `redoubt-forensics/macros` | 92 | 22 |
| `redoubt-hex` | 169 | 73 |
| `redoubt-hkdf` | 831 | 186 |
| `redoubt-mem` | 7 | 0 |
| `redoubt-mem/core` | 247 | 152 |
| `redoubt-mem/forensics` | 1 | 66 |
| `redoubt-rand` | 362 | 73 |
| `redoubt-secret` | 84 | 22 |
| `redoubt-test-utils` | 166 | 31 |
| `redoubt-util` | 32 | 41 |
| `redoubt-vault` | 3 | 71 |
| `redoubt-vault/core` | 885 | 244 |
| `redoubt-vault/derive` | 489 | 52 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 597 | 157 |
| `redoubt-zero/derive` | 393 | 71 |
| **Total** | **11,514** | **3550** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>