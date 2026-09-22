<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-09-22 10:48</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.87%** | 766 | 767 |
| **Line** | **99.32%** | 5,870 | 5,910 |
| **Region** | **99.24%** | 8,201 | 8,264 |
| **Branch** | **96.85%** | 492 | 508 |

## Security Audit

**No vulnerabilities found** — scanned 196 crates against 1261 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,218 | 41,145 | 51,363 |
| **Total Lines** | 14,144 | 53,635 | 67,779 |
| **Files** | 156 | 209 | 365 |
| **Comments** | 1,360 | - | 5,346 |

> **Test/Code Ratio:** `4.03x` — 41,145 test lines / 10,218 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 2,104 |
| **Total Assertions** | 2,719 |
| **Assertions/Test** | 1.3 |
| **Lines/Test** | 4.9 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,566 |
| `assert_eq!` | 1,144 |
| `debug_assert!` | 6 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 28 | 0 |
| `redoubt-aead` | 691 | 150 |
| `redoubt-aead/aegis128l` | 171 | 71 |
| `redoubt-aead/chacha` | 476 | 121 |
| `redoubt-aead/core` | 142 | 26 |
| `redoubt-aead/poly1305` | 447 | 51 |
| `redoubt-aead/xchachapoly1305` | 240 | 33 |
| `redoubt-alloc` | 795 | 324 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 320 | 86 |
| `redoubt-codec` | 3 | 0 |
| `redoubt-codec/core` | 1,554 | 191 |
| `redoubt-codec/derive` | 118 | 21 |
| `redoubt-forensics` | 1,377 | 337 |
| `redoubt-hkdf` | 788 | 135 |
| `redoubt-mem` | 86 | 73 |
| `redoubt-rand` | 230 | 32 |
| `redoubt-secret` | 86 | 15 |
| `redoubt-test-utils` | 87 | 5 |
| `redoubt-util` | 171 | 85 |
| `redoubt-vault` | 3 | 38 |
| `redoubt-vault/core` | 824 | 115 |
| `redoubt-vault/derive` | 690 | 67 |
| `redoubt-zero` | 6 | 0 |
| `redoubt-zero/core` | 592 | 76 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **10,218** | **2096** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>