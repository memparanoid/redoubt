<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-07-28 14:58</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.52%** | 625 | 628 |
| **Line** | **99.08%** | 4,735 | 4,779 |
| **Region** | **99.06%** | 6,455 | 6,516 |
| **Branch** | **97.55%** | 318 | 326 |

## Security Audit

**No vulnerabilities found** — scanned 196 crates against 1170 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 17,556 | 16,875 | 34,431 |
| **Total Lines** | 20,567 | 22,291 | 42,858 |
| **Files** | 134 | 130 | 264 |
| **Comments** | 912 | - | 2,780 |

> **Test/Code Ratio:** `0.96x` — 16,875 test lines / 17,556 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 774 |
| **Total Assertions** | 2,102 |
| **Assertions/Test** | 2.7 |
| **Lines/Test** | 22.7 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,423 |
| `assert_eq!` | 671 |
| `debug_assert!` | 5 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 29 | 0 |
| `redoubt-aead` | 7,807 | 51 |
| `redoubt-aead/core` | 66 | 0 |
| `redoubt-aead/xchacha` | 983 | 47 |
| `redoubt-alloc` | 769 | 128 |
| `redoubt-buffer` | 374 | 58 |
| `redoubt-codec` | 1,609 | 0 |
| `redoubt-codec/core` | 1,488 | 162 |
| `redoubt-codec/derive` | 118 | 17 |
| `redoubt-guard` | 195 | 1 |
| `redoubt-hkdf` | 3,768 | 3 |
| `redoubt-hkdf/arm` | 129 | 1 |
| `redoubt-hkdf/core` | 32 | 1 |
| `redoubt-hkdf/rust` | 599 | 20 |
| `redoubt-hkdf/wycheproof` | 2,838 | 0 |
| `redoubt-hkdf/x86` | 140 | 6 |
| `redoubt-rand` | 258 | 26 |
| `redoubt-secret` | 81 | 8 |
| `redoubt-test-utils` | 107 | 5 |
| `redoubt-util` | 171 | 19 |
| `redoubt-vault` | 1,528 | 0 |
| `redoubt-vault/core` | 842 | 77 |
| `redoubt-vault/derive` | 683 | 38 |
| `redoubt-zero` | 860 | 0 |
| `redoubt-zero/core` | 573 | 43 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **26,328** | **754** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>