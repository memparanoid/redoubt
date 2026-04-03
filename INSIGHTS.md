<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-04-03 07:43</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.60%** | 740 | 743 |
| **Line** | **99.17%** | 5,495 | 5,541 |
| **Region** | **99.07%** | 7,563 | 7,634 |
| **Branch** | **97.69%** | 381 | 390 |

## Security Audit

**No vulnerabilities found** — scanned 0 crates against 0 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 17,477 | 16,580 | 34,057 |
| **Total Lines** | 20,397 | 21,664 | 42,061 |
| **Files** | 134 | 128 | 262 |
| **Comments** | 846 | - | 2,556 |

> **Test/Code Ratio:** `0.95x` — 16,580 test lines / 17,477 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 737 |
| **Total Assertions** | 2,030 |
| **Assertions/Test** | 2.8 |
| **Lines/Test** | 23.7 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,354 |
| `assert_eq!` | 668 |
| `debug_assert!` | 5 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 28 | 0 |
| `redoubt-aead` | 7,742 | 49 |
| `redoubt-aead/core` | 66 | 0 |
| `redoubt-aead/xchacha` | 926 | 36 |
| `redoubt-alloc` | 764 | 120 |
| `redoubt-buffer` | 349 | 56 |
| `redoubt-codec` | 1,693 | 0 |
| `redoubt-codec/core` | 1,572 | 161 |
| `redoubt-codec/derive` | 118 | 17 |
| `redoubt-guard` | 195 | 1 |
| `redoubt-hkdf` | 3,736 | 3 |
| `redoubt-hkdf/arm` | 129 | 1 |
| `redoubt-hkdf/core` | 32 | 1 |
| `redoubt-hkdf/rust` | 581 | 14 |
| `redoubt-hkdf/wycheproof` | 2,824 | 0 |
| `redoubt-hkdf/x86` | 140 | 6 |
| `redoubt-rand` | 258 | 26 |
| `redoubt-secret` | 80 | 6 |
| `redoubt-test-utils` | 87 | 5 |
| `redoubt-util` | 170 | 19 |
| `redoubt-vault` | 1,524 | 0 |
| `redoubt-vault/core` | 838 | 77 |
| `redoubt-vault/derive` | 683 | 38 |
| `redoubt-zero` | 851 | 0 |
| `redoubt-zero/core` | 574 | 41 |
| `redoubt-zero/derive` | 271 | 40 |
| **Total** | **26,231** | **717** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>