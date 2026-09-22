<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-09-22 00:30</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **99.87%** | 766 | 767 |
| **Line** | **99.32%** | 5,870 | 5,910 |
| **Region** | **99.24%** | 8,201 | 8,264 |
| **Branch** | **96.85%** | 492 | 508 |

## Security Audit

**No vulnerabilities found** — scanned 187 crates against 1258 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,216 | 40,941 | 51,157 |
| **Total Lines** | 14,140 | 53,283 | 67,423 |
| **Files** | 156 | 207 | 363 |
| **Comments** | 1,358 | - | 5,302 |

> **Test/Code Ratio:** `4.01x` — 40,941 test lines / 10,216 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 2,097 |
| **Total Assertions** | 2,715 |
| **Assertions/Test** | 1.3 |
| **Lines/Test** | 4.9 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,562 |
| `assert_eq!` | 1,144 |
| `debug_assert!` | 6 |
| `debug_assert_eq!` | 3 |

</details>

## Per-Crate Breakdown

| Crate | Production Code | Tests |
|-------|-----------------|-------|
| `redoubt` | 28 | 0 |
| `redoubt-aead` | 2,167 | 146 |
| `redoubt-alloc` | 795 | 137 |
| `redoubt-asm` | 12 | 1 |
| `redoubt-buffer` | 320 | 64 |
| `redoubt-codec` | 1,675 | 0 |
| `redoubt-codec/core` | 1,554 | 165 |
| `redoubt-codec/derive` | 118 | 17 |
| `redoubt-forensics` | 1,377 | 0 |
| `redoubt-hkdf` | 788 | 135 |
| `redoubt-mem` | 86 | 39 |
| `redoubt-rand` | 230 | 24 |
| `redoubt-secret` | 84 | 8 |
| `redoubt-test-utils` | 87 | 5 |
| `redoubt-util` | 171 | 19 |
| `redoubt-vault` | 1,517 | 0 |
| `redoubt-vault/core` | 824 | 106 |
| `redoubt-vault/derive` | 690 | 38 |
| `redoubt-zero` | 879 | 0 |
| `redoubt-zero/core` | 592 | 45 |
| `redoubt-zero/derive` | 281 | 43 |
| **Total** | **14,275** | **992** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>