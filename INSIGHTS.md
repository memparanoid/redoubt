<picture>
    <p align="center">
    <source media="(prefers-color-scheme: dark)" width="320" srcset="/logo_light.png">
    <source media="(prefers-color-scheme: light)" width="320" srcset="/logo_light.png">
    <img alt="Redoubt" width="320" src="/logo_light.png">
    </p>
</picture>

<h1 align="center">Project Insights</h1>

<p align="center"><em>Generated on 2026-10-01 16:41</em></p>

---

## Test Coverage

| Metric | Coverage | Covered | Total |
|--------|----------|---------|-------|
| **Function** | **100.00%** | 831 | 831 |
| **Line** | **99.84%** | 6,066 | 6,076 |
| **Region** | **99.57%** | 8,667 | 8,704 |
| **Branch** | **97.75%** | 477 | 488 |

## Security Audit

**No vulnerabilities found** — scanned 202 crates against 1278 advisories

## Code Statistics

| Metric | Production | Tests | Total |
|--------|------------|-------|-------|
| **Code Lines** | 10,875 | 57,051 | 67,926 |
| **Total Lines** | 15,214 | 78,234 | 93,448 |
| **Files** | 190 | 348 | 538 |
| **Comments** | 1,503 | - | 8,806 |

> **Test/Code Ratio:** `5.25x` — 57,051 test lines / 10,875 production lines

## Tests

| Metric | Count |
|--------|-------|
| **Total Tests** | 3,361 |
| **Total Assertions** | 2,900 |
| **Assertions/Test** | 0.9 |
| **Lines/Test** | 3.2 |

<details>
<summary>Assertion Breakdown</summary>

| Macro | Count |
|-------|-------|
| `assert!` | 1,634 |
| `assert_eq!` | 1,257 |
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
| **Total** | **10,875** | **3353** |

---

<p align="center"><sub>Generated with <code>python scripts/insights.py</code></sub></p>