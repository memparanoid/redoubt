// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! A file per standard the seam answers to, rather than per function: the
//! compression and the digest are both FIPS 180-4 and share the answers that
//! pin them.

mod sha256;
