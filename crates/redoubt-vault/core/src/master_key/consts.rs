// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub const MASTER_KEY_LEN: usize = 32;

pub const CIPHERBOX_KEY_INFO_PREFIX: &[u8; 20] = b"redoubt.cipherbox.v1";

pub const CIPHERBOX_KEY_INFO_LEN: usize = CIPHERBOX_KEY_INFO_PREFIX.len() + 4 + 8;
