// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memcodec::Codec;
use memzer::{DropSentinel, MemZer};

#[derive(MemZer, Codec)]
#[memzer(drop)]
pub struct WalletSecrets {
    master_seed: [u8; 32],
    encryption_key: [u8; 32],
    signing_key: [u8; 64],
    pin_hash: [u8; 32],
    #[codec(skip)]
    __drop_sentinel: DropSentinel,
}

impl Default for WalletSecrets {
    fn default() -> Self {
        Self {
            master_seed: [0u8; 32],
            encryption_key: [0u8; 32],
            signing_key: [0u8; 64],
            pin_hash: [0u8; 32],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}
