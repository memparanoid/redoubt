// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::Key;
use zeroize::Zeroize;

use memguard::{
    AssertZeroizeOnDrop, DropSentinel, Zeroizable, ZeroizationProbe, assert::assert_zeroize_on_drop,
};

#[derive(Default, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AeadKey {
    pub key: Key,
    __drop_sentinel: DropSentinel,
}

impl AsRef<Key> for AeadKey {
    #[inline]
    fn as_ref(&self) -> &Key {
        &self.key
    }
}

impl AeadKey {
    pub fn from(bytes: [u8; 32]) -> Self {
        Self {
            key: Key::from(bytes),
            __drop_sentinel: DropSentinel::default(),
        }
    }

    pub fn fill_exact(&mut self, bytes: &mut [u8; 32]) {
        self.key.zeroize();
        self.key.copy_from_slice(bytes);
        bytes.zeroize();
    }
}

impl AssertZeroizeOnDrop for AeadKey {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl Zeroizable for AeadKey {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for AeadKey {
    fn is_zeroized(&self) -> bool {
        self.key.as_slice().iter().all(|b| *b == 0)
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[AeadKey: protected]")
    }
}
