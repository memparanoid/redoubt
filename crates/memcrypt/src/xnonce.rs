// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::XNonce as ChachaXNonce;
use zeroize::Zeroize;

use memzer::assert::assert_zeroize_on_drop;
use memzer::{AssertZeroizeOnDrop, DropSentinel, Zeroizable, ZeroizationProbe};

#[derive(Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
#[cfg_attr(test, derive(Debug))]
pub struct InnerChachaXNonce(pub ChachaXNonce);

impl InnerChachaXNonce {
    pub fn from(bytes: [u8; 24]) -> Self {
        Self(ChachaXNonce::from(bytes))
    }
}

impl Default for InnerChachaXNonce {
    fn default() -> Self {
        Self(ChachaXNonce::from([0u8; 24]))
    }
}

#[derive(Default, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
#[cfg_attr(test, derive(Debug))]
pub struct XNonce {
    inner: InnerChachaXNonce,
    __drop_sentinel: DropSentinel,
}

impl AsRef<ChachaXNonce> for XNonce {
    fn as_ref(&self) -> &ChachaXNonce {
        &self.inner.0
    }
}

impl Zeroizable for XNonce {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for XNonce {
    #[inline]
    fn is_zeroized(&self) -> bool {
        self.inner.0.iter().all(|&b| b == 0)
    }
}

impl AssertZeroizeOnDrop for XNonce {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl XNonce {
    pub fn from(bytes: [u8; 24]) -> Self {
        Self {
            inner: InnerChachaXNonce::from(bytes),
            __drop_sentinel: DropSentinel::default(),
        }
    }

    pub fn fill_exact(&mut self, bytes: &mut [u8; 24]) {
        self.inner.0.zeroize();

        let mut inner: [u8; 24] = [0u8; 24];
        for (i, b) in bytes.iter_mut().enumerate() {
            inner[i] = core::mem::take(b);
        }

        self.inner = InnerChachaXNonce::from(inner);
    }
}
