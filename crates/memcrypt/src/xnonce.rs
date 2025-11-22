// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::XNonce as ChachaXNonce;
use zeroize::Zeroize;

use memzer::assert::assert_zeroize_on_drop;
use memzer::{AssertZeroizeOnDrop, DropSentinel, Zeroizable, ZeroizationProbe};

/// XChaCha20 nonce (24 bytes) with automatic zeroization and drop verification.
///
/// `XNonce` wraps a 192-bit (24-byte) extended nonce for XChaCha20-Poly1305 AEAD.
/// It enforces systematic zeroization via a `DropSentinel`.
///
/// # Security Properties
///
/// - **Automatic zeroization**: Nonce is zeroized on drop
/// - **Drop verification**: `DropSentinel` panics if `zeroize()` wasn't called
/// - **Zero-copy**: `AsRef<ChachaXNonce>` allows borrowing without copying
///
/// # Example
///
/// ```
/// use memcrypt::XNonce;
/// use memzer::ZeroizationProbe;
/// use zeroize::Zeroize;
///
/// // Create from bytes
/// let mut nonce = XNonce::from([1u8; 24]);
///
/// // Verify not zeroized
/// assert!(!nonce.is_zeroized());
///
/// // Use the nonce (via AsRef)
/// let nonce_ref: &chacha20poly1305::XNonce = nonce.as_ref();
/// assert_eq!(nonce_ref.len(), 24);
///
/// // Manually zeroize
/// nonce.zeroize();
/// assert!(nonce.is_zeroized());
/// ```
#[derive(Default, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
#[cfg_attr(test, derive(Debug))]
pub struct XNonce {
    inner: ChachaXNonce,
    __drop_sentinel: DropSentinel,
}

impl AsRef<ChachaXNonce> for XNonce {
    fn as_ref(&self) -> &ChachaXNonce {
        &self.inner
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
    /// Fills this nonce with bytes from the provided buffer, zeroizing both the old nonce and the source buffer.
    ///
    /// This method:
    /// 1. Zeroizes the current nonce
    /// 2. Drains bytes from the source buffer (using `mem::take`)
    /// 3. Source buffer is zeroized as a side effect of `mem::take`
    ///
    /// # Example
    ///
    /// ```
    /// use memcrypt::XNonce;
    /// use memzer::ZeroizationProbe;
    ///
    /// let mut nonce = XNonce::default();
    /// let mut source = [7u8; 24];
    ///
    /// nonce.fill_exact(&mut source);
    ///
    /// // Source buffer is zeroized
    /// assert!(source.iter().all(|&b| b == 0));
    ///
    /// // Nonce contains the original bytes
    /// assert!(nonce.as_ref().iter().all(|&b| b == 7));
    /// ```
    pub fn fill_exact(&mut self, bytes: &mut [u8; 24]) {
        for (i, byte) in self.inner.iter_mut().enumerate() {
            *byte = core::mem::take(&mut bytes[i]);
        }
    }
}
