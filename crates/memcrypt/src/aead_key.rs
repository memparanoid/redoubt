// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use chacha20poly1305::Key;
use zeroize::Zeroize;

use memzer::{
    AssertZeroizeOnDrop, DropSentinel, Zeroizable, ZeroizationProbe, assert::assert_zeroize_on_drop,
};

/// AEAD key wrapper with automatic zeroization and drop verification.
///
/// `AeadKey` wraps a 32-byte ChaCha20-Poly1305 key and enforces systematic zeroization
/// via a `DropSentinel`. The key is automatically zeroized on drop, and the sentinel
/// ensures that zeroization was called before the value is dropped.
///
/// # Security Properties
///
/// - **Automatic zeroization**: Key material is zeroized on drop
/// - **Drop verification**: `DropSentinel` panics if `zeroize()` wasn't called
/// - **Debug safety**: `Debug` impl never exposes key bytes
/// - **Zero-copy**: `AsRef<Key>` allows borrowing without copying
///
/// # Example
///
/// ```
/// use memcrypt::AeadKey;
/// use memzer::ZeroizationProbe;
/// use zeroize::Zeroize;
///
/// // Create from bytes
/// let mut key = AeadKey::from([42u8; 32]);
///
/// // Verify not zeroized
/// assert!(!key.is_zeroized());
///
/// // Use the key (via AsRef<Key>)
/// let key_ref: &chacha20poly1305::Key = key.as_ref();
/// assert_eq!(key_ref.len(), 32);
///
/// // Manually zeroize
/// key.zeroize();
/// assert!(key.is_zeroized());
/// ```
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
    /// Creates a new `AeadKey` from a 32-byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use memcrypt::AeadKey;
    ///
    /// let key = AeadKey::from([1u8; 32]);
    /// assert_eq!(key.as_ref().len(), 32);
    /// ```
    pub fn from(bytes: [u8; 32]) -> Self {
        Self {
            key: Key::from(bytes),
            __drop_sentinel: DropSentinel::default(),
        }
    }

    /// Fills this key with bytes from the provided buffer, zeroizing both the old key and the source buffer.
    ///
    /// This method:
    /// 1. Zeroizes the current key
    /// 2. Copies bytes from the source buffer
    /// 3. Zeroizes the source buffer
    ///
    /// # Example
    ///
    /// ```
    /// use memcrypt::AeadKey;
    /// use memzer::ZeroizationProbe;
    ///
    /// let mut key = AeadKey::default();
    /// let mut source = [37u8; 32];
    ///
    /// key.fill_exact(&mut source);
    ///
    /// // Source buffer is zeroized
    /// assert!(source.iter().all(|&b| b == 0));
    ///
    /// // Key contains the original bytes
    /// assert!(key.as_ref().iter().all(|&b| b == 37));
    /// ```
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
