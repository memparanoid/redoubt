// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Re-export of `MemEncodeBuf` with [`DropSentinel`] support.
//!
//! This module wraps `memcode-core`'s `MemEncodeBuf` and adds zeroization verification.

use zeroize::Zeroize;

use crate::assert::assert_zeroize_on_drop;
use crate::drop_sentinel::DropSentinel;
use crate::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

use memcode_core::MemEncodeBuf as InnerMemEncodeBuf;

/// Wrapper around `memcode-core::MemEncodeBuf` with [`DropSentinel`] support.
///
/// This type wraps the serialization buffer from `memcode-core` and adds
/// zeroization verification via an embedded [`DropSentinel`].
///
/// Available only when the `memcode` feature is enabled.
///
/// # Example
///
/// ```rust,ignore
/// use memzer_core::MemEncodeBuf;
///
/// let buf = MemEncodeBuf::default();
/// // Use for encoding...
/// // Auto-zeroizes on drop
/// ```
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MemEncodeBuf {
    inner: InnerMemEncodeBuf,
    __drop_sentinel: DropSentinel,
}

impl AsRef<InnerMemEncodeBuf> for MemEncodeBuf {
    fn as_ref(&self) -> &InnerMemEncodeBuf {
        &self.inner
    }
}

impl AsMut<InnerMemEncodeBuf> for MemEncodeBuf {
    fn as_mut(&mut self) -> &mut InnerMemEncodeBuf {
        &mut self.inner
    }
}

impl Default for MemEncodeBuf {
    fn default() -> Self {
        Self {
            inner: InnerMemEncodeBuf::new(0),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl Zeroizable for MemEncodeBuf {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for MemEncodeBuf {
    fn is_zeroized(&self) -> bool {
        self.inner.as_slice().iter().all(|&b| b == 0)
    }
}

impl AssertZeroizeOnDrop for MemEncodeBuf {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}
