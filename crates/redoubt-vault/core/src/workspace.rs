// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use quiesce::{Mutex, MutexGuard};
use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use super::types::Data;

/// A buffer one reader at a time decrypts into, kept between reads so that a
/// read allocates nothing.
pub(crate) struct Workspace(Mutex<Data>);

impl Workspace {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Data::new()))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Data> {
        self.0.lock()
    }
}

impl ZeroizeMetadata for Workspace {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for Workspace {
    fn fast_zeroize(&mut self) {
        self.0.get_mut().fast_zeroize();
    }
}

impl ZeroizationProbe for Workspace {
    fn is_zeroized(&self) -> bool {
        self.lock().is_zeroized()
    }
}
