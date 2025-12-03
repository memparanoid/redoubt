// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

use memcode::{
    MemCodeTestBreaker as InnerMemCodeTestBreaker, MemCodeTestBreakerBehaviour, MemCodec,
};
use memzer::{
    AssertZeroizeOnDrop, DropSentinel, FastZeroizable, ZeroizationProbe, assert::assert_zeroize_on_drop,
};

#[derive(Default, Debug, MemCodec, Zeroize)]
#[zeroize(drop)]
pub struct MemCodeTestBreaker(InnerMemCodeTestBreaker, #[memcode(default)] DropSentinel);

impl MemCodeTestBreaker {
    pub fn new(behaviour: MemCodeTestBreakerBehaviour) -> Self {
        Self(
            InnerMemCodeTestBreaker::new(behaviour),
            DropSentinel::default(),
        )
    }
}

impl Deref for MemCodeTestBreaker {
    type Target = InnerMemCodeTestBreaker;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MemCodeTestBreaker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FastZeroizable for MemCodeTestBreaker {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for MemCodeTestBreaker {
    fn is_zeroized(&self) -> bool {
        self.0.is_zeroized()
    }
}

impl AssertZeroizeOnDrop for MemCodeTestBreaker {
    fn clone_drop_sentinel(&self) -> DropSentinel {
        self.1.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self)
    }
}
