// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use crate::assert::assert_zeroize_on_drop;
use crate::collections::{collection_zeroed, to_zeroization_probe_dyn_ref};
use crate::drop_sentinel::DropSentinel;
use crate::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};
use crate::zeroizing_mut_guard::ZeroizingMutGuard;

#[derive(Zeroize)]
#[zeroize(drop)]
struct Foo {
    pub data: Vec<u8>,
    __drop_sentinel: DropSentinel,
}

impl Default for Foo {
    fn default() -> Self {
        Self {
            data: vec![1, 2, 3, 4],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl ZeroizationProbe for Foo {
    fn is_zeroized(&self) -> bool {
        let fields: [&dyn ZeroizationProbe; 1] = [to_zeroization_probe_dyn_ref(&self.data)];
        // `fields.into_iter()` produces &dyn ZeroizationProbe directly,
        // avoiding the double reference (&&) that `.iter()` would create.
        // No values are copied - we're just iterating over references from the array.
        collection_zeroed(&mut fields.into_iter())
    }
}

impl AssertZeroizeOnDrop for Foo {
    fn clone_drop_sentinel(&self) -> crate::drop_sentinel::DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl Zeroizable for Foo {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct FunctionalStruct<'a> {
    pub bytes: Vec<u8>,
    pub bytes_16: [u8; 16],
    pub bytes_32: [u8; 32],
    pub foo: ZeroizingMutGuard<'a, Foo>,
    __drop_sentinel: DropSentinel,
}

impl<'a> FunctionalStruct<'a> {
    fn new(foo: &'a mut Foo) -> Self {
        let mut bytes = Vec::new();
        bytes.resize_with(128, || u8::MAX);

        Self {
            bytes,
            bytes_16: [u8::MAX; 16],
            bytes_32: [u8::MAX; 32],
            foo: ZeroizingMutGuard::from(foo),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl<'a> ZeroizationProbe for FunctionalStruct<'a> {
    fn is_zeroized(&self) -> bool {
        let fields: [&dyn ZeroizationProbe; 4] = [
            to_zeroization_probe_dyn_ref(&self.bytes_16),
            to_zeroization_probe_dyn_ref(&self.bytes_32),
            to_zeroization_probe_dyn_ref(&self.bytes),
            to_zeroization_probe_dyn_ref(&self.foo),
        ];
        // `fields.into_iter()` produces &dyn ZeroizationProbe directly,
        // avoiding the double reference (&&) that `.iter()` would create.
        // No values are copied - we're just iterating over references from the array.
        collection_zeroed(&mut fields.into_iter())
    }
}

impl<'a> AssertZeroizeOnDrop for FunctionalStruct<'a> {
    fn clone_drop_sentinel(&self) -> crate::drop_sentinel::DropSentinel {
        self.__drop_sentinel.clone()
    }

    fn assert_zeroize_on_drop(self) {
        assert_zeroize_on_drop(self);
    }
}

impl<'a> Zeroizable for FunctionalStruct<'a> {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

#[test]
fn test_functionl_struct() {
    let mut foo = Foo::default();

    // Assert (not) zeroization!
    assert!(!foo.is_zeroized());

    let mut fs = FunctionalStruct::new(&mut foo);

    // Assert (not) zeroization!
    assert!(!fs.is_zeroized());

    fs.zeroize();

    // Assert zeroization!
    assert!(fs.is_zeroized());

    fs.assert_zeroize_on_drop();
}
