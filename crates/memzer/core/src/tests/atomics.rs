// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::sync::atomic::Ordering;

use crate::traits::{FastZeroizable, ZeroizationProbe};

macro_rules! test_atomic_int_zeroization {
    ($($ty:ty => $non_zero:expr),* $(,)?) => {
        $(
            {
                let mut value = <$ty>::new(0);
                assert!(
                    value.is_zeroized(),
                    concat!("Zero value should be zeroized for ", stringify!($ty))
                );

                value.store($non_zero, Ordering::Relaxed);
                assert!(
                    !value.is_zeroized(),
                    concat!("Non-zero value should not be zeroized for ", stringify!($ty))
                );

                value.fast_zeroize();
                assert!(
                    value.is_zeroized(),
                    concat!("Value should be zeroized after fast_zeroize for ", stringify!($ty))
                );
                assert_eq!(
                    value.load(Ordering::Relaxed),
                    0,
                    concat!("Value should be 0 after zeroize for ", stringify!($ty))
                );
            }
        )*
    };
}

#[test]
fn test_atomic_int_zeroization_roundtrip() {
    use core::sync::atomic::{AtomicI8, AtomicI16, AtomicI32, AtomicI64, AtomicIsize};
    use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize};

    test_atomic_int_zeroization!(
        AtomicU8 => 42,
        AtomicU16 => 1000,
        AtomicU32 => 100_000,
        AtomicU64 => 1_000_000_000,
        AtomicUsize => 12345,
        AtomicI8 => -42,
        AtomicI16 => -1000,
        AtomicI32 => -100_000,
        AtomicI64 => -1_000_000_000,
        AtomicIsize => -12345,
    );
}

#[test]
fn test_atomic_bool_zeroization() {
    use core::sync::atomic::AtomicBool;

    let mut value = AtomicBool::new(false);
    assert!(value.is_zeroized(), "false should be considered zeroized");

    value.store(true, Ordering::Relaxed);
    assert!(!value.is_zeroized(), "true should NOT be zeroized");

    value.fast_zeroize();
    assert!(
        value.is_zeroized(),
        "AtomicBool should be zeroized (false) after fast_zeroize"
    );
    assert!(!value.load(Ordering::Relaxed));
}
