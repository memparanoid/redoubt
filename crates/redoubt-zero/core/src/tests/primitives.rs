// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[test]
fn test_primitive_zeroization_roundtrip() {
    use crate::traits::{FastZeroizable, ZeroizationProbe};

    macro_rules! run_test_for {
        ($ty:ty) => {{
            let mut value: $ty = 0;
            assert!(
                value.is_zeroized(),
                concat!("Zero value should be zeroized for ", stringify!($ty))
            );

            value = <$ty>::MAX;
            assert!(
                !value.is_zeroized(),
                concat!("MAX value should not be zeroized for ", stringify!($ty))
            );

            value.fast_zeroize();
            assert!(
                value.is_zeroized(),
                concat!(
                    "Value should be zeroized after fast_zeroize for ",
                    stringify!($ty)
                )
            );
            assert_eq!(
                value, 0,
                concat!("Value should be 0 after zeroize for ", stringify!($ty))
            );
        }};
    }

    run_test_for!(u8);
    run_test_for!(u16);
    run_test_for!(u32);
    run_test_for!(u64);
    run_test_for!(u128);
    run_test_for!(usize);
    run_test_for!(i8);
    run_test_for!(i16);
    run_test_for!(i32);
    run_test_for!(i64);
    run_test_for!(i128);
    run_test_for!(isize);
}

#[test]
fn test_bool_zeroization_probe() {
    use crate::traits::{FastZeroizable, ZeroizationProbe};

    let mut value = false;
    assert!(value.is_zeroized(), "false should be considered zeroized");

    value = true;
    assert!(!value.is_zeroized(), "true should NOT be zeroized");

    value.fast_zeroize();
    assert!(
        value.is_zeroized(),
        "bool should be zeroized (false) after zeroize"
    );
    assert!(!value);
}

#[test]
fn test_float_zeroization() {
    use crate::traits::{FastZeroizable, ZeroizationProbe};

    // f32
    let mut value_f32: f32 = 0.0;
    assert!(value_f32.is_zeroized(), "0.0 f32 should be zeroized");

    value_f32 = 1.5;
    assert!(!value_f32.is_zeroized(), "1.5 f32 should not be zeroized");

    value_f32.fast_zeroize();
    assert!(
        value_f32.is_zeroized(),
        "f32 should be zeroized after fast_zeroize"
    );
    assert_eq!(value_f32, 0.0);

    // f64
    let mut value_f64: f64 = 0.0;
    assert!(value_f64.is_zeroized(), "0.0 f64 should be zeroized");

    value_f64 = core::f64::consts::PI;
    assert!(
        !value_f64.is_zeroized(),
        "PI f64 should not be zeroized"
    );

    value_f64.fast_zeroize();
    assert!(
        value_f64.is_zeroized(),
        "f64 should be zeroized after fast_zeroize"
    );
    assert_eq!(value_f64, 0.0);
}

#[test]
fn test_char_zeroization() {
    use crate::traits::{FastZeroizable, ZeroizationProbe};

    let mut value = '\0';
    assert!(value.is_zeroized(), "null char should be zeroized");

    value = 'A';
    assert!(!value.is_zeroized(), "'A' should not be zeroized");

    value.fast_zeroize();
    assert!(
        value.is_zeroized(),
        "char should be zeroized after fast_zeroize"
    );
    assert_eq!(value, '\0');
}
