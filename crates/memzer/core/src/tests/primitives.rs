// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[test]
fn test_primitive_zeroization_roundtrip() {
    macro_rules! run_test_for {
        ($ty:ty, $fn_name:ident, $wrapper_ty:ident) => {{
            use $crate::primitives::$fn_name;
            use $crate::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

            let mut value = $fn_name();

            assert_eq!(value.expose(), &0);
            assert!(value.is_zeroized(), "Default value should be zeroized");

            *value.expose_mut() = <$ty>::MAX;
            assert_eq!(value.expose(), &<$ty>::MAX);

            assert!(
                !value.is_zeroized(),
                concat!("Not zeroized after mutate for ", stringify!($ty))
            );

            value.self_zeroize();

            assert!(
                value.is_zeroized(),
                concat!("Not zeroized after zeroize for ", stringify!($ty))
            );

            // Assert on drop probe
            value.assert_zeroize_on_drop();
        }};
    }

    run_test_for!(u8, u8, U8);
    run_test_for!(u16, u16, U16);
    run_test_for!(u32, u32, U32);
    run_test_for!(u64, u64, U64);
    run_test_for!(u128, u128, U128);
    run_test_for!(usize, usize, USIZE);
}

#[test]
fn test_bool_zeroization_probe() {
    use crate::traits::{Zeroizable, ZeroizationProbe};

    let mut value = false;
    assert!(value.is_zeroized(), "false should be considered zeroized");

    value = true;
    assert!(!value.is_zeroized(), "true should NOT be zeroized");

    value.self_zeroize();
    assert!(value.is_zeroized(), "bool should be zeroized (false) after zeroize");
    assert!(!value);
}
