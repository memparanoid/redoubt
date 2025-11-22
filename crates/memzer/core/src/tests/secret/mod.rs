// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::fmt::Write;

use crate::secret::Secret;
use crate::traits::{AssertZeroizeOnDrop, Zeroizable, ZeroizationProbe};

#[cfg(any(test, feature = "memcode"))]
mod features;

#[test]
fn test_secret_assert_zeroization_probe_trait() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let mut secret = Secret::from(vec);

    // Assert (not) zeroization!
    assert!(!secret.is_zeroized());

    secret.self_zeroize();

    // Assert zeroization!
    assert!(secret.is_zeroized());
}

#[test]
fn test_secret_assert_zeroed_on_drop_trait() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let secret = Secret::from(vec);

    secret.assert_zeroize_on_drop();
}

#[test]
fn test_secret_expose_methods() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let mut secret = Secret::from(vec);

    fn with_ref(vec: &[u8]) -> bool {
        vec.iter().sum::<u8>() == 15
    }

    fn with_mut(vec: &mut [u8]) -> bool {
        for item in vec.iter_mut() {
            *item *= 2
        }

        vec.iter().sum::<u8>() == 30
    }

    assert!(with_ref(secret.expose()));
    assert!(with_mut(secret.expose_mut()));
}

#[test]
fn test_secret_debug() {
    let inner = vec![1u8, 2, 3];
    let secret = Secret::from(inner);

    let mut buf = String::new();
    write!(&mut buf, "{:?}", secret).unwrap();
    assert_eq!(buf, "[REDACTED Secret]", "Debug should redact Secret");
}
