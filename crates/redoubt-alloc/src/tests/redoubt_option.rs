// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::{RedoubtOption, RedoubtOptionError};
use redoubt_zero::ZeroizationProbe;

#[test]
fn test_redoubt_option_is_none_by_default() {
    let opt = RedoubtOption::<u64>::default();
    assert!(opt.is_none());
    assert!(!opt.is_some());
}

#[test]
fn test_redoubt_option_as_ref_empty() {
    let opt = RedoubtOption::<u64>::default();
    let result = opt.as_ref();
    assert!(result.is_err());
    assert!(matches!(result, Err(RedoubtOptionError::Empty)));
}

#[test]
fn test_redoubt_option_as_mut_empty() {
    let mut opt = RedoubtOption::<u64>::default();
    let result = opt.as_mut();
    assert!(result.is_err());
    assert!(matches!(result, Err(RedoubtOptionError::Empty)));
}

#[test]
fn test_redoubt_option_replace() {
    let mut opt = RedoubtOption::<u64>::default();
    let mut value = 42u64;

    opt.replace(&mut value);

    assert!(opt.is_some());
    assert_eq!(*opt.as_ref().expect("Failed to get as_ref"), 42);
    assert!(value.is_zeroized());
}

#[test]
fn test_redoubt_option_replace_zeroizes_old_value() {
    let mut opt = RedoubtOption::<u64>::default();

    let mut value1 = 42u64;
    opt.replace(&mut value1);

    let mut value2 = 99u64;
    opt.replace(&mut value2);

    assert_eq!(*opt.as_ref().expect("Failed to get as_ref"), 99);
    assert!(value1.is_zeroized());
    assert!(value2.is_zeroized());
}

#[test]
fn test_redoubt_option_take_some() {
    let mut opt = RedoubtOption::<u64>::default();
    let mut value = 42u64;
    opt.replace(&mut value);

    let taken = opt.take();
    assert!(taken.is_some());
    assert_eq!(taken.expect("Failed to take"), 42);
    assert!(opt.is_none());
}

#[test]
fn test_redoubt_option_take_none() {
    let mut opt = RedoubtOption::<u64>::default();
    let taken = opt.take();
    assert!(taken.is_none());
    assert!(opt.is_none());
}

#[test]
fn test_redoubt_option_as_mut() {
    let mut opt = RedoubtOption::<u64>::default();
    let mut value = 42u64;
    opt.replace(&mut value);

    let val_mut = opt.as_mut().expect("Failed to get as_mut");
    *val_mut = 99;

    assert_eq!(*opt.as_ref().expect("Failed to get as_ref"), 99);
}
