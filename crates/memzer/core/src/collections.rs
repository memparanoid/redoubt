// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use super::traits::{Zeroizable, ZeroizationProbe};

#[inline(always)]
pub fn to_zeroizable_dyn_mut<'a, T: Zeroizable>(x: &'a mut T) -> &'a mut (dyn Zeroizable + 'a) {
    x
}

#[inline(always)]
pub fn to_zeroization_probe_dyn_ref<'a, T: ZeroizationProbe>(
    x: &'a T,
) -> &'a (dyn ZeroizationProbe + 'a) {
    x
}

pub fn zeroize_collection(collection_iter: &mut dyn Iterator<Item = &mut dyn Zeroizable>) {
    for z in collection_iter {
        z.self_zeroize();
    }
}

pub fn collection_zeroed(collection_iter: &mut dyn Iterator<Item = &dyn ZeroizationProbe>) -> bool {
    for z in collection_iter {
        if !z.is_zeroized() {
            return false;
        }
    }

    true
}

#[inline(always)]
pub fn zeroize_slice_collection(collection_iter: &mut dyn Iterator<Item = &mut dyn Zeroizable>) {
    for elem in collection_iter {
        elem.self_zeroize();
    }
}

// === === === === === === === === === ===
// [T]
// === === === === === === === === === ===
impl<T> Zeroizable for [T]
where
    T: Zeroizable,
{
    fn self_zeroize(&mut self) {
        zeroize_slice_collection(&mut self.iter_mut().map(to_zeroizable_dyn_mut));
    }
}

impl<T> ZeroizationProbe for [T]
where
    T: ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
    }
}

// === === === === === === === === === ===
// [T; N]
// === === === === === === === === === ===
impl<T, const N: usize> Zeroizable for [T; N]
where
    T: Zeroize + Zeroizable,
{
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl<T, const N: usize> ZeroizationProbe for [T; N]
where
    T: ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
    }
}

// === === === === === === === === === ===
// Vec<T>
// === === === === === === === === === ===
impl<T> Zeroizable for Vec<T>
where
    T: Zeroize + Zeroizable,
{
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl<T> ZeroizationProbe for Vec<T>
where
    T: ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
    }
}
