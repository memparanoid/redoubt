// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations and helpers for collections (slices, arrays, `Vec<T>`).
use alloc::string::String;
use alloc::vec::Vec;

use core::sync::atomic::{Ordering, compiler_fence};

use super::traits::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

/// Converts a mutable reference to a trait object (`&mut dyn FastZeroizable`).
///
/// Helper for working with heterogeneous collections where elements implement
/// `FastZeroizable` but may have different concrete types.
#[inline(always)]
pub fn to_fast_zeroizable_dyn_mut<'a, T: FastZeroizable>(
    x: &'a mut T,
) -> &'a mut (dyn FastZeroizable + 'a) {
    x
}

/// Converts a reference to a trait object (`&dyn ZeroizationProbe`).
///
/// Helper for working with heterogeneous collections where elements implement
/// `ZeroizationProbe` but may have different concrete types.
#[inline(always)]
pub fn to_zeroization_probe_dyn_ref<'a, T: ZeroizationProbe>(
    x: &'a T,
) -> &'a (dyn ZeroizationProbe + 'a) {
    x
}

/// Zeroizes all elements in a collection via an iterator.
///
/// Iterates over `&mut dyn FastZeroizable` and calls `.fast_zeroize()` on each element.
pub fn zeroize_collection(collection_iter: &mut dyn Iterator<Item = &mut dyn FastZeroizable>) {
    for z in collection_iter {
        z.fast_zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Checks if all elements in a collection are zeroized.
///
/// Returns `true` if all elements return `true` for `.is_zeroized()`, `false` otherwise.
pub fn collection_zeroed(collection_iter: &mut dyn Iterator<Item = &dyn ZeroizationProbe>) -> bool {
    for z in collection_iter {
        if !z.is_zeroized() {
            return false;
        }
    }

    true
}

// === === === === === === === === === ===
// [T] - slices
// === === === === === === === === === ===
/// Zeroizes an array using either bulk memset or recursive element zeroization.
///
/// When `fast=true`, forces bulk memset regardless of `T::CAN_BE_BULK_ZEROIZED`.
/// When `fast=false`, recursively zeroizes each element.
///
/// This function is exposed for testing both code paths independently.
#[inline(always)]
pub(crate) fn slice_fast_zeroize<T: FastZeroizable + ZeroizeMetadata>(slice: &mut [T], fast: bool) {
    if fast {
        // Fast path: bulk zeroize the entire array
        redoubt_util::fast_zeroize_slice(slice);
        compiler_fence(Ordering::SeqCst);
    } else {
        // Slow path: recursively zeroize each element
        for elem in slice.iter_mut() {
            elem.fast_zeroize();
            compiler_fence(Ordering::SeqCst);
        }
    }
}

impl<T> ZeroizeMetadata for [T]
where
    T: FastZeroizable + ZeroizeMetadata,
{
    const CAN_BE_BULK_ZEROIZED: bool = T::CAN_BE_BULK_ZEROIZED;
}

impl<T> FastZeroizable for [T]
where
    T: FastZeroizable + ZeroizeMetadata,
{
    fn fast_zeroize(&mut self) {
        slice_fast_zeroize(self, T::CAN_BE_BULK_ZEROIZED);
    }
}

impl<T> ZeroizationProbe for [T]
where
    T: ZeroizeMetadata + FastZeroizable + ZeroizationProbe,
{
    fn is_zeroized(&self) -> bool {
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
    }
}

// === === === === === === === === === ===
// [T; N] - arrays
// === === === === === === === === === ===

/// Zeroizes an array using either bulk memset or recursive element zeroization.
///
/// When `fast=true`, forces bulk memset regardless of `T::CAN_BE_BULK_ZEROIZED`.
/// When `fast=false`, recursively zeroizes each element.
///
/// This function is exposed for testing both code paths independently.
impl<T: ZeroizeMetadata, const N: usize> ZeroizeMetadata for [T; N] {
    // Arrays inherit bulk-zeroize capability from their element type
    const CAN_BE_BULK_ZEROIZED: bool = T::CAN_BE_BULK_ZEROIZED;
}

impl<T: ZeroizeMetadata + FastZeroizable, const N: usize> FastZeroizable for [T; N] {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        slice_fast_zeroize(self, T::CAN_BE_BULK_ZEROIZED);
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

/// Zeroizes a Vec using either bulk memset or recursive element zeroization.
///
/// When `fast=true`, forces bulk memset of entire allocation (contents + spare capacity).
/// When `fast=false`, recursively zeroizes each element, then spare capacity.
///
/// This function is exposed for testing both code paths independently.
#[inline(always)]
pub(crate) fn vec_fast_zeroize<T: FastZeroizable + ZeroizeMetadata>(vec: &mut Vec<T>, fast: bool) {
    if fast {
        // T is primitive: fast zeroize entire allocation (contents + spare capacity)
        redoubt_util::fast_zeroize_vec(vec);
        compiler_fence(Ordering::SeqCst);
    } else {
        // T is complex: recursively zeroize each element, then spare capacity
        for elem in vec.iter_mut() {
            elem.fast_zeroize();
            compiler_fence(Ordering::SeqCst);
        }
        redoubt_util::zeroize_spare_capacity(vec);
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: ZeroizeMetadata> ZeroizeMetadata for Vec<T> {
    // Vec can NEVER be bulk-zeroized from outside (has ptr/len/capacity)
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T: ZeroizeMetadata + FastZeroizable> FastZeroizable for Vec<T> {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        vec_fast_zeroize(self, T::CAN_BE_BULK_ZEROIZED);
    }
}

impl<T> ZeroizationProbe for Vec<T>
where
    T: ZeroizationProbe,
{
    /// Returns true if all elements AND spare capacity are zeroed.
    ///
    /// # Important
    /// This is only meaningful after calling `fast_zeroize()`.
    /// A freshly allocated Vec may have uninitialized memory in
    /// spare capacity, causing this to return false even if no
    /// sensitive data was ever stored.
    fn is_zeroized(&self) -> bool {
        // Short-circuit: check elements first (cheaper for complex types)
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
            && redoubt_util::is_spare_capacity_zeroized(self)
    }
}

// === === === === === === === === === ===
// String
// === === === === === === === === === ===
impl ZeroizeMetadata for String {
    // String can NEVER be bulk-zeroized from outside (has ptr/len/capacity)
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for String {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        // Safety: String is Vec<u8> internally, and u8::CAN_BE_BULK_ZEROIZED = true
        // SAFETY: This is sound because we're treating String as Vec<u8>
        unsafe {
            let vec_bytes = self.as_mut_vec();
            redoubt_util::fast_zeroize_vec(vec_bytes);
        }
    }
}

impl ZeroizationProbe for String {
    fn is_zeroized(&self) -> bool {
        redoubt_util::is_slice_zeroized(self.as_bytes())
    }
}
