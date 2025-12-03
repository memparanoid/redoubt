// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations and helpers for collections (slices, arrays, `Vec<T>`).

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

/// Zeroizes all elements in a slice collection via an iterator.
///
/// Specialized version of [`zeroize_collection`] optimized for slices.
#[inline(always)]
pub fn zeroize_slice_collection(
    collection_iter: &mut dyn Iterator<Item = &mut dyn FastZeroizable>,
) {
    for elem in collection_iter {
        elem.fast_zeroize();
    }
}

// === === === === === === === === === ===
// [T] - slices
// === === === === === === === === === ===
impl<T> ZeroizeMetadata for [T]
where
    T: FastZeroizable,
{
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T> FastZeroizable for [T]
where
    T: FastZeroizable,
{
    fn fast_zeroize(&mut self) {
        zeroize_slice_collection(&mut self.iter_mut().map(to_fast_zeroizable_dyn_mut));
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
// [T; N] - arrays
// === === === === === === === === === ===
impl<T: ZeroizeMetadata, const N: usize> ZeroizeMetadata for [T; N] {
    // Arrays inherit bulk-zeroize capability from their element type
    const CAN_BE_BULK_ZEROIZED: bool = T::CAN_BE_BULK_ZEROIZED;
}

impl<T: ZeroizeMetadata + FastZeroizable, const N: usize> FastZeroizable for [T; N] {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        if T::CAN_BE_BULK_ZEROIZED {
            // Fast path: bulk zeroize the entire array
            memutil::fast_zeroize_slice(self.as_mut_slice());
        } else {
            // Slow path: recursively zeroize each element
            for elem in self.iter_mut() {
                elem.fast_zeroize();
            }
        }
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
impl<T: ZeroizeMetadata> ZeroizeMetadata for Vec<T> {
    // Vec can NEVER be bulk-zeroized from outside (has ptr/len/capacity)
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T: ZeroizeMetadata + FastZeroizable> FastZeroizable for Vec<T> {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        if T::CAN_BE_BULK_ZEROIZED {
            // T is primitive: fast zeroize entire allocation (contents + spare capacity)
            memutil::fast_zeroize_vec(self);
        } else {
            // T is complex: recursively zeroize each element, then spare capacity
            for elem in self.iter_mut() {
                elem.fast_zeroize();
            }
            memutil::zeroize_spare_capacity(self);
        }
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
            memutil::fast_zeroize_vec(vec_bytes);
        }
    }
}

impl ZeroizationProbe for String {
    fn is_zeroized(&self) -> bool {
        memutil::is_slice_zeroized(self.as_bytes())
    }
}
