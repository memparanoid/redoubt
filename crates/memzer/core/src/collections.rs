// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Trait implementations and helpers for collections (slices, arrays, `Vec<T>`).

use zeroize::Zeroize;

use super::traits::{Zeroizable, ZeroizationProbe};

/// Converts a mutable reference to a trait object (`&mut dyn Zeroizable`).
///
/// Helper for working with heterogeneous collections where elements implement
/// `Zeroizable` but may have different concrete types.
#[inline(always)]
pub fn to_zeroizable_dyn_mut<'a, T: Zeroizable>(x: &'a mut T) -> &'a mut (dyn Zeroizable + 'a) {
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
/// Iterates over `&mut dyn Zeroizable` and calls `.self_zeroize()` on each element.
pub fn zeroize_collection(collection_iter: &mut dyn Iterator<Item = &mut dyn Zeroizable>) {
    for z in collection_iter {
        z.self_zeroize();
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

// === === === === === === === === === ===
// String
// === === === === === === === === === ===
impl Zeroizable for String {
    fn self_zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizationProbe for String {
    fn is_zeroized(&self) -> bool {
        memutil::is_slice_zeroized(self.as_bytes())
    }
}

// =============================================================================
// FastZeroize implementations
// =============================================================================

use super::traits::FastZeroize;

// Arrays [T; N]
impl<T: FastZeroize, const N: usize> FastZeroize for [T; N] {
    // Arrays inherit bulk-zeroize capability from their element type
    const CAN_BE_BULK_ZEROIZED: bool = T::CAN_BE_BULK_ZEROIZED;

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

// Vec<T>
impl<T: FastZeroize> FastZeroize for Vec<T> {
    // Vec can NEVER be bulk-zeroized from outside (has ptr/len/capacity)
    const CAN_BE_BULK_ZEROIZED: bool = false;

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

// String
impl FastZeroize for String {
    // String can NEVER be bulk-zeroized from outside (has ptr/len/capacity)
    const CAN_BE_BULK_ZEROIZED: bool = false;

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
