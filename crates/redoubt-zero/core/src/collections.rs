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
/// Empties a slice by writing zeros over its bytes when `fast`, and element by
/// element when not.
///
/// # Safety
///
/// With `fast`, every byte zero has to be a value of `T`.
#[inline(always)]
pub(crate) unsafe fn fast_zeroize_slice<T: FastZeroizable + ZeroizeMetadata>(
    slice: &mut [T],
    fast: bool,
) {
    if fast {
        // SAFETY: the caller's.
        unsafe { redoubt_util::fast_zeroize_slice(slice) };
        compiler_fence(Ordering::SeqCst);
    } else {
        for elem in slice.iter_mut() {
            elem.fast_zeroize();
            compiler_fence(Ordering::SeqCst);
        }
    }
}

// SAFETY: a slice's bytes are its elements', so every byte zero is a slice of
// values exactly when it is a value of `T`, which `T` promised.
unsafe impl<T> ZeroizeMetadata for [T]
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
        // SAFETY: `fast` is `T::CAN_BE_BULK_ZEROIZED`, `true` only where `T`
        // promised every byte zero is one of its values.
        unsafe { fast_zeroize_slice(self, T::CAN_BE_BULK_ZEROIZED) };
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

// SAFETY: an array's bytes are its elements', so every byte zero is an array
// of values exactly when it is a value of `T`, which `T` promised.
unsafe impl<T: ZeroizeMetadata, const N: usize> ZeroizeMetadata for [T; N] {
    const CAN_BE_BULK_ZEROIZED: bool = T::CAN_BE_BULK_ZEROIZED;
}

impl<T: ZeroizeMetadata + FastZeroizable, const N: usize> FastZeroizable for [T; N] {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        // SAFETY: `fast` is `T::CAN_BE_BULK_ZEROIZED`, `true` only where `T`
        // promised every byte zero is one of its values.
        unsafe { fast_zeroize_slice(self, T::CAN_BE_BULK_ZEROIZED) };
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

/// Empties a `Vec` by writing zeros over its whole allocation when `fast`, and
/// element by element and then the spare when not.
///
/// # Safety
///
/// With `fast`, every byte zero has to be a value of `T`.
#[inline(always)]
pub(crate) unsafe fn fast_zeroize_vec<T: FastZeroizable + ZeroizeMetadata>(
    vec: &mut Vec<T>,
    fast: bool,
) {
    if fast {
        // SAFETY: the caller's.
        unsafe { redoubt_util::fast_zeroize_vec(vec) };
        compiler_fence(Ordering::SeqCst);
    } else {
        for elem in vec.iter_mut() {
            elem.fast_zeroize();
            compiler_fence(Ordering::SeqCst);
        }
        redoubt_util::zeroize_spare_capacity(vec);
        compiler_fence(Ordering::SeqCst);
    }
}

// SAFETY: `false` promises nothing.
unsafe impl<T: ZeroizeMetadata> ZeroizeMetadata for Vec<T> {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T: ZeroizeMetadata + FastZeroizable> FastZeroizable for Vec<T> {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        // SAFETY: `fast` is `T::CAN_BE_BULK_ZEROIZED`, `true` only where `T`
        // promised every byte zero is one of its values.
        unsafe { fast_zeroize_vec(self, T::CAN_BE_BULK_ZEROIZED) };
    }
}

impl<T> ZeroizationProbe for Vec<T>
where
    T: ZeroizationProbe,
{
    /// The elements, and not the spare: what a truncate left past `len` is
    /// not seen, because a spare never written is uninitialized and reading it
    /// is undefined.
    fn is_zeroized(&self) -> bool {
        collection_zeroed(&mut self.iter().map(to_zeroization_probe_dyn_ref))
    }
}

// === === === === === === === === === ===
// String
// === === === === === === === === === ===
// SAFETY: `false` promises nothing.
unsafe impl ZeroizeMetadata for String {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for String {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        // SAFETY: every byte zero is a `u8`, and zeros are valid UTF-8, so the
        // `String` the bytes are handed back to holds a `str`.
        unsafe {
            let vec_bytes = self.as_mut_vec();
            redoubt_util::fast_zeroize_vec(vec_bytes);
        }
    }
}

impl ZeroizationProbe for String {
    fn is_zeroized(&self) -> bool {
        redoubt_mem::is_zeroized(self.as_bytes())
    }
}

// Blanket impls for Box<T>
//
// Never bulk, whatever `T` is: a box's own bytes are a pointer, so a memset of
// a collection of boxes empties the pointers and leaves every value they held.
// SAFETY: `false` promises nothing.
unsafe impl<T: ZeroizeMetadata + FastZeroizable> ZeroizeMetadata for alloc::boxed::Box<T> {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T: FastZeroizable> FastZeroizable for alloc::boxed::Box<T> {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        (**self).fast_zeroize();
    }
}

impl<T: ZeroizationProbe> ZeroizationProbe for alloc::boxed::Box<T> {
    fn is_zeroized(&self) -> bool {
        (**self).is_zeroized()
    }
}

// Blanket impls for Option<T>
// Option has discriminant/tag that requires proper handling, cannot bulk zeroize
// SAFETY: `false` promises nothing.
unsafe impl<T: ZeroizeMetadata + FastZeroizable> ZeroizeMetadata for Option<T> {
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl<T: FastZeroizable> FastZeroizable for Option<T> {
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        if let Some(val) = self {
            val.fast_zeroize();
        }
        // Zeroize the discriminant by setting to None
        *self = None;
    }
}

impl<T: ZeroizationProbe> ZeroizationProbe for Option<T> {
    fn is_zeroized(&self) -> bool {
        match self {
            Some(val) => val.is_zeroized(),
            None => true, // None is considered zeroized
        }
    }
}
