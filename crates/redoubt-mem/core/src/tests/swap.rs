// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::cell::Cell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use redoubt_asm::Backend;
use rstest::rstest;

use crate::swap::{swap_nonoverlapping_using, swap_using};
use crate::{swap, swap_nonoverlapping};

// ============================================================================
// swap
// ============================================================================

proptest! {
    #[test]
    fn test_swap_exchanges_the_two_values(first in any::<[u64; 4]>(), second in any::<[u64; 4]>()) {
        let mut a = first;
        let mut b = second;

        swap(&mut a, &mut b);

        prop_assert_eq!((a, b), (second, first));
    }
}

// ============================================================================
// swap_using
// ============================================================================

/// The pointer, the capacity and the length of a `Vec` have to arrive together:
/// a handle that came apart does not fail here, it fails at the free. The drop
/// count says no third copy was left behind.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_using_exchanges_owners_without_dropping_or_duplicating_them(#[case] backend: Backend) {
    #[repr(C)]
    struct Owner {
        tag: u8,
        holding: Vec<u8>,
        drops: Rc<Cell<usize>>,
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    let drops = Rc::new(Cell::new(0));

    let mut a = Owner {
        tag: 1,
        holding: vec![11_u8; 3],
        drops: drops.clone(),
    };

    let mut b = Owner {
        tag: 2,
        holding: vec![22_u8; 64],
        drops: drops.clone(),
    };

    let held_a = (a.holding.as_ptr(), a.holding.capacity());
    let held_b = (b.holding.as_ptr(), b.holding.capacity());

    swap_using(backend, &mut a, &mut b);

    assert_eq!((a.tag, &a.holding[..]), (2, &[22_u8; 64][..]));
    assert_eq!((b.tag, &b.holding[..]), (1, &[11_u8; 3][..]));
    assert_eq!((a.holding.as_ptr(), a.holding.capacity()), held_b);
    assert_eq!((b.holding.as_ptr(), b.holding.capacity()), held_a);
    assert_eq!(drops.get(), 0, "a swap drops nothing");

    drop(a);
    drop(b);

    assert_eq!(drops.get(), 2, "two owners, dropped once each");
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

proptest! {
    #[test]
    fn test_swap_nonoverlapping_exchanges_the_two_ranges(
        pairs in proptest::collection::vec(any::<(u8, u8)>(), 0..1024),
    ) {
        let (first, second): (Vec<u8>, Vec<u8>) = pairs.into_iter().unzip();
        let mut a = first.clone();
        let mut b = second.clone();

        // SAFETY: two distinct allocations of the same length.
        unsafe { swap_nonoverlapping(a.as_mut_ptr(), b.as_mut_ptr(), a.len()) };

        prop_assert_eq!((a, b), (second, first));
    }
}

// ============================================================================
// swap_nonoverlapping_using
// ============================================================================

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_using_counts_in_elements(#[case] backend: Backend) {
    let mut a = [0x1234_5678_dead_beef_u64; 67];
    let mut b = [0xfedc_ba98_7654_3210_u64; 67];

    // SAFETY: 65 elements starting at index 1 of two arrays of 67, which are
    // separate allocations.
    unsafe { swap_nonoverlapping_using(backend, a.as_mut_ptr().add(1), b.as_mut_ptr().add(1), 65) };

    assert!(a[1..66].iter().all(|&v| v == 0xfedc_ba98_7654_3210));
    assert!(b[1..66].iter().all(|&v| v == 0x1234_5678_dead_beef));
    assert_eq!(a[0], a[66], "wrote outside the range");
    assert_eq!(b[0], b[66], "wrote outside the range");
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_using_touches_nothing_for_a_count_of_zero(#[case] backend: Backend) {
    let dangling = core::ptr::NonNull::<u64>::dangling().as_ptr();

    // SAFETY: a count of zero reads and writes nothing, which a dangling
    // pointer is allowed to be handed.
    unsafe { swap_nonoverlapping_using(backend, dangling, dangling, 0) };
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_using_touches_nothing_for_a_type_of_no_size(#[case] backend: Backend) {
    let zero_sized = core::ptr::NonNull::<()>::dangling().as_ptr();

    // SAFETY: every count of a zero-sized type is zero bytes, `usize::MAX`
    // included.
    unsafe { swap_nonoverlapping_using(backend, zero_sized, zero_sized, usize::MAX) };
}
