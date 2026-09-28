// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! That both backends exchange exactly what they were asked to, and nothing
//! else.
//!
//! The oracle is [`core::ptr::swap_nonoverlapping`], run beside each exchange,
//! so the answer is not read out of the implementation under test. Both
//! buffers are compared end to end, so a write one byte outside the range is a
//! failure here; the guard-page test asks the same of a read.

use std::vec::Vec;

use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::swap_nonoverlapping;

/// Cases that are the same on every run and on every machine.
///
/// Deterministic on purpose: a failure under emulation is a failure anyone can
/// reproduce, which a random seed would not be. It is three shifts rather than
/// a dependency because nothing here needs the distribution to be good, only
/// for the bytes to differ from each other.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;

        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// One exchange against `core`'s, and then back again.
///
/// Three claims in one place, because they need the same setup: that the
/// exchange matches the oracle, that nothing outside the range moved, and that
/// doing it twice restores both buffers — which catches a routine that writes
/// the right bytes to the wrong side.
fn matches_core(
    backend: Backend,
    a: &mut [u8],
    b: &mut [u8],
    offset_a: usize,
    offset_b: usize,
    n: usize,
) {
    let original_a = a.to_vec();
    let original_b = b.to_vec();

    let mut expected_a = a.to_vec();
    let mut expected_b = b.to_vec();

    // SAFETY: both offsets are within their buffers, `n` elements fit past
    // each, and the two buffers are separate allocations.
    unsafe {
        core::ptr::swap_nonoverlapping(
            expected_a.as_mut_ptr().add(offset_a),
            expected_b.as_mut_ptr().add(offset_b),
            n,
        );

        swap_nonoverlapping(
            backend,
            a.as_mut_ptr().add(offset_a),
            b.as_mut_ptr().add(offset_b),
            n,
        );
    }

    assert_eq!(a, expected_a, "left: n={n}, offsets={offset_a},{offset_b}");
    assert_eq!(b, expected_b, "right: n={n}, offsets={offset_a},{offset_b}");

    // SAFETY: as above, on buffers of the same shape.
    unsafe {
        swap_nonoverlapping(
            backend,
            a.as_mut_ptr().add(offset_a),
            b.as_mut_ptr().add(offset_b),
            n,
        );
    }

    assert_eq!(a, original_a, "swapping twice must restore the left buffer");
    assert_eq!(
        b, original_b,
        "swapping twice must restore the right buffer"
    );
}

// ============================================================================
// swap_nonoverlapping
// ============================================================================

/// Every size the routine has a path for, at every alignment it can be handed.
///
/// The assembly branches on the low bits of the length — thirty-two down to
/// one — and on nothing else, so every combination of those bits is a distinct
/// path and all of them are here. The offsets are independent because the two
/// pointers are: a routine that assumed they shared an alignment would pass a
/// test that moved them together.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_matches_core_at_every_small_size_and_alignment(
    #[case] backend: Backend,
) {
    let mut generator = Generator(0x4db7_629e_c185_3fa1);

    let mut a = generator.bytes(384);
    let mut b = generator.bytes(384);

    for n in 0..=256 {
        for offset_a in 0..64 {
            for offset_b in 0..64 {
                matches_core(backend, &mut a, &mut b, offset_a, offset_b, n);
            }
        }
    }
}

/// Sizes past anything the small sweep reaches, including the boundaries.
///
/// Two thousand generated cases and then the sizes either side of sixty-four
/// kilobytes and of a megabyte by hand, because an off-by-one in the loop
/// counter shows at a boundary and nowhere else.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_matches_core_at_generated_sizes_and_offsets(#[case] backend: Backend) {
    let mut generator = Generator(0xd39a_745b_126f_e801);

    for case in 0..2048 {
        let n = if case < 64 {
            case
        } else {
            generator.next() as usize % 65537
        };

        let offset_a = generator.next() as usize % 128;
        let offset_b = generator.next() as usize % 128;

        let mut a = generator.bytes(n + 256);
        let mut b = generator.bytes(n + 256);

        matches_core(backend, &mut a, &mut b, offset_a, offset_b, n);
    }

    for n in [65535, 65536, 65537, 1048575, 1048576, 1048577] {
        let mut a = generator.bytes(n + 128);
        let mut b = generator.bytes(n + 128);

        matches_core(backend, &mut a, &mut b, 1, 63, n);
    }
}

/// Ranges that touch, in both address orders.
///
/// Disjoint but adjacent is the closest two ranges can be without breaking the
/// contract, and it is where a routine that walked one pointer too far would
/// corrupt the other rather than fault. Both orders, because the assembly
/// advances both pointers and nothing says which is lower.
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_exchanges_adjacent_ranges_in_both_address_orders(
    #[case] backend: Backend,
) {
    for n in 1..=1024 {
        let mut data: Vec<u8> = (0..2 * n + 2)
            .map(|i| ((i * 131) ^ (i >> 8)) as u8)
            .collect();

        let original = data.clone();
        let mut expected = data.clone();

        expected[1..n + 1].copy_from_slice(&original[n + 1..2 * n + 1]);
        expected[n + 1..2 * n + 1].copy_from_slice(&original[1..n + 1]);

        // SAFETY: the two ranges are `n` bytes each inside one allocation of
        // `2n + 2`, starting at 1 and at `n + 1`, so they do not overlap.
        unsafe {
            swap_nonoverlapping(
                backend,
                data.as_mut_ptr().add(1),
                data.as_mut_ptr().add(n + 1),
                n,
            )
        };

        assert_eq!(data, expected);

        // SAFETY: the same two ranges, named the other way round.
        unsafe {
            swap_nonoverlapping(
                backend,
                data.as_mut_ptr().add(n + 1),
                data.as_mut_ptr().add(1),
                n,
            )
        };

        assert_eq!(data, original);
    }
}

// ============================================================================
// The bound the kernel enforces
// ============================================================================

/// A page with no permissions on each side of both ranges.
///
/// The comparisons above would catch a byte written outside the range only
/// because both buffers are compared whole. This catches a byte *read* outside
/// it as well, which nothing in Rust can see: a load from a `PROT_NONE` page
/// is a signal, and the test dies rather than passing quietly.
///
/// Every size up to a page, and each range placed at the start and at the end
/// of its own, so that both edges are against the wall.
#[cfg(unix)]
#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_swap_nonoverlapping_touches_nothing_outside_either_range(#[case] backend: Backend) {
    /// One readable page with an unreadable one on each side.
    struct Walled {
        base: *mut u8,
        size: usize,
    }

    impl Walled {
        fn new() -> Self {
            // SAFETY: a fresh anonymous mapping of three pages, of which the
            // middle one is then made readable and writable. Nothing else
            // refers to it.
            unsafe {
                let size = libc::sysconf(libc::_SC_PAGESIZE);

                assert!(size > 0);

                let size = size as usize;

                let at = libc::mmap(
                    core::ptr::null_mut(),
                    size * 3,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                assert_ne!(at, libc::MAP_FAILED);

                let walled = Self {
                    base: at.cast(),
                    size,
                };

                assert_eq!(
                    libc::mprotect(
                        walled.base.add(size).cast(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE
                    ),
                    0
                );

                walled
            }
        }
    }

    impl Drop for Walled {
        fn drop(&mut self) {
            // SAFETY: the mapping this struct made, in one piece.
            unsafe { libc::munmap(self.base.cast(), self.size * 3) };
        }
    }

    let a = Walled::new();
    let b = Walled::new();

    // SAFETY: each slice is the readable middle page of its own mapping.
    unsafe {
        let left = core::slice::from_raw_parts_mut(a.base.add(a.size), a.size);
        let right = core::slice::from_raw_parts_mut(b.base.add(b.size), b.size);

        for (at, byte) in left.iter_mut().enumerate() {
            *byte = ((at * 131) ^ (at >> 8)) as u8;
        }

        for (at, byte) in right.iter_mut().enumerate() {
            *byte = ((at * 79) ^ (at >> 4) ^ 0xff) as u8;
        }

        for n in 0..=a.size {
            for against_the_end_a in [false, true] {
                for against_the_end_b in [false, true] {
                    matches_core(
                        backend,
                        left,
                        right,
                        if against_the_end_a { a.size - n } else { 0 },
                        if against_the_end_b { b.size - n } else { 0 },
                        n,
                    );
                }
            }
        }
    }
}
