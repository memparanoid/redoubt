// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate std;

use alloc::vec::Vec;
use core::cell::{Cell, OnceCell};

use crate::error::EntropyError;
use crate::system::SystemEntropySource;
use crate::traits::EntropySource;

/// Configurable behavior for [`MockEntropySource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockEntropySourceBehaviour {
    /// Normal operation (delegates to real entropy source).
    None,
    /// Always fail fill_bytes.
    FailAlways,
    /// Fail fill_bytes on the Nth call (1-indexed: 1 = first call fails).
    FailAtNthFillBytes(usize),
    /// Hands out the stream in order, each fill the next piece as long as what
    /// it fills, and fails once what is left is shorter.
    YieldOver(&'static [u8]),
}

/// Mock entropy source for testing.
///
/// Wraps [`SystemEntropySource`], fails on demand, or hands out a stream the
/// test chose, as [`MockEntropySourceBehaviour`] says.
pub struct MockEntropySource {
    inner: SystemEntropySource,
    behaviour: MockEntropySourceBehaviour,
    fill_bytes_count: Cell<usize>,
    yielded: Cell<usize>,
    expected: OnceCell<Vec<usize>>,
    drawn: Cell<usize>,
}

impl MockEntropySource {
    /// Creates a new mock entropy source with the specified behavior.
    pub fn new(behaviour: MockEntropySourceBehaviour) -> Self {
        Self {
            inner: SystemEntropySource {},
            behaviour,
            fill_bytes_count: Cell::new(0),
            yielded: Cell::new(0),
            expected: OnceCell::new(),
            drawn: Cell::new(0),
        }
    }

    /// The next pieces the stream hands out, one per size and each backwards,
    /// and from then on every fill has to ask for exactly those sizes, in order.
    ///
    /// # Panics
    ///
    /// Without a stream, on a second ask, or where the stream is shorter than
    /// the sizes.
    pub fn upcoming_backwards(&self, sizes: &[usize]) -> Vec<Vec<u8>> {
        let MockEntropySourceBehaviour::YieldOver(stream) = self.behaviour else {
            panic!("only a mock yielding over a stream has needles to hand out");
        };

        assert!(
            self.expected.set(sizes.to_vec()).is_ok(),
            "the needles of this mock were asked for already"
        );

        let mut at = self.yielded.get();
        let mut needles = Vec::with_capacity(sizes.len());

        for &size in sizes {
            let piece = stream
                .get(at..)
                .and_then(|rest| rest.get(..size))
                .expect("the stream should hold every needle asked for");

            needles.push(backwards(piece));

            at += size;
        }

        needles
    }

    fn yield_over(&self, stream: &'static [u8], dest: &mut [u8]) -> Result<(), EntropyError> {
        if let Some(expected) = self.expected.get() {
            let drawn = self.drawn.get();

            // A panic and not an `Err`: a test expecting a refusal would take
            // the `Err` for it, with its needles computed for other draws.
            assert!(
                expected.get(drawn) == Some(&dest.len()),
                "draw {drawn} asked for {} bytes, and the needles were taken for {expected:?}",
                dest.len(),
            );

            self.drawn.set(drawn + 1);
        }

        let at = self.yielded.get();

        let Some(piece) = stream.get(at..).and_then(|rest| rest.get(..dest.len())) else {
            return Err(EntropyError::EntropyNotAvailable);
        };

        // SAFETY: `piece` was cut to `dest.len()`, and a static cannot overlap
        // a `&mut` borrow.
        unsafe { redoubt_mem::copy_nonoverlapping(piece.as_ptr(), dest.as_mut_ptr(), dest.len()) };

        self.yielded.set(at + dest.len());

        Ok(())
    }

    /// Changes the mock behavior at runtime.
    pub fn change_behaviour(&mut self, behaviour: MockEntropySourceBehaviour) {
        self.behaviour = behaviour;
    }

    /// Resets the call counter.
    pub fn reset_count(&self) {
        self.fill_bytes_count.set(0);
    }

    /// Returns the current call count.
    pub fn call_count(&self) -> usize {
        self.fill_bytes_count.get()
    }
}

impl EntropySource for MockEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let current = self.fill_bytes_count.get();
        self.fill_bytes_count.set(current + 1);

        match self.behaviour {
            MockEntropySourceBehaviour::None => self.inner.fill_bytes(dest),
            MockEntropySourceBehaviour::FailAlways => Err(EntropyError::EntropyNotAvailable),
            MockEntropySourceBehaviour::FailAtNthFillBytes(n) if current + 1 == n => {
                Err(EntropyError::EntropyNotAvailable)
            }
            MockEntropySourceBehaviour::FailAtNthFillBytes(_) => self.inner.fill_bytes(dest),
            MockEntropySourceBehaviour::YieldOver(stream) => self.yield_over(stream, dest),
        }
    }
}

impl Drop for MockEntropySource {
    fn drop(&mut self) {
        // A panic while unwinding aborts, and the abort hides what failed.
        if std::thread::panicking() {
            return;
        }

        if let Some(expected) = self.expected.get() {
            assert_eq!(
                self.drawn.get(),
                expected.len(),
                "the needles were taken for {expected:?}, and not every one of them was drawn"
            );
        }
    }
}

/// The needle, read from the last byte to the first, volatile and one at a
/// time: a reverse through a vector register would hold the bytes forwards.
fn backwards(of: &[u8]) -> Vec<u8> {
    let mut needle = alloc::vec![0_u8; of.len()];

    for at in 0..of.len() {
        // SAFETY: both in bounds of live slices of the same length.
        unsafe {
            needle
                .as_mut_ptr()
                .add(at)
                .write_volatile(of.as_ptr().add(of.len() - 1 - at).read_volatile());
        }
    }

    needle
}
