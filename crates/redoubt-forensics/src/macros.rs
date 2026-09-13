// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Running an operation far enough down that nothing can reach what it leaves.
//!
//! # The other side of the same problem
//!
//! Whatever runs between an operation ending and the memory freezing is written
//! onto the stack the operation just used, over the frames that are the whole
//! reason to look. [`crate::Forensics`] answers that by writing nothing there —
//! the block is reserved ahead of time and the analysis runs on a stack of its
//! own, measured at zero bytes below the caller.
//!
//! This answers it from the other end, and the two do not overlap. The
//! operation runs under a megabyte of frame, so its leavings are a megabyte
//! down, and it stops mattering how much anything writes: a sweep that took a
//! kilobyte of somebody's stack would still be nowhere near.
//!
//! Which is worth having for two reasons. [`crate::occurrences_reversed`] does
//! not run on its own stack — a caller of that gets its footprint whatever it
//! is, and this covers them. And a measurement that holds for two unrelated
//! reasons is worth more than one that holds for one.
//!
//! # And the order
//!
//! The other thing a caller can do wrong is put something between the operation
//! and the photograph. A `?`, a `format!`, an `unwrap` that does not inline —
//! each is a call, and a call writes exactly where the evidence is. The macro
//! takes both at once: the block goes down, and the photograph is the next
//! thing that happens, with nothing in between for anybody to add to later.

/// How far down an operation is run.
///
/// A megabyte, which is nothing on a stack of eight and more than anything
/// reading memory has ever needed.
pub const DEPTH: usize = 1 << 20;

/// Run something a megabyte down the stack.
///
/// The padding is touched, not merely declared: an array nobody reads is an
/// array the compiler is free never to make, and the point of this one is to
/// exist between the caller's frame and everything below it.
#[inline(never)]
pub fn deep<R>(work: impl FnOnce() -> R) -> R {
    let mut pad = [0_u8; DEPTH];

    core::hint::black_box(&mut pad);

    let out = work();

    core::hint::black_box(&mut pad);

    out
}

/// An operation and the photograph of what it left, with nothing in between.
///
/// ```no_run
/// # use redoubt_forensics::{Forensics, forensics};
/// # let needle: Vec<u8> = Vec::new();
/// # fn operation() {}
/// let mut watch = Forensics::watching(&needle).expect("no fork");
///
/// let before = watch.snapshot().expect("no photograph");
/// let after = forensics!(watch, { operation() });
///
/// println!("{}", after.expect("no photograph").against(&before));
/// ```
///
/// The block runs under [`DEPTH`] bytes of frame and the photograph is taken
/// the instant it returns. Nothing a caller writes can get between the two,
/// which is the one thing left that a caller could get wrong.
///
/// # And the registers
///
/// Between the block returning and the photograph the macro takes a register
/// capture, so that what was left in the register file is in memory and the
/// same sweep finds it. It costs one `call` with no argument and no branch
/// — see [`crate::spill`] for why that matters and
/// [`crate::Forensics::watching`] for where it was arranged.
///
/// What that capture is worth depends on which half of the register file the
/// question is about. Returning from a closure, out of [`deep`], and into the
/// capture is a handful of instructions, and any of them can land in a
/// caller-saved register — so a secret that was passing through one is already
/// gone, and it was going to be gone anyway. `zmm16-31` are the other half:
/// nothing in ordinary compiled code writes them, so whatever a wide `memcpy`
/// left there is still there, and this is what puts it somewhere a photograph
/// can reach.
#[macro_export]
macro_rules! forensics {
    ($watch:expr, $work:block) => {{
        $crate::deep(|| $work);

        $crate::spill();

        $watch.snapshot()
    }};
}
