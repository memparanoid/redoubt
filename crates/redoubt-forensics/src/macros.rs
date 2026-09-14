// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Running an operation far enough down that nothing can reach what it leaves.
//!
//! # The other side of the same problem
//!
//! Whatever runs between an operation ending and the memory freezing is written
//! onto the stack the operation just used, over the frames that are the whole
//! reason to look. [`crate::Forensics`] answers that by writing almost nothing
//! there — the block is reserved ahead of time and the analysis runs on a stack
//! of its own, reached through a single frame that holds the errand and saved
//! registers and no part of anybody's secret.
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
//!
//! Which is also why a block's own failure is settled by [`Outcome`] on the far
//! side of the capture rather than by a `?` where it was written.

use crate::analysis::report::Report;
use crate::errors::Reason;

/// What a measured block came to, settled against the photograph.
///
/// A block that cannot fail comes to `()` and its error is [`Reason`]; one that
/// can comes to a `Result` and brings its own.
///
/// The error is associated and not a parameter, so that nothing is left to
/// infer: a parameter here has to be solved through the `From` at the call
/// site, and for a boxed `dyn Error` there are five that would serve.
pub trait Outcome {
    /// What this block can have failed with.
    type Error;

    /// The photograph, unless something on the way to it went wrong.
    fn settle(self, after: Result<Report, Reason>) -> Result<Report, Self::Error>;
}

/// A block with nothing to answer for, so only the photograph can have failed
/// and the error is the photograph's.
impl Outcome for () {
    type Error = Reason;

    fn settle(self, after: Result<Report, Reason>) -> Result<Report, Reason> {
        after
    }
}

/// The operation is asked first and the photograph second, which is the order
/// they happened in — and the photograph is taken either way, before either is
/// read. A block that failed is photographed and the photograph thrown away,
/// because a measurement of an operation that did not finish measures nothing.
impl<T, E: From<Reason>> Outcome for Result<T, E> {
    type Error = E;

    fn settle(self, after: Result<Report, Reason>) -> Result<Report, E> {
        self?;

        after.map_err(E::from)
    }
}

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
/// What comes back is the photograph itself and not a `Result`, so there is no
/// `?` after the closing brace:
///
/// ```no_run
/// # use redoubt_forensics::{Forensics, Reason, forensics};
/// # fn operation() {}
/// # fn measured() -> Result<(), Reason> {
/// # let needle: Vec<u8> = Vec::new();
/// let mut watch = Forensics::watching(&needle)?;
///
/// let report_before = watch.snapshot()?;
/// let report_after = forensics!(watch, { operation() });
///
/// println!("{}", report_after.against(&report_before));
/// # Ok(())
/// # }
/// ```
///
/// # The `return` inside it
///
/// A photograph that could not be taken leaves the enclosing function, and this
/// does that itself: it expands to a `match` whose failing arm is a `return`.
/// So it can only be written inside a function that returns a `Result`, and
/// that function's error must be reachable by `From` from whatever went wrong.
///
/// A `return` hidden in a macro is the sort of thing that reads wrong six
/// months later, so here is what it is for.
///
/// A block that can fail ends in a `Result` and uses `?` inside. If this handed
/// a `Result` back as well, the caller would write a second `?` after the
/// brace — and then there are two conversions in a row with a type between them
/// that nothing has named. `rustc` solves the outer one first, finds more than
/// one `From` that would serve, and stops: `E0283`, at every call site,
/// answered only by a turbofish in every block. The ambiguity is in the chain
/// and not in the error type, so no choice of error type avoids it.
///
/// Taking the `return` in here removes the outer conversion. What is left is
/// one conversion into a type the enclosing signature has already named.
///
/// # An operation that can fail
///
/// The block ends in a `Result` whose error the enclosing function can reach by
/// `From` — including from [`Reason`], which is what the photograph fails with.
/// [`crate::AnyError`] is that type. A block that cannot fail stays an
/// expression, as above, and the function returns [`Reason`].
///
/// The block runs under [`DEPTH`] bytes of frame and the photograph is taken
/// the instant it returns. Nothing a caller writes can get between the two,
/// which is the one thing left that a caller could get wrong.
///
/// Nor can the `?` inside the block: its failure is carried past the capture
/// untouched and settled by [`Outcome`] only once the photograph has been
/// taken. A `?` is a call, and a call between the operation and the photograph
/// writes over the frames the photograph is for.
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
        let out = $crate::deep(|| $work);

        $crate::spill();

        let after = $watch.snapshot();

        match $crate::Outcome::settle(out, after) {
            Ok(report) => report,
            // The `return` is the point, and it is explained above the macro.
            Err(why) => return Err(::core::convert::From::from(why)),
        }
    }};
}

/// [`forensics!`] with the register capture taken out, and nothing else.
///
/// The other half of a pair. What the capture is worth is the difference
/// between the two answers, and a difference is only readable when one line
/// separates them: a control written by hand out of `deep`, `snapshot` and a
/// `settle` would differ in three places, and a disagreement could be any of
/// them.
///
/// Here rather than in the tests because the day `forensics!` changes, these
/// two have to be read together. A copy living in a test file goes stale
/// without saying so, and the pair would go on reporting a difference that is
/// no longer about the capture.
#[cfg(test)]
macro_rules! without_the_capture {
    ($watch:expr, $work:block) => {{
        let out = $crate::deep(|| $work);

        let after = $watch.snapshot();

        match $crate::Outcome::settle(out, after) {
            Ok(report) => report,
            Err(why) => return Err(::core::convert::From::from(why)),
        }
    }};
}

#[cfg(test)]
pub(crate) use without_the_capture;
