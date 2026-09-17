// // Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// // SPDX-License-Identifier: GPL-3.0-only
// // See LICENSE in the repository root for full license text.

// //! What a measurement has to be shaped like for its answer to be about the
// //! operation.
// //!
// //! # The trap
// //!
// //! [`deep`] runs the work a megabyte down the stack so that reading the
// //! photograph afterwards does not write over what the work left. What it
// //! cannot do is protect the work from itself. A call made after the operation
// //! — a buffer dropped, an allocation freed, a value emptied — pushes a frame
// //! onto the stack the operation has just released, and a secret of a few dozen
// //! bytes goes under it whole.
// //!
// //! The photograph then reports a clean process, and it reports it just as
// //! cleanly for an operation that wiped nothing. That is the failure this file
// //! exists for: it was found in a crate above, where a test went on passing
// //! against a zeroization that had been commented out.
// //!
// //! # The shape that works
// //!
// //! ```text
// //! deep(|| {
// //!     operation();    // the only thing that touches the secret
// //!     spill();        // the registers, before returning loses them
// //! });
// //!
// //! cleanup();          // a megabyte above the evidence
// //!
// //! let report_after = watch.snapshot()?;
// //! ```
// //!
// //! [`spill`] is the one thing that may follow the operation inside the block,
// //! and it is not an exception to the rule: it is hand-written assembly that
// //! stores registers into a room of its own, takes no frame and calls nothing,
// //! so there is nothing of it to land on what the operation left.
// //!
// //! It has to be there rather than after, because returning from `deep` is what
// //! costs the registers: the return value, the argument register and every
// //! callee-saved one are written on the way out. Inside, every register the
// //! operation left is still the operation's.
// //!
// //! # A process each
// //!
// //! The memory swept is the whole process's, so a test sharing it is another
// //! place the secret could be. `nextest`, not `cargo test`.

// #![cfg(target_os = "linux")]

// use redoubt_forensics::{AnyError, Forensics, deep, spill};

// /// Thirty-two distinct bytes: no value repeats, so a run that extends did not
// /// extend by luck.
// ///
// /// A `const`, so it lives where nothing can write and the sweep never reads it
// /// as a copy.
// const SECRET: [u8; 32] = [
//     0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
//     0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
// ];

// /// How much a cleanup allocates, so that freeing it is a real call and not
// /// something the compiler folds away.
// const WASTE: usize = 1024;

// /// The needle, built from its last byte to its first.
// ///
// /// Never turned around in this process: the forward bytes must not exist here
// /// even for as long as it would take to reverse them.
// fn backwards() -> Vec<u8> {
//     SECRET.iter().rev().copied().collect()
// }

// /// The secret into somewhere the caller owns, one byte at a time through a
// /// pointer.
// ///
// /// Not an assignment: `held = SECRET` is whatever move the compiler decides to
// /// emit, and on AArch64 it emitted one that left a copy the wipe below could
// /// not reach — which turned a test of the wipe into a test of the copy.
// /// Through a pointer there is one copy, and it is at the address the wipe is
// /// given.
// fn giving(into: &mut [u8; SECRET.len()]) {
//     for (at, byte) in SECRET.iter().enumerate() {
//         // SAFETY: `at` indexes a destination of exactly the secret's width.
//         unsafe { into.as_mut_ptr().add(at).write_volatile(*byte) };
//     }
// }

// /// The secret out of it again, the same way.
// fn taking(from: &mut [u8; SECRET.len()]) {
//     for at in 0..from.len() {
//         // SAFETY: as above.
//         unsafe { from.as_mut_ptr().add(at).write_volatile(0) };
//     }
// }

// /// An operation that leaves the secret in the frame it used.
// ///
// /// What every measurement in this file is of. Not inlined, so the frame is one
// /// the machine makes and leaves; folded into its caller there would be no
// /// frame to leave and nothing to find.
// #[inline(never)]
// fn a_frame_left_full() {
//     let mut held = [0_u8; SECRET.len()];

//     giving(&mut held);

//     core::hint::black_box(&held);
// }

// /// The same operation, emptying the frame before it leaves it.
// #[inline(never)]
// fn a_frame_emptied() {
//     let mut held = [0_u8; SECRET.len()];

//     giving(&mut held);

//     core::hint::black_box(&held);

//     taking(&mut held);

//     core::hint::black_box(&held);
// }

// // ============================================================================
// // The instrument reaches
// // ============================================================================

// /// The sweep finds a secret in a frame that has already been left.
// ///
// /// Everything below is an absence, and an absence is worth exactly this: the
// /// photograph would have spoken had there been something in that frame.
// #[test]
// fn test_the_sweep_finds_a_frame_that_was_left_full() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;

//     deep(|| {
//         a_frame_left_full();
//         spill();
//     });

//     let report = watch.snapshot()?;

//     println!();
//     report.summary("a frame left full");
//     println!();

//     assert!(
//         report.found,
//         "the sweep does not reach a frame that was left, so every absence in \
//          this file is the instrument standing where the evidence is: {report}"
//     );

//     Ok(())
// }

// /// A frame emptied before it is left holds nothing.
// ///
// /// The pair with the one above: the same call site and the same shape, and the
// /// only difference is whether the operation wiped.
// #[test]
// fn test_a_frame_emptied_before_it_is_left_holds_nothing() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;

//     deep(|| {
//         a_frame_emptied();
//         spill();
//     });

//     let report = watch.snapshot()?;

//     println!();
//     report.summary("a frame emptied");
//     println!();

//     // Assert zeroization!
//     assert!(!report.found, "the wipe left the secret behind: {report}");

//     Ok(())
// }

// // ============================================================================
// // The pair every measurement is read as
// // ============================================================================

// /// Two photographs and the difference between them say the secret surfaced.
// ///
// /// Every file above this crate reads its answer this way rather than from one
// /// report: a score on its own is a number about a process that was already
// /// running, and what is being asked is what one operation added to it. So the
// /// difference has to be able to speak, and this is what says it can.
// #[test]
// fn test_the_difference_says_the_secret_surfaced() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;

//     let report_before = watch.snapshot()?;

//     println!();
//     report_before.summary("nothing run yet");

//     deep(|| {
//         a_frame_left_full();
//         spill();
//     });

//     let report_after = watch.snapshot()?;

//     report_after.summary_against(&report_before, "a frame left full");
//     println!();

//     assert!(
//         report_after.found,
//         "the whole secret did not surface: {report_after}"
//     );

//     let delta = report_after.against(&report_before);

//     assert!(
//         !delta.is_noise(),
//         "the difference calls a whole secret surfacing noise, so every file \
//          that reads a measurement this way is reading nothing: {delta}"
//     );

//     Ok(())
// }

// /// The same pair, when the operation emptied what it used.
// ///
// /// The other half: a difference that were never noise would call every clean
// /// measurement dirty, and one that is always noise would call every dirty one
// /// clean. This is the side that says it can be quiet.
// #[test]
// fn test_the_difference_is_quiet_when_the_frame_was_emptied() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;

//     let report_before = watch.snapshot()?;

//     println!();
//     report_before.summary("nothing run yet");

//     deep(|| {
//         a_frame_emptied();
//         spill();
//     });

//     let report_after = watch.snapshot()?;

//     report_after.summary_against(&report_before, "a frame emptied");
//     println!();

//     // Assert zeroization!
//     assert!(
//         !report_after.found,
//         "the wipe left the secret behind: {report_after}"
//     );

//     let delta = report_after.against(&report_before);

//     assert!(delta.is_noise(), "an emptied frame moved the score: {delta}");

//     Ok(())
// }

// // ============================================================================
// // Where the cleanup runs
// // ============================================================================

// /// A cleanup run where it lies erases the evidence.
// ///
// /// This is the trap, pinned. The operation left the secret in its frame — the
// /// control above says the sweep would find it — and one `drop` afterwards is
// /// enough for the photograph to report a clean process.
// ///
// /// Nothing about the operation changed between this and the control. What
// /// changed is that a call ran on the stack the operation had just released.
// #[test]
// fn test_a_cleanup_run_where_it_lies_erases_the_evidence() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;
//     let waste = vec![0_u8; WASTE];

//     deep(|| {
//         a_frame_left_full();

//         drop(core::hint::black_box(waste));

//         spill();
//     });

//     let report = watch.snapshot()?;

//     println!();
//     report.summary("a cleanup where it lies");
//     println!();

//     assert!(
//         !report.found,
//         "a call after the operation no longer erases what it left, so the \
//          hazard this file is about has changed shape and every measurement \
//          written against it has to be read again: {report}"
//     );

//     Ok(())
// }

// /// The same cleanup, run after `deep` has returned, leaves the evidence.
// ///
// /// The fix, and it is a position rather than a mechanism. `deep` reserves a
// /// megabyte and the operation runs below it; when `deep` returns that megabyte
// /// is released, and a call made from here has all of it to spend before it
// /// reaches the frame the operation left.
// ///
// /// So the cleanup still runs before the photograph, as it must. What changed
// /// is that it runs a megabyte above the evidence instead of on top of it.
// #[test]
// fn test_a_cleanup_run_after_deep_leaves_the_evidence() -> Result<(), AnyError> {
//     let mut watch = Forensics::watching(&backwards())?;
//     let waste = vec![0_u8; WASTE];

//     deep(|| {
//         a_frame_left_full();
//         spill();
//     });

//     drop(core::hint::black_box(waste));

//     let report = watch.snapshot()?;

//     println!();
//     report.summary("a cleanup after deep");
//     println!();

//     assert!(
//         report.found,
//         "the cleanup erased the evidence even from a megabyte above it: {report}"
//     );

//     Ok(())
// }
