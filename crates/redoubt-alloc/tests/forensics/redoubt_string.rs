// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_alloc::RedoubtString;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::support::needles::SECRET;
use crate::support::{hold_on, is_found, leaves_nothing, let_go};

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The secret spelled in hex, over and over: a string holds text, so what the
/// sweep looks for in one is the spelling.
///
/// Pushed a character at a time into room reserved up front: `push_str` or
/// `write!` would grow the string and leave the spelling in every block it
/// outgrew.
fn spelled(of: usize) -> String {
    let mut all = String::with_capacity(of);

    // SAFETY: every byte pushed is an ASCII hex digit, so what is built stays
    // valid UTF-8.
    let bytes = unsafe { all.as_mut_vec() };

    for at in 0..of {
        let byte = SECRET[(at / 2) % SECRET.len()];

        bytes.push(if at % 2 == 0 {
            HEX[(byte >> 4) as usize]
        } else {
            HEX[(byte & 0xF) as usize]
        });
    }

    all
}

/// One copy of the spelling, from its last character to its first and never
/// turned around: the forward spelling must not exist in this process.
fn spelled_backwards() -> Vec<u8> {
    let mut backwards = Vec::with_capacity(SECRET.len() * 2);

    for byte in SECRET.iter().rev() {
        backwards.push(HEX[(byte & 0xF) as usize]);
        backwards.push(HEX[(byte >> 4) as usize]);
    }

    backwards
}

/// Zeroes a string by hand, a byte at a time and volatile, for text a method
/// borrows and never empties: a `String` does not clear itself on drop, and the
/// freed block would still hold the spelling.
fn emptying(text: &mut str) {
    // SAFETY: every byte written is zero, which is valid UTF-8, and the length
    // is the string's own.
    let bytes = unsafe { text.as_bytes_mut() };

    for at in 0..bytes.len() {
        // SAFETY: in bounds of a live string.
        unsafe { bytes.as_mut_ptr().add(at).write_volatile(0) };
    }
}

// ============================================================================
// RedoubtString::drop
// ============================================================================

macro_rules! a_redoubt_string_dropped {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                held.replace_from_mut_string(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| drop(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string of {} bytes dropped", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_dropped!(test_a_redoubt_string_of_32_dropped_leaves_nothing, 32);
a_redoubt_string_dropped!(test_a_redoubt_string_of_64_dropped_leaves_nothing, 64);
a_redoubt_string_dropped!(test_a_redoubt_string_of_128_dropped_leaves_nothing, 128);
a_redoubt_string_dropped!(test_a_redoubt_string_of_512_dropped_leaves_nothing, 512);
a_redoubt_string_dropped!(test_a_redoubt_string_of_1024_dropped_leaves_nothing, 1024);
a_redoubt_string_dropped!(test_a_redoubt_string_of_4096_dropped_leaves_nothing, 4096);
a_redoubt_string_dropped!(test_a_redoubt_string_of_8192_dropped_leaves_nothing, 8192);
a_redoubt_string_dropped!(test_a_redoubt_string_of_16384_dropped_leaves_nothing, 16384);
a_redoubt_string_dropped!(test_a_redoubt_string_of_32768_dropped_leaves_nothing, 32768);
a_redoubt_string_dropped!(test_a_redoubt_string_of_65536_dropped_leaves_nothing, 65536);

// ============================================================================
// RedoubtString: ownership
// ============================================================================

#[test]
fn test_a_redoubt_string_given_away_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        held.replace_from_mut_string(&mut source);

        // CORRECTNESS: inside the capture, because this is the operation. What
        // the section measures is whether it leaves a copy in the registers or
        // the stack it used itself. What it writes over is whatever ran before
        // it, which has a section of its own.
        capture(|| hold_on(held));
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string given away, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_string_given_away {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                held.replace_from_mut_string(&mut source);

                // CORRECTNESS: inside the capture, because this is the
                // operation. What the section measures is whether it leaves a
                // copy in the registers or the stack it used itself. What it
                // writes over is whatever ran before it, which has a section
                // of its own.
                capture(|| let_go(held));
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string of {} bytes given away", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_given_away!(test_a_redoubt_string_of_32_given_away_leaves_nothing, 32);
a_redoubt_string_given_away!(test_a_redoubt_string_of_64_given_away_leaves_nothing, 64);
a_redoubt_string_given_away!(test_a_redoubt_string_of_128_given_away_leaves_nothing, 128);
a_redoubt_string_given_away!(test_a_redoubt_string_of_512_given_away_leaves_nothing, 512);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_1024_given_away_leaves_nothing,
    1024
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_4096_given_away_leaves_nothing,
    4096
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_8192_given_away_leaves_nothing,
    8192
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_16384_given_away_leaves_nothing,
    16384
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_32768_given_away_leaves_nothing,
    32768
);
a_redoubt_string_given_away!(
    test_a_redoubt_string_of_65536_given_away_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString: Debug
// ============================================================================

#[test]
#[ignore = "Reads no secret: it prints the length and the capacity, and \
            redacts the contents."]
fn test_formatting_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::new
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::with_capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_making_a_redoubt_string_with_capacity_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::from_mut_string
// ============================================================================

#[test]
fn test_a_redoubt_string_from_a_mut_string_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let held = capture(|| RedoubtString::from_mut_string(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string made from a string, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_string_from_a_mut_string {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let held = capture(|| RedoubtString::from_mut_string(&mut source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string made from a string of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_32_leaves_nothing,
    32
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_64_leaves_nothing,
    64
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_128_leaves_nothing,
    128
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_512_leaves_nothing,
    512
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_1024_leaves_nothing,
    1024
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_4096_leaves_nothing,
    4096
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_8192_leaves_nothing,
    8192
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_from_a_mut_string!(
    test_a_redoubt_string_from_a_mut_string_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::from_str
// ============================================================================

#[test]
fn test_a_redoubt_string_from_a_str_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let held = capture(|| RedoubtString::from_str(&source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string made from a str, and kept");

    emptying(&mut source);

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_string_from_a_str {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let held = capture(|| RedoubtString::from_str(&source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            emptying(&mut source);

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string made from a str of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_from_a_str!(test_a_redoubt_string_from_a_str_of_32_leaves_nothing, 32);
a_redoubt_string_from_a_str!(test_a_redoubt_string_from_a_str_of_64_leaves_nothing, 64);
a_redoubt_string_from_a_str!(test_a_redoubt_string_from_a_str_of_128_leaves_nothing, 128);
a_redoubt_string_from_a_str!(test_a_redoubt_string_from_a_str_of_512_leaves_nothing, 512);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_1024_leaves_nothing,
    1024
);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_4096_leaves_nothing,
    4096
);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_8192_leaves_nothing,
    8192
);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_from_a_str!(
    test_a_redoubt_string_from_a_str_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::len
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_length_of_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::is_empty
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_whether_a_redoubt_string_is_empty_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::capacity
// ============================================================================

#[test]
#[ignore = "Reads no secret: it reads a length."]
fn test_the_capacity_of_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::grow_to
// ============================================================================

#[test]
#[ignore = "Covered transitively: private, and every section that grows the \
            string past its capacity runs it."]
fn test_a_redoubt_string_grown_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::maybe_grow_to
// ============================================================================

#[test]
#[ignore = "Covered transitively: private, and every section that adds to the \
            string runs it."]
fn test_a_redoubt_string_maybe_grown_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::extend_from_mut_string
// ============================================================================

#[test]
fn test_a_redoubt_string_extended_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.extend_from_mut_string(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string extended, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

/// Appended in pieces rather than replaced, so the container reallocates on the
/// way up, and what the sweep asks about is the blocks it outgrew.
macro_rules! a_redoubt_string_extended {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut sources: Vec<String> = (0..($of / (SECRET.len() * 2)).max(1))
                .map(|_| spelled(SECRET.len() * 2))
                .collect();

            forensics!({
                let mut held = RedoubtString::new();

                capture(|| {
                    for source in &mut sources {
                        held.extend_from_mut_string(source);
                    }
                });

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            drop(core::hint::black_box(sources));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string extended to {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_extended!(test_a_redoubt_string_extended_to_32_leaves_nothing, 32);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_64_leaves_nothing, 64);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_128_leaves_nothing, 128);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_512_leaves_nothing, 512);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_1024_leaves_nothing, 1024);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_4096_leaves_nothing, 4096);
a_redoubt_string_extended!(test_a_redoubt_string_extended_to_8192_leaves_nothing, 8192);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_16384_leaves_nothing,
    16384
);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_32768_leaves_nothing,
    32768
);
a_redoubt_string_extended!(
    test_a_redoubt_string_extended_to_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::replace_from_mut_string
// ============================================================================

#[test]
fn test_a_redoubt_string_replaced_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.replace_from_mut_string(&mut source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string replaced, and kept");

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_string_replaced {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                capture(|| held.replace_from_mut_string(&mut source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string replaced of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_32_leaves_nothing, 32);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_64_leaves_nothing, 64);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_128_leaves_nothing, 128);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_512_leaves_nothing, 512);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_1024_leaves_nothing, 1024);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_4096_leaves_nothing, 4096);
a_redoubt_string_replaced!(test_a_redoubt_string_replaced_of_8192_leaves_nothing, 8192);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_replaced!(
    test_a_redoubt_string_replaced_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::extend_from_str
// ============================================================================

#[test]
fn test_a_redoubt_string_extended_from_a_str_is_found_while_it_holds_it() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&spelled_backwards())?;

    let mut source = spelled(SECRET.len() * 2);

    forensics!({
        let mut held = RedoubtString::new();
        capture(|| held.extend_from_str(&source));

        core::mem::forget(held);
    });

    let report = watch.snapshot()?;

    is_found(&report, "a string extended from a str, and kept");

    emptying(&mut source);

    drop(core::hint::black_box(source));

    Ok(())
}

macro_rules! a_redoubt_string_extended_from_a_str {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                capture(|| held.extend_from_str(&source));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            emptying(&mut source);

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string extended from a str of {} bytes", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_32_leaves_nothing,
    32
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_64_leaves_nothing,
    64
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_128_leaves_nothing,
    128
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_512_leaves_nothing,
    512
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_1024_leaves_nothing,
    1024
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_4096_leaves_nothing,
    4096
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_8192_leaves_nothing,
    8192
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_16384_leaves_nothing,
    16384
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_32768_leaves_nothing,
    32768
);
a_redoubt_string_extended_from_a_str!(
    test_a_redoubt_string_extended_from_a_str_of_65536_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::clear
// ============================================================================

macro_rules! a_redoubt_string_cleared {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&spelled_backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = spelled($of);

            forensics!({
                let mut held = RedoubtString::new();
                held.replace_from_mut_string(&mut source);

                capture(|| held.clear());

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                drop(held);
            });

            drop(core::hint::black_box(source));

            let report_after = watch.snapshot()?;

            leaves_nothing(
                &report_before,
                &report_after,
                &format!("a string of {} bytes cleared", $of),
            );

            Ok(())
        }
    };
}

a_redoubt_string_cleared!(test_a_redoubt_string_of_32_cleared_leaves_nothing, 32);
a_redoubt_string_cleared!(test_a_redoubt_string_of_64_cleared_leaves_nothing, 64);
a_redoubt_string_cleared!(test_a_redoubt_string_of_128_cleared_leaves_nothing, 128);
a_redoubt_string_cleared!(test_a_redoubt_string_of_512_cleared_leaves_nothing, 512);
a_redoubt_string_cleared!(test_a_redoubt_string_of_1024_cleared_leaves_nothing, 1024);
a_redoubt_string_cleared!(test_a_redoubt_string_of_4096_cleared_leaves_nothing, 4096);
a_redoubt_string_cleared!(test_a_redoubt_string_of_8192_cleared_leaves_nothing, 8192);
a_redoubt_string_cleared!(
    test_a_redoubt_string_of_16384_cleared_leaves_nothing,
    16384
);
a_redoubt_string_cleared!(
    test_a_redoubt_string_of_32768_cleared_leaves_nothing,
    32768
);
a_redoubt_string_cleared!(
    test_a_redoubt_string_of_65536_cleared_leaves_nothing,
    65536
);

// ============================================================================
// RedoubtString::as_str
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_string_as_a_str_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::as_mut_str
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_string_as_a_mut_str_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::as_string
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_string_as_a_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString::as_mut_string
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_a_redoubt_string_as_a_mut_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString: Default
// ============================================================================

#[test]
#[ignore = "Reads no secret: it makes an empty container."]
fn test_a_default_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString: Deref
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_dereferencing_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// RedoubtString: DerefMut
// ============================================================================

#[test]
#[ignore = "Reads no secret: it hands back a reference and copies nothing."]
fn test_mutably_dereferencing_a_redoubt_string_leaves_nothing() {
    // Intentionally empty.
}
