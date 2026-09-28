// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::encode::{bytes_to_hex, bytes_to_hex_with_backend};

use crate::tests::forensics::support::needles::{BYTES, DIGITS, OLD};
use crate::tests::forensics::support::{backwards, hold, is_found, leaves_nothing, wipe};

macro_rules! encoding {
    (
        $found:ident,
        $absent:ident,
        $over_a_secret:ident,
        |$src:ident, $dst:ident| $call:expr
    ) => {
        #[redoubt_forensics::test]
        fn $found() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards(&DIGITS))?;

            let mut $src = hold(&BYTES);

            forensics!({
                // Leaked and not a local: any call after the capture may write
                // over what a buffer let go of, and then the sweep genuinely
                // does not find what the operation wrote there.
                let $dst = vec![0_u8; DIGITS.len()].leak();

                capture(|| $call)?;

                // What it read, emptied: what is found is what it wrote.
                wipe(&mut $src);
            });

            is_found(&watch.snapshot()?, "digits encoded, and kept");

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $absent() -> Result<(), AnyError> {
            let mut bytes_watch = Forensics::watching(&backwards(&BYTES))?;
            let mut digits_watch = Forensics::watching(&backwards(&DIGITS))?;

            let bytes_before = bytes_watch.snapshot()?;
            let digits_before = digits_watch.snapshot()?;

            let mut $src = hold(&BYTES);

            forensics!({
                let mut written = vec![0_u8; DIGITS.len()];
                let $dst = &mut written[..];

                capture(|| $call)?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                wipe($dst);
                wipe(&mut $src);
            });

            leaves_nothing(
                &bytes_before,
                "nothing held yet",
                &bytes_watch.snapshot()?,
                "an encoding, of what it read",
            );
            leaves_nothing(
                &digits_before,
                "nothing held yet",
                &digits_watch.snapshot()?,
                "an encoding, of what it wrote",
            );

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $over_a_secret() -> Result<(), AnyError> {
            let mut bytes_watch = Forensics::watching(&backwards(&BYTES))?;
            let mut digits_watch = Forensics::watching(&backwards(&DIGITS))?;
            let mut old_watch = Forensics::watching(&backwards(&OLD))?;

            let bytes_before = bytes_watch.snapshot()?;
            let digits_before = digits_watch.snapshot()?;
            let old_before = old_watch.snapshot()?;

            let mut $src = hold(&BYTES);
            let mut written = hold(&OLD);

            forensics!({
                let $dst = &mut written[..];

                capture(|| $call)?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                wipe($dst);
                wipe(&mut $src);
            });

            leaves_nothing(
                &bytes_before,
                "nothing held yet",
                &bytes_watch.snapshot()?,
                "an encoding over a secret, of what it read",
            );
            leaves_nothing(
                &digits_before,
                "nothing held yet",
                &digits_watch.snapshot()?,
                "an encoding over a secret, of what it wrote",
            );
            leaves_nothing(
                &old_before,
                "nothing held yet",
                &old_watch.snapshot()?,
                "an encoding over a secret, of what it wrote over",
            );

            Ok(())
        }
    };
}

// ============================================================================
// bytes_to_hex
// ============================================================================

encoding!(
    test_what_an_encoding_wrote_is_found_while_the_digits_hold_it,
    test_encoding_leaves_nothing,
    test_encoding_over_a_secret_leaves_nothing,
    |src, dst| bytes_to_hex(&src, dst)
);

#[test]
#[ignore = "Reads no secret: the lengths are refused before a byte is read."]
fn test_encoding_into_the_wrong_destination_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// bytes_to_hex_with_backend
// ============================================================================

encoding!(
    test_what_an_encoding_through_a_backend_wrote_is_found_while_the_digits_hold_it,
    test_encoding_through_a_backend_leaves_nothing,
    test_encoding_through_a_backend_over_a_secret_leaves_nothing,
    |src, dst| bytes_to_hex_with_backend(Backend::default(), &src, dst)
);

#[test]
#[ignore = "Reads no secret: the lengths are refused before a byte is read."]
fn test_encoding_through_a_backend_into_the_wrong_destination_leaves_nothing() {
    // Intentionally empty.
}
