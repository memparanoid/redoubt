// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;
use redoubt_forensics::{AnyError, Forensics, capture, forensics};

use crate::decode::{hex_to_bytes, hex_to_bytes_with_backend};
use crate::error::HexError;

use crate::tests::forensics::support::needles::{BYTES, DIGITS, OLD};
use crate::tests::forensics::support::{backwards, hold, is_found, leaves_nothing, wipe};

const NOT_A_DIGIT: u8 = b'g';

macro_rules! decoding {
    (
        $found:ident,
        $absent:ident,
        $over_a_secret:ident,
        $refused:ident,
        |$src:ident, $dst:ident| $call:expr
    ) => {
        #[redoubt_forensics::test]
        fn $found() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards(&BYTES))?;

            let mut $src = hold(&DIGITS);

            forensics!({
                // Leaked and not a local: any call after the capture may write
                // over what a buffer let go of, and then the sweep genuinely
                // does not find what the operation wrote there.
                let $dst = vec![0_u8; BYTES.len()].leak();

                capture(|| $call)?;

                // What it read, emptied: what is found is what it wrote.
                wipe(&mut $src);
            });

            is_found(&watch.snapshot()?, "bytes decoded, and kept");

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $absent() -> Result<(), AnyError> {
            let mut digits_watch = Forensics::watching(&backwards(&DIGITS))?;
            let mut bytes_watch = Forensics::watching(&backwards(&BYTES))?;

            let digits_before = digits_watch.snapshot()?;
            let bytes_before = bytes_watch.snapshot()?;

            let mut $src = hold(&DIGITS);

            forensics!({
                let mut written = vec![0_u8; BYTES.len()];
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
                &digits_before,
                "nothing held yet",
                &digits_watch.snapshot()?,
                "a decoding, of what it read",
            );
            leaves_nothing(
                &bytes_before,
                "nothing held yet",
                &bytes_watch.snapshot()?,
                "a decoding, of what it wrote",
            );

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $over_a_secret() -> Result<(), AnyError> {
            let mut digits_watch = Forensics::watching(&backwards(&DIGITS))?;
            let mut bytes_watch = Forensics::watching(&backwards(&BYTES))?;
            let mut old_watch = Forensics::watching(&backwards(&OLD[..BYTES.len()]))?;

            let digits_before = digits_watch.snapshot()?;
            let bytes_before = bytes_watch.snapshot()?;
            let old_before = old_watch.snapshot()?;

            let mut $src = hold(&DIGITS);
            let mut written = hold(&OLD[..BYTES.len()]);

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
                &digits_before,
                "nothing held yet",
                &digits_watch.snapshot()?,
                "a decoding over a secret, of what it read",
            );
            leaves_nothing(
                &bytes_before,
                "nothing held yet",
                &bytes_watch.snapshot()?,
                "a decoding over a secret, of what it wrote",
            );
            leaves_nothing(
                &old_before,
                "nothing held yet",
                &old_watch.snapshot()?,
                "a decoding over a secret, of what it wrote over",
            );

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $refused() -> Result<(), AnyError> {
            let mut digits_watch = Forensics::watching(&backwards(&DIGITS[..DIGITS.len() - 1]))?;
            let mut bytes_watch = Forensics::watching(&backwards(&BYTES[..BYTES.len() - 1]))?;

            let digits_before = digits_watch.snapshot()?;
            let bytes_before = bytes_watch.snapshot()?;

            let mut $src = hold(&DIGITS);

            $src[DIGITS.len() - 1] = NOT_A_DIGIT;

            forensics!({
                let mut written = vec![0_u8; BYTES.len()];
                let $dst = &mut written[..];

                let refused = capture(|| $call);

                assert_eq!(refused, Err(HexError::NotHex));

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                wipe(&mut $src);

                // The destination is not emptied here: that is the refusal's
                // to do, and emptying it here would keep this absence green
                // without it.
            });

            leaves_nothing(
                &digits_before,
                "nothing held yet",
                &digits_watch.snapshot()?,
                "a decoding refused at its last character, of what it read",
            );
            leaves_nothing(
                &bytes_before,
                "nothing held yet",
                &bytes_watch.snapshot()?,
                "a decoding refused at its last character, of what it decoded",
            );

            Ok(())
        }
    };
}

// ============================================================================
// hex_to_bytes
// ============================================================================

decoding!(
    test_what_a_decoding_wrote_is_found_while_the_bytes_hold_it,
    test_decoding_leaves_nothing,
    test_decoding_over_a_secret_leaves_nothing,
    test_decoding_a_character_that_is_not_a_digit_leaves_nothing,
    |src, dst| hex_to_bytes(&src, dst)
);

#[test]
#[ignore = "Reads no secret: the length is refused before a character is read."]
fn test_decoding_an_odd_length_leaves_nothing() {
    // Intentionally empty.
}

#[test]
#[ignore = "Reads no secret: the lengths are refused before a character is read."]
fn test_decoding_into_the_wrong_destination_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// hex_to_bytes_with_backend
// ============================================================================

decoding!(
    test_what_a_decoding_through_a_backend_wrote_is_found_while_the_bytes_hold_it,
    test_decoding_through_a_backend_leaves_nothing,
    test_decoding_through_a_backend_over_a_secret_leaves_nothing,
    test_decoding_through_a_backend_a_character_that_is_not_a_digit_leaves_nothing,
    |src, dst| hex_to_bytes_with_backend(Backend::default(), &src, dst)
);

#[test]
#[ignore = "Reads no secret: the length is refused before a character is read."]
fn test_decoding_an_odd_length_through_a_backend_leaves_nothing() {
    // Intentionally empty.
}

#[test]
#[ignore = "Reads no secret: the lengths are refused before a character is read."]
fn test_decoding_through_a_backend_into_the_wrong_destination_leaves_nothing() {
    // Intentionally empty.
}
