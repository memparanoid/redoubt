// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What reading out of a decode buffer leaves behind.

use redoubt_forensics::{AnyError, Forensics, capture, forensics};
use redoubt_zero::FastZeroizable;

use crate::traits::DecodeBuffer;

use crate::tests::forensics::support::needles::backwards;
use crate::tests::forensics::support::{giving, is_found, leaves_nothing};

fn source(of: usize) -> Vec<u8> {
    let mut source = vec![0_u8; of];

    giving(&mut source);

    source
}

// ============================================================================
// <&mut [u8]>::read
// ============================================================================

#[test]
fn test_what_reading_a_value_wrote_is_found_while_the_value_holds_it() -> Result<(), AnyError> {
    let mut source = source(4096);
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut destination = Box::new([0_u8; 32]);

        capture(|| source.as_mut_slice().read(&mut *destination))?;

        // Emptied, so what is found can only be what was read.
        source.fast_zeroize();

        core::mem::forget(destination);
    });

    is_found(&watch.snapshot()?, "a value read, and kept");

    Ok(())
}

#[test]
fn test_reading_a_value_leaves_nothing() -> Result<(), AnyError> {
    let mut watch = Forensics::watching(&backwards())?;

    let report_before = watch.snapshot()?;

    let mut source = source(4096);

    forensics!({
        let mut destination = Box::new([0_u8; 32]);

        capture(|| source.as_mut_slice().read(&mut *destination))?;

        // CORRECTNESS: after the capture. A call made before it writes over the
        // stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        //
        // The source is emptied here because the read takes thirty-two of its
        // bytes and the rest are still the test's.
        destination.fast_zeroize();
        source.fast_zeroize();
    });

    leaves_nothing(
        &report_before,
        "nothing held yet",
        &watch.snapshot()?,
        "a value read",
    );

    Ok(())
}

// ============================================================================
// <&mut [u8]>::read_slice
// ============================================================================

#[test]
fn test_what_reading_a_slice_wrote_is_found_while_the_slice_holds_it() -> Result<(), AnyError> {
    let mut source = source(4096);
    let mut watch = Forensics::watching(&backwards())?;

    forensics!({
        let mut destination = vec![0_u8; 4096];

        capture(|| source.as_mut_slice().read_slice(&mut destination))?;

        source.fast_zeroize();

        core::mem::forget(destination);
    });

    is_found(&watch.snapshot()?, "a slice read, and kept");

    Ok(())
}

macro_rules! read_slice_of {
    ($name:ident, $of:expr) => {
        #[test]
        fn $name() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards())?;

            let report_before = watch.snapshot()?;

            let mut source = source($of);

            forensics!({
                let mut destination = vec![0_u8; $of];

                capture(|| source.as_mut_slice().read_slice(&mut destination))?;

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and then
                // the absence below is about that call and not about the
                // operation.
                destination.fast_zeroize();

                // Forgotten and not emptied: the read takes all of it, and
                // emptying it is the operation's.
                core::mem::forget(source);
            });

            leaves_nothing(
                &report_before,
                "nothing held yet",
                &watch.snapshot()?,
                &format!("a slice of {} bytes read", $of),
            );

            Ok(())
        }
    };
}

read_slice_of!(test_reading_a_slice_of_32_bytes_leaves_nothing, 32);
read_slice_of!(test_reading_a_slice_of_1024_bytes_leaves_nothing, 1024);
read_slice_of!(test_reading_a_slice_of_4096_bytes_leaves_nothing, 4096);
read_slice_of!(test_reading_a_slice_of_16384_bytes_leaves_nothing, 16384);
read_slice_of!(test_reading_a_slice_of_32768_bytes_leaves_nothing, 32768);
