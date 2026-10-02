// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_forensics::{AnyError, Forensics, Watching, capture, forensics, is_found};

use crate::support::test_utils::{MockEntropySource, MockEntropySourceBehaviour};
use crate::traits::EntropySource;

const WIDE: usize = 32;

const STREAM: [u8; 2 * WIDE] = [
    0x8f, 0x3a, 0xd1, 0x56, 0xe4, 0x29, 0xb7, 0x0c, 0x73, 0xfa, 0x45, 0x9e, 0x12, 0xcb, 0x68, 0xa3,
    0x3e, 0xd5, 0x81, 0x1f, 0x6c, 0xb2, 0x07, 0xe9, 0x54, 0x9b, 0x2d, 0xf6, 0xa8, 0x13, 0xc4, 0x7d,
    0x26, 0x91, 0xec, 0x4b, 0xb8, 0x05, 0x5f, 0xd3, 0x8a, 0x37, 0xc1, 0x6e, 0x19, 0xa4, 0xf2, 0x50,
    0xdb, 0x62, 0x0e, 0x97, 0x3c, 0xe1, 0x75, 0xae, 0x48, 0xbd, 0x16, 0x8c, 0xf9, 0x21, 0x6a, 0xc7,
];

fn wipe(into: &mut [u8]) {
    // SAFETY: `into` is a live slice of `into.len()` bytes, borrowed exclusively.
    unsafe { redoubt_mem::zeroize(into.as_mut_ptr(), into.len()) };
}

// ============================================================================
// yield_over
// ============================================================================

#[redoubt_forensics::test]
fn test_what_a_fill_yielded_is_found_while_it_is_held() -> Result<(), AnyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let needles = mock.upcoming_backwards(&[WIDE]);

    let mut watch = Forensics::watching(&needles[0])?;

    forensics!({
        // Leaked and not a local: any call after the capture may write over a
        // slot of the stack, and then the sweep genuinely does not find what
        // the operation wrote there.
        let dest = Box::leak(Box::new([0_u8; WIDE]));

        let filled = capture(|| mock.fill_bytes(dest));

        filled?;
    });

    is_found(&watch.snapshot()?, "a piece yielded, and kept");

    Ok(())
}

#[redoubt_forensics::test]
fn test_a_fill_yielded_leaves_nothing() -> Result<(), AnyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let needles = mock.upcoming_backwards(&[WIDE]);

    let mut watching = Watching::start(&[("piece", &needles[0])])?;

    forensics!({
        let mut dest = [0_u8; WIDE];

        let filled = capture(|| mock.fill_bytes(&mut dest));

        filled?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut dest);
    });

    watching.none_left("a fill yielded")?;

    Ok(())
}

#[redoubt_forensics::test]
fn test_a_second_fill_yielded_leaves_nothing_of_either() -> Result<(), AnyError> {
    let mock = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&STREAM));
    let needles = mock.upcoming_backwards(&[WIDE, WIDE]);

    let mut watching = Watching::start(&[
        ("first piece", &needles[0]),
        ("second piece", &needles[1]),
    ])?;

    forensics!({
        let mut first = [0_u8; WIDE];
        let mut second = [0_u8; WIDE];

        mock.fill_bytes(&mut first)?;

        let filled = capture(|| mock.fill_bytes(&mut second));

        filled?;

        // CORRECTNESS: after the capture. A call made before it writes over
        // the stack and the registers the operation left, and then the absence
        // below is about that call and not about the operation.
        wipe(&mut first);
        wipe(&mut second);
    });

    watching.none_left("a second fill yielded")?;

    Ok(())
}
