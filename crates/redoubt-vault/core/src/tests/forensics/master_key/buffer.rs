// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What making the master key leaves behind.

use redoubt_forensics::{AnyError, Forensics, Watching, capture, forensics, is_found};
use redoubt_rand::test_utils::{MockEntropySource, MockEntropySourceBehaviour};

use crate::master_key::buffer::{create_buffer, initialize_buffer_with};
use crate::master_key::consts::MASTER_KEY_LEN;

use crate::tests::forensics::support::copying_into;

const KEY: [u8; MASTER_KEY_LEN] = [
    0xa3, 0x5d, 0x12, 0xe8, 0x7f, 0x34, 0xc9, 0x06, 0xbb, 0x60, 0x2e, 0xd5, 0x89, 0x47, 0xf1, 0x1a,
    0x6c, 0x93, 0x28, 0xde, 0x55, 0x0b, 0xa7, 0x3f, 0xe4, 0x71, 0x9c, 0x16, 0xcd, 0x82, 0x3b, 0xf8,
];

// ============================================================================
// create_buffer
// ============================================================================

#[test]
#[ignore = "Reads no secret: it maps an empty page."]
fn test_making_a_buffer_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// create_initialized_buffer
// ============================================================================

#[test]
#[ignore = "Audited: it draws from the system and hands the source to \
            `initialize_buffer_with`, which is measured."]
fn test_making_the_key_leaves_nothing() {
    // Intentionally empty.
}

// ============================================================================
// initialize_buffer_with
// ============================================================================

/// The page the key is made in is guarded, and a guarded page is never swept.
#[redoubt_forensics::test]
fn test_the_key_made_is_found_once_copied_out_of_its_page() -> Result<(), AnyError> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&KEY));
    let needles = entropy.upcoming_backwards(&[MASTER_KEY_LEN]);

    let mut watch = Forensics::watching(&needles[0])?;

    let mut buffer = create_buffer()?;

    forensics!({
        let made = capture(|| initialize_buffer_with(&entropy, &mut *buffer));

        made?;
    });

    let kept = vec![0_u8; MASTER_KEY_LEN].leak();

    buffer.open(&mut copying_into(kept))?;

    is_found(&watch.snapshot()?, "the key made, copied out of its page");

    Ok(())
}

#[redoubt_forensics::test]
fn test_making_the_key_from_a_source_leaves_nothing() -> Result<(), AnyError> {
    let entropy = MockEntropySource::new(MockEntropySourceBehaviour::YieldOver(&KEY));
    let needles = entropy.upcoming_backwards(&[MASTER_KEY_LEN]);

    let mut watching = Watching::start(&[("key", &needles[0])])?;

    let mut buffer = create_buffer()?;

    forensics!({
        let made = capture(|| initialize_buffer_with(&entropy, &mut *buffer));

        made?;
    });

    // Nothing emptied: the key stays in its page, which is guarded and never
    // swept.
    watching.none_left("the key made")?;

    Ok(())
}
