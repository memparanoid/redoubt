// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_asm::Backend;
use rstest::rstest;

use crate::backend::fill;
use crate::error::EntropyError;

/// The most the assembly asks the kernel for at once.
const PIECE: usize = 256;

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_fill_returns_ok_for_an_empty_slice(#[case] backend: Backend) -> Result<(), EntropyError> {
    let mut empty = [0_u8; 0];

    fill(backend, &mut empty)
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_fill_writes_every_piece_of_a_slice_wider_than_one(
    #[case] backend: Backend,
) -> Result<(), EntropyError> {
    let mut wide = [0_u8; 4 * PIECE + 32];

    fill(backend, &mut wide)?;

    for (at, piece) in wide.chunks(PIECE).enumerate() {
        assert!(
            piece.iter().any(|&byte| byte != 0),
            "piece {at} came back empty"
        );
    }

    Ok(())
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_fill_returns_different_bytes_each_time(
    #[case] backend: Backend,
) -> Result<(), EntropyError> {
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];

    fill(backend, &mut first)?;
    fill(backend, &mut second)?;

    assert_ne!(first, second);

    Ok(())
}
