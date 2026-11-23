// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use rstest::rstest;

use redoubt_alloc::RedoubtArray;
use redoubt_codec_core::{BytesRequired, Decode, DecodeError, Encode, RedoubtCodecBuffer};
use redoubt_codec_derive::RedoubtCodec;
use redoubt_zero::{RedoubtZero, ZeroizationProbe};

#[repr(u8)]
#[derive(RedoubtCodec, RedoubtZero, Clone, Debug, PartialEq)]
enum Scope {
    Owner = 0,
    Other([u8; 16]) = 1,
    Named { key: [u8; 32], id: u64 } = 2,
}

#[repr(u8)]
#[derive(RedoubtCodec, RedoubtZero)]
#[fast_zeroize(drop)]
enum Private {
    Owner(RedoubtArray<u8, 32>) = 0,
    Other(RedoubtArray<u8, 32>, [u8; 16]) = 1,
}

#[repr(u8)]
#[derive(RedoubtCodec, RedoubtZero, Clone, Debug, PartialEq)]
enum Counted {
    Empty = 0,
    Held([u8; 16], #[codec(default)] u64) = 1,
}

fn encode(
    value: &mut (impl Encode + BytesRequired),
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = RedoubtCodecBuffer::with_capacity(value.encode_bytes_required()?);

    value.encode_into(&mut buf)?;

    Ok(buf.export_as_vec())
}

#[rstest]
#[case::owner(Scope::Owner)]
#[case::other(Scope::Other([0x5A; 16]))]
#[case::named(Scope::Named { key: [0x6B; 32], id: 7 })]
fn test_each_variant_round_trips(
    #[case] original: Scope,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wire = encode(&mut original.clone())?;
    let mut decoded = Scope::Owner;

    decoded.decode_from(&mut wire.as_mut_slice())?;

    assert_eq!(decoded, original);
    assert!(wire.is_zeroized());

    Ok(())
}

#[test]
fn test_the_tag_goes_first_and_then_the_fields() -> Result<(), Box<dyn std::error::Error>> {
    let wire = encode(&mut Scope::Other([0x5A; 16]))?;
    let array_wire = encode(&mut [0x5A_u8; 16])?;

    assert_eq!(wire[0], 1);
    assert_eq!(&wire[1..], array_wire.as_slice());

    Ok(())
}

#[test]
fn test_a_field_with_codec_default_does_not_travel() -> Result<(), Box<dyn std::error::Error>> {
    let wire = encode(&mut Counted::Held([0x5A; 16], 7))?;
    let array_wire = encode(&mut [0x5A_u8; 16])?;

    assert_eq!(wire[0], 1);
    assert_eq!(&wire[1..], array_wire.as_slice());

    Ok(())
}

#[test]
fn test_a_field_with_codec_default_is_decoded_as_its_default()
-> Result<(), Box<dyn std::error::Error>> {
    let mut wire = encode(&mut Counted::Held([0x5A; 16], 7))?;
    let mut decoded = Counted::Empty;

    decoded.decode_from(&mut wire.as_mut_slice())?;

    assert_eq!(decoded, Counted::Held([0x5A; 16], 0));

    Ok(())
}

#[test]
fn test_encoding_empties_the_source() -> Result<(), Box<dyn std::error::Error>> {
    let mut scope = Scope::Named {
        key: [0x6B; 32],
        id: 7,
    };

    encode(&mut scope)?;

    assert!(scope.is_zeroized());

    Ok(())
}

#[test]
fn test_another_variant_replaces_the_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut wire = encode(&mut Private::Other(
        RedoubtArray::from_mut_array(&mut [0x11; 32]),
        [0x22; 16],
    ))?;
    let mut decoded = Private::Owner(RedoubtArray::from_mut_array(&mut [0x99; 32]));

    decoded.decode_from(&mut wire.as_mut_slice())?;

    assert!(matches!(&decoded, Private::Other(seed, id)
        if seed.as_array() == &[0x11; 32] && id == &[0x22; 16]));

    Ok(())
}

#[test]
fn test_an_unknown_tag_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let mut wire = encode(&mut Scope::Other([0x5A; 16]))?;

    wire[0] = 9;

    let mut decoded = Scope::Other([0x77; 16]);
    let refused = decoded.decode_from(&mut wire.as_mut_slice());

    assert!(matches!(refused, Err(DecodeError::UnknownTag { tag: 9 })));
    assert!(decoded.is_zeroized());

    Ok(())
}
