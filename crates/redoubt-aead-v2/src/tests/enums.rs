// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use rstest::rstest;

use redoubt_codec::{
    BytesRequired, Decode, DecodeError, DecodeSlice, Encode, EncodeError, EncodeSlice, PreAlloc,
    RedoubtCodecBuffer,
};

use crate::enums::AeadAlgorithm;

const EVERY: [AeadAlgorithm; 2] = [AeadAlgorithm::Aegis128L, AeadAlgorithm::XChachaPoly1305];

fn named(said: u8) -> bool {
    EVERY.iter().any(|algorithm| algorithm.said() == said)
}

// === === === === === === === === === ===
// said
// === === === === === === === === === ===

#[rstest]
#[case::xchachapoly1305(AeadAlgorithm::XChachaPoly1305, 1)]
#[case::aegis128l(AeadAlgorithm::Aegis128L, 2)]
fn test_said_is_the_byte_the_variant_declares(
    #[case] algorithm: AeadAlgorithm,
    #[case] expected: u8,
) {
    assert_eq!(algorithm.said(), expected);
}

#[test]
fn test_no_variant_says_zero() {
    for algorithm in EVERY {
        assert_ne!(algorithm.said(), 0, "{algorithm:?}");
    }
}

#[test]
fn test_no_two_variants_say_the_same_byte() {
    for (at, algorithm) in EVERY.iter().enumerate() {
        for other in &EVERY[at + 1..] {
            assert_ne!(algorithm.said(), other.said(), "{algorithm:?} and {other:?}");
        }
    }
}

// === === === === === === === === === ===
// read
// === === === === === === === === === ===

#[test]
fn test_zero_is_no_algorithm() {
    assert_eq!(AeadAlgorithm::read(0), None);
}

#[test]
fn test_no_byte_outside_the_named_ones_is_an_algorithm() {
    for said in 0..=u8::MAX {
        if named(said) {
            continue;
        }

        assert_eq!(AeadAlgorithm::read(said), None, "byte {said}");
    }
}

#[test]
fn test_a_byte_a_variant_said_reads_back_as_that_variant() {
    for algorithm in EVERY {
        assert_eq!(AeadAlgorithm::read(algorithm.said()), Some(algorithm));
    }
}

// === === === === === === === === === ===
// encode_bytes_required
// === === === === === === === === === ===

#[test]
fn test_encode_bytes_required_is_one_byte() {
    for algorithm in EVERY {
        assert_eq!(algorithm.encode_bytes_required(), Ok(1));
    }
}

// === === === === === === === === === ===
// encode_into
// === === === === === === === === === ===

#[test]
fn test_encode_into_propagates_a_buffer_with_no_room() {
    for mut algorithm in EVERY {
        let mut buffer = RedoubtCodecBuffer::with_capacity(0);

        assert!(
            matches!(
                algorithm.encode_into(&mut buffer),
                Err(EncodeError::RedoubtCodecBufferError(_))
            ),
            "{algorithm:?}"
        );
    }
}

#[test]
fn test_encode_into_empties_a_buffer_it_could_not_write_to() {
    let mut algorithm = AeadAlgorithm::Aegis128L;
    let mut buffer = RedoubtCodecBuffer::with_capacity(0);

    let result = algorithm.encode_into(&mut buffer);

    assert!(matches!(
        result,
        Err(EncodeError::RedoubtCodecBufferError(_))
    ));

    // Assert zeroization!
    assert!(buffer.as_slice().iter().all(|byte| *byte == 0));
}

#[test]
fn test_encode_into_writes_the_byte_the_variant_said() {
    for mut algorithm in EVERY {
        let mut buffer = RedoubtCodecBuffer::with_capacity(1);

        assert_eq!(algorithm.encode_into(&mut buffer), Ok(()));
        assert_eq!(buffer.as_slice(), &[algorithm.said()]);
    }
}

#[test]
fn test_encode_into_leaves_the_variant_where_it_was() {
    for mut algorithm in EVERY {
        let mut buffer = RedoubtCodecBuffer::with_capacity(1);
        let before = algorithm;

        assert_eq!(algorithm.encode_into(&mut buffer), Ok(()));
        assert_eq!(algorithm, before);
    }
}

// === === === === === === === === === ===
// decode_from
// === === === === === === === === === ===

#[test]
fn test_decode_from_propagates_a_buffer_with_nothing_in_it() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes: [u8; 0] = [];
    let mut cursor = &mut bytes[..];

    assert!(matches!(
        algorithm.decode_from(&mut cursor),
        Err(DecodeError::DecodeBufferError(_))
    ));
}

#[test]
fn test_decode_from_reports_a_byte_that_is_no_algorithm() {
    for said in 0..=u8::MAX {
        if named(said) {
            continue;
        }

        let mut algorithm = AeadAlgorithm::default();
        let mut bytes = [said];
        let mut cursor = &mut bytes[..];

        assert_eq!(
            algorithm.decode_from(&mut cursor),
            Err(DecodeError::PreconditionViolated),
            "byte {said}"
        );
    }
}

#[test]
fn test_decode_from_reports_a_byte_that_was_zeroized() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes = [0_u8];
    let mut cursor = &mut bytes[..];

    assert_eq!(
        algorithm.decode_from(&mut cursor),
        Err(DecodeError::PreconditionViolated)
    );
}

#[test]
fn test_decode_from_leaves_the_variant_it_was_given_when_it_refuses() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes = [0xff_u8];
    let mut cursor = &mut bytes[..];

    let result = algorithm.decode_from(&mut cursor);

    assert_eq!(result, Err(DecodeError::PreconditionViolated));
    assert_eq!(algorithm, AeadAlgorithm::default());
}

#[test]
fn test_decode_from_empties_the_message_when_it_refuses() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes = [0xff_u8, 0x5c, 0x5c, 0x5c];
    let mut cursor = &mut bytes[..];

    let result = algorithm.decode_from(&mut cursor);

    assert_eq!(result, Err(DecodeError::PreconditionViolated));

    // Assert zeroization!
    assert_eq!(bytes, [0, 0, 0, 0]);
}

#[test]
fn test_decode_from_advances_the_cursor_past_the_byte_it_read() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes = [AeadAlgorithm::Aegis128L.said(), 0x5c, 0x5c];
    let mut cursor = &mut bytes[..];

    assert_eq!(algorithm.decode_from(&mut cursor), Ok(()));
    assert_eq!(cursor.len(), 2);
}

#[test]
fn test_decode_from_empties_the_byte_it_read() {
    let mut algorithm = AeadAlgorithm::default();
    let mut bytes = [AeadAlgorithm::Aegis128L.said(), 0x5c, 0x5c];
    let mut cursor = &mut bytes[..];

    assert_eq!(algorithm.decode_from(&mut cursor), Ok(()));

    // Assert zeroization!
    assert_eq!(bytes[0], 0);
}

#[test]
fn test_decode_from_returns_the_variant_the_byte_names() {
    for expected in EVERY {
        let mut algorithm = AeadAlgorithm::default();
        let mut bytes = [expected.said()];
        let mut cursor = &mut bytes[..];

        assert_eq!(algorithm.decode_from(&mut cursor), Ok(()));
        assert_eq!(algorithm, expected);
    }
}

// === === === === === === === === === ===
// encode_into, then decode_from
// === === === === === === === === === ===

#[test]
fn test_a_variant_encoded_and_decoded_is_the_variant_it_was() {
    for mut expected in EVERY {
        let mut buffer = RedoubtCodecBuffer::with_capacity(
            expected
                .encode_bytes_required()
                .expect("Infallible: one byte never overflows a usize"),
        );

        expected
            .encode_into(&mut buffer)
            .expect("Infallible: capacity calculated above");

        let mut bytes = buffer.export_as_vec();
        let mut cursor = &mut bytes[..];
        let mut algorithm = AeadAlgorithm::default();

        assert_eq!(algorithm.decode_from(&mut cursor), Ok(()));
        assert_eq!(algorithm, expected);
    }
}

// === === === === === === === === === ===
// prealloc
// === === === === === === === === === ===

/// All-zeros is not a value this type admits.
///
/// A `true` here sends the collection down the path that memsets and then
/// declares the memory initialized without constructing anything, and the byte
/// it would leave names no algorithm. Reading that back is undefined, and
/// nothing about it is a compile error.
#[test]
#[expect(
    clippy::assertions_on_constants,
    reason = "the constant is the claim: nothing else fails when it changes"
)]
fn test_this_type_is_never_bulk_initialized() {
    assert!(!<AeadAlgorithm as PreAlloc>::ZERO_INIT);
}

#[test]
fn test_prealloc_leaves_the_variant_where_it_was() {
    for mut algorithm in EVERY {
        let before = algorithm;

        algorithm.prealloc(64);

        assert_eq!(algorithm, before);
    }
}

// === === === === === === === === === ===
// encode_slice_into
// === === === === === === === === === ===

#[test]
fn test_encode_slice_into_propagates_a_buffer_that_runs_out_partway() {
    let mut slice = EVERY;
    let mut buffer = RedoubtCodecBuffer::with_capacity(EVERY.len() - 1);

    assert!(matches!(
        AeadAlgorithm::encode_slice_into(&mut slice, &mut buffer),
        Err(EncodeError::RedoubtCodecBufferError(_))
    ));
}

#[test]
fn test_encode_slice_into_writes_nothing_for_a_slice_with_nothing_in_it() {
    let mut slice: [AeadAlgorithm; 0] = [];
    let mut buffer = RedoubtCodecBuffer::with_capacity(0);

    assert_eq!(
        AeadAlgorithm::encode_slice_into(&mut slice, &mut buffer),
        Ok(())
    );
    assert!(buffer.as_slice().is_empty());
}

#[test]
fn test_encode_slice_into_writes_one_byte_for_each_variant_in_order() {
    let mut slice = EVERY;
    let mut buffer = RedoubtCodecBuffer::with_capacity(EVERY.len());

    assert_eq!(
        AeadAlgorithm::encode_slice_into(&mut slice, &mut buffer),
        Ok(())
    );
    assert_eq!(
        buffer.as_slice(),
        &EVERY.map(AeadAlgorithm::said),
        "the bytes are not the variants in the order they were given"
    );
}

// === === === === === === === === === ===
// decode_slice_from
// === === === === === === === === === ===

#[test]
fn test_decode_slice_from_propagates_a_message_that_runs_out_partway() {
    let mut slice = [AeadAlgorithm::default(); 2];
    let mut bytes = [AeadAlgorithm::Aegis128L.said()];
    let mut cursor = &mut bytes[..];

    assert!(matches!(
        AeadAlgorithm::decode_slice_from(&mut slice, &mut cursor),
        Err(DecodeError::DecodeBufferError(_))
    ));
}

#[test]
fn test_decode_slice_from_propagates_a_byte_that_is_no_algorithm() {
    let mut slice = [AeadAlgorithm::default(); 2];
    let mut bytes = [AeadAlgorithm::Aegis128L.said(), 0xff];
    let mut cursor = &mut bytes[..];

    assert_eq!(
        AeadAlgorithm::decode_slice_from(&mut slice, &mut cursor),
        Err(DecodeError::PreconditionViolated)
    );
}

#[test]
fn test_decode_slice_from_empties_the_message_when_it_refuses() {
    let mut slice = [AeadAlgorithm::default(); 2];
    let mut bytes = [AeadAlgorithm::Aegis128L.said(), 0xff, 0x5c];
    let mut cursor = &mut bytes[..];

    let result = AeadAlgorithm::decode_slice_from(&mut slice, &mut cursor);

    assert_eq!(result, Err(DecodeError::PreconditionViolated));

    // Assert zeroization!
    assert!(bytes.iter().all(|byte| *byte == 0));
}

#[test]
fn test_decode_slice_from_reads_nothing_for_a_slice_with_nothing_in_it() {
    let mut slice: [AeadAlgorithm; 0] = [];
    let mut bytes = [0x5c_u8];
    let mut cursor = &mut bytes[..];

    assert_eq!(
        AeadAlgorithm::decode_slice_from(&mut slice, &mut cursor),
        Ok(())
    );
    assert_eq!(cursor.len(), 1);
}

#[test]
fn test_decode_slice_from_fills_the_slice_in_the_order_the_bytes_came() {
    let mut slice = [AeadAlgorithm::default(); 2];
    let mut bytes = EVERY.map(AeadAlgorithm::said);
    let mut cursor = &mut bytes[..];

    assert_eq!(
        AeadAlgorithm::decode_slice_from(&mut slice, &mut cursor),
        Ok(())
    );
    assert_eq!(slice, EVERY);
}

// === === === === === === === === === ===
// encode_slice_into, then decode_slice_from
// === === === === === === === === === ===

#[test]
fn test_a_slice_encoded_and_decoded_is_the_slice_it_was() {
    let mut written = EVERY;
    let mut buffer = RedoubtCodecBuffer::with_capacity(EVERY.len());

    AeadAlgorithm::encode_slice_into(&mut written, &mut buffer)
        .expect("Infallible: capacity is one byte per variant");

    let mut bytes = buffer.export_as_vec();
    let mut cursor = &mut bytes[..];
    let mut read = [AeadAlgorithm::default(); EVERY.len()];

    assert_eq!(
        AeadAlgorithm::decode_slice_from(&mut read, &mut cursor),
        Ok(())
    );
    assert_eq!(read, EVERY);
}
