// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use pastey::paste;
use seq_macro::seq;
use zeroize::Zeroize;

use crate::collections::{
    self, drain_from, drain_into, extract_collection_header, mem_bytes_required,
};
use crate::error::{MemDecodeError, MemEncodeBufError, MemEncodeError, OverflowError};
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{
    CollectionDecode, CollectionEncode, MemBytesRequired, MemDecodable, MemEncodable,
};

use crate::support::test_utils::memcode_test_breaker::{
    MemCodeTestBreaker, MemCodeTestBreakerBehaviour,
};
use crate::tests::support::perm::permute_with;

#[test]
fn test_mem_bytes_required_happy_path() {
    macro_rules! check_for_type {
        ($ty:ty, $max_val:literal) => {{
            paste! {
                seq!(N in 0..=$max_val {
                    {
                        let collection = [
                            #(
                                (N % ($max_val + 1)) as $ty,
                            )*
                        ];
                        let bytes_required = collections::mem_bytes_required(
                            &mut collection.iter().map(collections::to_bytes_required_dyn_ref),
                        )
                        .expect("Failed to get mem_bytes_required()");
                        let header_size = 2 * core::mem::size_of::<usize>();
                        let expected = collection.len() * core::mem::size_of::<$ty>() + header_size;
                        assert_eq!(
                            bytes_required, expected,
                            "Failed for {} with {} elements",
                            stringify!($ty), collection.len()
                        );
                    }
                });
            }
        }};
    }

    check_for_type!(u8, 64);
    check_for_type!(u16, 128);
    check_for_type!(u32, 256);
    check_for_type!(u64, 512);
}

#[test]
fn test_mem_bytes_required_propagates_element_overflow_error() {
    let collection = Vec::from([MemCodeTestBreaker::new(
        MemCodeTestBreakerBehaviour::ForceBytesRequiredOverflowError,
    )]);

    let result = mem_bytes_required(
        &mut collection
            .iter()
            .map(collections::to_bytes_required_dyn_ref),
    );
    let expected_overflow_error = OverflowError {
        reason: "Overflow while getting the element mem_bytes_required()".into(),
    };

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ref error) if error == &expected_overflow_error
    ));
}

#[test]
fn test_mem_bytes_required_propagates_collection_overflow_error() {
    let collection = Vec::from([
        MemCodeTestBreaker::new(
            MemCodeTestBreakerBehaviour::ForceBytesRequiredUsizeMax,
        ),
        MemCodeTestBreaker::new(
            MemCodeTestBreakerBehaviour::ForceBytesRequiredUsizeMax,
        ),
    ]);

    let result = mem_bytes_required(
        &mut collection
            .iter()
            .map(collections::to_bytes_required_dyn_ref),
    );
    let expected_overflow_error = OverflowError {
        reason: "Overflow while summing collection bytes required".into(),
    };

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ref error) if error == &expected_overflow_error
    ));
}

#[test]
fn test_mem_bytes_required_reports_result_overflow_error() {
    let collection = Vec::from([MemCodeTestBreaker::new(
        MemCodeTestBreakerBehaviour::ForceBytesRequiredUsize(usize::MAX - size_of::<usize>() + 1),
    )]);

    let result = mem_bytes_required(
        &mut collection
            .iter()
            .map(collections::to_bytes_required_dyn_ref),
    );
    let expected_overflow_error = OverflowError {
        reason: "Overflow while summing collection total bytes required".into(),
    };

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ref error) if error == &expected_overflow_error
    ));
}

#[test]
fn test_drain_into_propagates_element_mem_bytes_required_overflow_error() {
    let mut collection = Vec::new();
    collection.push(MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None));

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    collection[0].change_behaviour(MemCodeTestBreakerBehaviour::ForceBytesRequiredOverflowError);

    let result = drain_into(&mut buf, &mut collection);
    let expected_overflow_error = MemEncodeError::OverflowError(OverflowError {
        reason: "Overflow while getting element mem_bytes_required()".into(),
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ref error) if error == &expected_overflow_error
    ));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(collection.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_drain_into_reports_mem_encode_buf_capacity_exceeded_error() {
    let collection: Vec<u8> = vec![1, 2, 3];
    let bytes_required = collection
        .mem_bytes_required()
        .expect("Failed to get mem_bytes_required()");

    for i in 0..bytes_required {
        // We need to clone because drain will zeroize which shrinks the vec.
        let mut collection_clone = collection.clone();
        let mut buf = MemEncodeBuf::new(i);

        // Assert (not) zeroization!
        assert!(collection_clone.iter().any(|b| *b != 0));

        let result = drain_into(&mut buf, &mut collection_clone);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MemEncodeError::MemEncodeBufError(
                MemEncodeBufError::CapacityExceededError
            ))
        ));

        // Assert zeroization!
        assert!(collection_clone.iter().all(|b| *b == 0));
        assert!(buf.as_slice().iter().all(|b| *b == 0));
    }
}

#[test]
// cargo test -p memcode_core test_drain_into_reports_encode_error --release -- --nocapture --test-threads=1
fn test_drain_into_propagates_encode_error() {
    let mut collection = vec![
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::ForceEncodeError),
    ];

    permute_with(&mut collection, |collection| {
        let bytes_required = collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = MemEncodeBuf::new(bytes_required);

        let result = drain_into(&mut buf, collection);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MemEncodeError::IntentionalEncodeError)
        ));

        // Assert zeroization!
        assert!(collection.iter().all(|tb| tb.is_zeroized()));
        assert!(buf.as_slice().iter().all(|b| *b == 0));

        for elem in collection {
            elem.restore_to_max();
        }
    });
}

#[test]
fn test_extract_collection_header() {
    // Scope 1: cursor != 0 -> InvariantViolated
    {
        let mut bytes = [0u8; 16];
        let mut cursor = 1;
        let result = extract_collection_header(&mut bytes, &mut cursor);
        assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));
    }

    // Scope 2: bytes.len() < header_size -> InvariantViolated
    {
        let mut bytes = [0u8; 8]; // Only 8 bytes, needs 16
        let mut cursor = 0;
        let result = extract_collection_header(&mut bytes, &mut cursor);
        assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));
    }

    // Scope 3: Happy path + zeroization
    {
        let num_elements = 42usize;
        let bytes_required = 1024usize;

        let mut bytes = [
            num_elements.to_le_bytes().as_slice(),
            bytes_required.to_le_bytes().as_slice(),
        ]
        .concat();

        let mut cursor = 0;
        let result = extract_collection_header(&mut bytes, &mut cursor);

        assert_eq!(result, Ok((num_elements, bytes_required)));
        assert_eq!(cursor, 2 * core::mem::size_of::<usize>());

        // Assert zeroization!
        assert!(bytes.iter().all(|b| *b == 0));
    }
}

#[test]
fn test_drain_from_propagates_extract_collection_header_error() {
    let mut bytes = [1u8];
    let mut collection = vec![0u8];

    let result = drain_from(&mut bytes, &mut collection);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));

    // Assert zeroization!
    assert!(bytes.iter().all(|b| *b == 0));
    assert!(collection.iter().all(|b| *b == 0));
}

#[test]
fn test_drain_from_propagates_violated_invariant_error() {
    let mut collection = [u8::MAX; 256];
    let mut decoded_collection = [0u8; 256];

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem required capacity"),
    );

    // Assert (not) zeroization!
    assert!(collection.iter().any(|b| *b != 0));

    drain_into(&mut buf, &mut collection).expect("Failed to drain_into(..)");

    let mut bytes = buf.as_slice().to_vec();

    while !bytes.is_empty() {
        bytes.pop();
        let mut bytes_clone = bytes.clone();

        let result = drain_from(&mut bytes_clone, &mut decoded_collection);

        assert!(result.is_err());
        assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));

        // Assert zeroization!
        assert!(bytes_clone.iter().all(|b| *b == 0));
        assert!(collection.iter().all(|b| *b == 0));
    }

    assert!(bytes.is_empty());
}

#[test]
fn test_drain_from_propagates_prepare_with_num_elements_error() {
    let mut collection = [MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None)];
    let mut decoded_collection = [MemCodeTestBreaker::new(
        MemCodeTestBreakerBehaviour::ForcePrepareWithNumElementsError,
    )];

    // Assert (not) zeroization!
    assert!(!collection[0].data.is_empty());
    assert!(!decoded_collection[0].data.is_empty());
    assert!(!collection.iter().all(|tb| tb.is_zeroized()));
    assert!(!decoded_collection.iter().all(|tb| tb.is_zeroized()));

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem_required_bytes()"),
    );

    drain_into(&mut buf, &mut collection).expect("Failed to drain_into(..)");

    // Assert zeroization!
    assert!(collection.iter().all(|tb| tb.is_zeroized()));

    let result = drain_from(buf.as_mut_slice(), &mut decoded_collection);

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MemDecodeError::IntentionalPrepareWithNumElementsError)
    ));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(decoded_collection.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_drain_from_propagates_decode_error() {
    let mut collection = vec![
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::ForceDecodeError),
    ];

    permute_with(&mut collection, |collection| {
        // Assert (not) zeroization!
        assert!(!collection[0].data.is_empty());
        assert!(!collection.iter().all(|tb| tb.is_zeroized()));

        let bytes_required = collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let mut buf = MemEncodeBuf::new(bytes_required);

        drain_into(&mut buf, collection).expect("Failed to drain_into(..)");

        let result = drain_from(buf.as_mut_slice(), collection);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MemDecodeError::IntentionalDecodeError)
        ));

        // Assert zeroization!
        assert!(collection.iter().all(|tb| tb.is_zeroized()));
        assert!(buf.as_slice().iter().all(|b| *b == 0));

        for elem in collection {
            elem.restore_to_max();
        }
    });
}

#[test]
fn test_drain_from_propagates_overflow_error_on_cursor_counter() {
    let mut collection = [
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
        MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None),
    ];

    // Assert (not) zeroization!
    assert!(
        !collection
            .iter()
            .all(|tb| !tb.data.is_empty() && tb.is_zeroized())
    );

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    drain_into(&mut buf, &mut collection).expect("Failed to drain_into(..)");

    collection[0].change_behaviour(MemCodeTestBreakerBehaviour::ForceDecodeReturnBytes(
        usize::MAX,
    ));
    collection[1].change_behaviour(MemCodeTestBreakerBehaviour::ForceDecodeReturnBytes(
        usize::MAX,
    ));

    let result = drain_from(buf.as_mut_slice(), &mut collection);
    let expected_overflow_error = MemDecodeError::OverflowError(OverflowError {
        reason: "Overflow while adding consumed bytes to cursor".into(),
    });

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ref error) if error == &expected_overflow_error
    ));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(collection.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn rountrip_test() {
    let mut array = [u8::MAX; 5];
    let required_bytes = collections::mem_bytes_required(
        &mut array.iter().map(collections::to_bytes_required_dyn_ref),
    )
    .expect("Failed to get mem_bytes_required()");

    let mut buf = MemEncodeBuf::new(required_bytes);

    // Assert (not) zeroization!
    assert!(array.iter().any(|b| *b != 0));

    drain_into(&mut buf, &mut array).expect("Failed to drain_into(..)");

    let mut recovered_array = [0u8; 5];
    let result = drain_from(buf.as_mut_slice(), &mut recovered_array);

    assert!(result.is_ok());
    assert_eq!(recovered_array, [u8::MAX; 5]);

    // Assert zeroization!
    assert!(array.iter().all(|b| *b == 0));
    assert!(buf.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn test_drain_from_propagates_invariant_violated_on_cursor_overflow() {
    let mut collection = [MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None)];

    // Assert (not) zeroization!
    assert!(!collection[0].data.is_empty());
    assert!(!collection.iter().all(|tb| tb.is_zeroized()));

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    drain_into(&mut buf, &mut collection).expect("Failed to drain_into(..)");

    // Force drain_from to return a consumed value larger than remaining bytes
    collection[0].change_behaviour(MemCodeTestBreakerBehaviour::ForceDecodeReturnBytes(
        buf.as_slice().len(),
    ));

    let result = drain_from(buf.as_mut_slice(), &mut collection);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(collection.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_drain_from_propagates_invariant_violated_on_bytes_mismatch() {
    let mut collection = [MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None)];

    // Assert (not) zeroization!
    assert!(!collection[0].data.is_empty());
    assert!(!collection.iter().all(|tb| tb.is_zeroized()));

    let mut buf = MemEncodeBuf::new(
        collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()"),
    );

    drain_into(&mut buf, &mut collection).expect("Failed to drain_into(..)");

    // Force drain_from to return a consumed value different than expected
    // (less than what bytes_required in header says)
    collection[0].change_behaviour(MemCodeTestBreakerBehaviour::ForceDecodeReturnBytes(1));

    let result = drain_from(buf.as_mut_slice(), &mut collection);

    assert!(result.is_err());
    assert!(matches!(result, Err(MemDecodeError::InvariantViolated)));

    // Assert zeroization!
    assert!(buf.as_slice().iter().all(|b| *b == 0));
    assert!(collection.iter().all(|tb| tb.is_zeroized()));
}

#[test]
fn test_encode_decode_roundtrip_with_collection_traits() {
    trait Collection: CollectionDecode + CollectionEncode {}
    impl<T> Collection for Vec<T> where T: Default + Zeroize + MemEncodable + MemDecodable {}
    impl<T> Collection for [T] where T: Zeroize + MemEncodable + MemDecodable {}
    impl<T, const N: usize> Collection for [T; N] where T: Zeroize + MemEncodable + MemDecodable {}

    // What this test tries to prove (unit tests = best effort):
    // ∀C ∈ Collections  : dec(Buf, enc(Buf, C)) = C
    // ∀X ∈ Collections  : dec(Buf, enc(Buf, X)) -> zero(Buf)
    fn test_collection<T, Z>(collection: &mut T, is_zeroized: Z)
    where
        T: Collection + ?Sized,
        Z: Fn(&T) -> bool,
    {
        let bytes_required = collection
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required");

        // Encode -> Decode roundtrip
        let mut buf = MemEncodeBuf::new(bytes_required);

        // Assert (not) zeroization!
        assert!(!is_zeroized(collection));

        drain_into(&mut buf, collection).expect("Failed to drain_into(...)");

        collection
            .drain_from(buf.as_mut_slice())
            .expect("Should decode successfully");

        // Assert zeroization!
        assert!(buf.as_slice().iter().all(|b| *b == 0));
    }

    // We deliberately construct a `Vec<[u8; 16]>` so that iteration happens over fixed-size arrays
    // rather than primitive bytes — this allows testing behavior on chunked, array-based data.
    let mut vec_of_arrays = vec![[u8::MAX; 16]; 4];
    test_collection(&mut vec_of_arrays, |chunks| {
        chunks.iter().all(|arr| arr.iter().all(|b| *b == 0))
    });

    let mut array = [10u8, 20, 30, 40, 50, 60, 70, 80];
    test_collection(&mut array, |a| a.iter().all(|b| *b == 0));

    let mut slice_data = [10u8, 20, 30, 40, 50, 60, 70, 80];
    test_collection(slice_data.as_mut_slice(), |s| s.iter().all(|b| *b == 0));
}
