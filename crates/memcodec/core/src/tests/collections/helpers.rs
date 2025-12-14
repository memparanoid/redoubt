// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(feature = "zeroize")]
use redoubt_zero::ZeroizationProbe;

use crate::codec_buffer::CodecBuffer;
use crate::collections::helpers::{
    bytes_required_sum, decode_fields, encode_fields, header_size, process_header,
    to_bytes_required_dyn_ref, to_decode_dyn_mut, to_decode_zeroize_dyn_mut, to_encode_dyn_mut,
    to_encode_zeroize_dyn_mut, write_header,
};
use crate::error::{CodecBufferError, DecodeError, OverflowError};
use crate::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use crate::traits::{BytesRequired, Decode, DecodeZeroize, Encode, EncodeZeroize};
use redoubt_test_utils::{apply_permutation, index_permutations};

// header_size

#[test]
fn test_header_size() {
    assert_eq!(header_size(), 2 * size_of::<usize>());
}

// write_header

#[test]
fn test_write_header_ok() {
    let mut size = 42usize;
    let mut bytes_required = 128usize;
    let mut buf = CodecBuffer::with_capacity(header_size());

    let result = write_header(&mut buf, &mut size, &mut bytes_required);

    assert!(result.is_ok());
}

#[test]
fn test_write_header_capacity_exceeded_for_size() {
    let mut size = 42usize;
    let mut bytes_required = 128usize;
    let mut buf = CodecBuffer::with_capacity(1); // Too small for size

    let result = write_header(&mut buf, &mut size, &mut bytes_required);

    assert!(result.is_err());
    assert!(matches!(result, Err(CodecBufferError::CapacityExceeded)));
}

#[test]
fn test_write_header_capacity_exceeded_for_bytes_required() {
    let mut size = 42usize;
    let mut bytes_required = 128usize;
    let mut buf = CodecBuffer::with_capacity(size_of::<usize>()); // Enough for size, too small for bytes_required

    let result = write_header(&mut buf, &mut size, &mut bytes_required);

    assert!(result.is_err());
    assert!(matches!(result, Err(CodecBufferError::CapacityExceeded)));
}

// process_header
#[test]
fn test_process_header_buffer_too_small_for_header() {
    // First precondition violated: buf.len() < *header_size
    let mut output_size = 0usize;
    let mut buf = [0u8; 1]; // Too small for header

    let result = process_header(&mut buf.as_mut_slice(), &mut output_size);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_process_header_buffer_too_small_for_data() {
    // Second precondition violated: buf.len() < *expected_len
    let mut buf = CodecBuffer::with_capacity(header_size() + size_of::<u8>()); // only capacity for size.

    let mut size: usize = 20;
    let mut excessive_bytes_required: usize = 1024;
    let mut data: u8 = 1;

    buf.write(&mut size).expect("Failed to write size");
    buf.write(&mut excessive_bytes_required)
        .expect("Failed to write bytes_required");
    // Write some data
    buf.write(&mut data).expect("Failed to write data");

    let mut read_buf = buf.as_mut_slice();
    let result = process_header(&mut read_buf, &mut 0);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_process_header_buffer_header_size_gt_bytes_required() {
    // Third precondition violated: *bytes_required > *header_size
    let mut buf = CodecBuffer::with_capacity(header_size() + size_of::<u8>()); // only capacity for size.

    let mut size: usize = 1;
    let mut insufficient_bytes_required: usize = header_size() - 1;
    let mut data: u8 = 1;

    buf.write(&mut size).expect("Failed to write size");
    buf.write(&mut insufficient_bytes_required)
        .expect("Failed to write bytes_required");
    // Write some data
    buf.write(&mut data).expect("Failed to write data");

    let mut read_buf = buf.as_mut_slice();
    let result = process_header(&mut read_buf, &mut 0);

    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::PreconditionViolated)));
}

#[test]
fn test_process_header_ok() {
    let mut buf = CodecBuffer::with_capacity(header_size() + size_of::<u8>()); // only capacity for size.

    let mut size: usize = 1;
    let mut data: u8 = 1;
    let mut bytes_required: usize = header_size() + data.to_le_bytes().len();

    buf.write(&mut size).expect("Failed to write size");
    buf.write(&mut bytes_required)
        .expect("Failed to write bytes_required");
    // Write some data
    buf.write(&mut data).expect("Failed to write data");

    let mut output_size = 0;
    let mut read_buf = buf.as_mut_slice();
    let result = process_header(&mut read_buf, &mut output_size);

    assert!(result.is_ok());
    assert_eq!(output_size, 1);
}

// to_bytes_required_dyn_ref

#[test]
fn test_to_bytes_required_dyn_ref() {
    let tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let dyn_ref: &dyn BytesRequired = to_bytes_required_dyn_ref(&tb);

    assert_eq!(
        dyn_ref.encode_bytes_required().expect("Failed"),
        tb.encode_bytes_required().expect("Failed")
    );
}

// to_encode_dyn_mut

#[test]
fn test_to_encode_dyn_mut() {
    let mut tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let mut buf = CodecBuffer::with_capacity(1024);

    let dyn_mut: &mut dyn Encode = to_encode_dyn_mut(&mut tb);
    let result = dyn_mut.encode_into(&mut buf);

    assert!(result.is_ok());
}

// to_decode_dyn_mut

#[test]
fn test_to_decode_dyn_mut() {
    // First encode
    let mut tb = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let bytes_required = tb.encode_bytes_required().expect("Failed");
    let mut buf = CodecBuffer::with_capacity(bytes_required);
    tb.encode_into(&mut buf).expect("Failed to encode");

    // Decode
    {
        let mut decode_buf = buf.export_as_vec();
        let mut decoded = CodecTestBreaker::default();
        let dyn_mut: &mut dyn Decode = to_decode_dyn_mut(&mut decoded);
        let result = dyn_mut.decode_from(&mut decode_buf.as_mut_slice());

        assert!(result.is_ok());
        assert_eq!(decoded.usize.data, 100);

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(decode_buf.is_zeroized());
        }
    }

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(tb.is_zeroized());
    }
}

// bytes_required_sum

#[test]
fn test_bytes_required_sum_ok() {
    let tb1 = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let tb2 = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_ok());
}

#[test]
fn test_bytes_required_sum_element_error() {
    let tb1 = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let tb2 = CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceBytesRequiredOverflow, 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(OverflowError { reason }) if reason == "CodecTestBreaker forced overflow"
    ));
}

#[test]
fn test_bytes_required_sum_overflow() {
    let tb1 = CodecTestBreaker::new(CodecTestBreakerBehaviour::BytesRequiredReturn(usize::MAX), 100);
    let tb2 = CodecTestBreaker::new(CodecTestBreakerBehaviour::BytesRequiredReturn(1), 200);

    let refs: [&dyn BytesRequired; 2] = [
        to_bytes_required_dyn_ref(&tb1),
        to_bytes_required_dyn_ref(&tb2),
    ];

    let result = bytes_required_sum(refs.into_iter());

    assert!(result.is_err());
}

// encode_fields / decode_fields

#[test]
fn perm_test_encode_fields_propagates_error_at_any_position() {
    let fields = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 2),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 3),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 4),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 5),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::ForceEncodeError, 6),
    ];
    let bytes_required = fields
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");

    index_permutations(fields.len(), |idx_perm| {
        let mut fields_clone = fields;
        apply_permutation(&mut fields_clone, idx_perm);

        let mut buf = CodecBuffer::with_capacity(bytes_required);

        let result = encode_fields(
            fields_clone.iter_mut().map(to_encode_zeroize_dyn_mut),
            &mut buf,
        );

        assert!(result.is_err());

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(fields_clone.is_zeroized());
        }
    });
}

#[test]
fn perm_test_decode_fields_propagates_error_at_any_position() {
    let fields = [
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 1),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 2),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 3),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 4),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 5),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 6),
    ];

    let bytes_required = fields
        .iter()
        .map(|tb| tb.encode_bytes_required().expect("Failed"))
        .sum();

    let mut recovered_fields = fields;
    recovered_fields[0].set_behaviour(CodecTestBreakerBehaviour::ForceDecodeError);

    index_permutations(fields.len(), |idx_perm| {
        // Encode
        let mut fields_clone = fields;
        apply_permutation(&mut fields_clone, idx_perm);

        let mut buf = CodecBuffer::with_capacity(bytes_required);
        encode_fields(
            fields_clone.iter_mut().map(to_encode_zeroize_dyn_mut),
            &mut buf,
        )
        .expect("Failed to encode");

        // Decode
        {
            let mut recovered_fields_clone = recovered_fields;
            apply_permutation(&mut recovered_fields_clone, idx_perm);

            let mut decode_buf = buf.export_as_vec();
            let result = decode_fields(
                recovered_fields_clone
                    .iter_mut()
                    .map(to_decode_zeroize_dyn_mut),
                &mut decode_buf.as_mut_slice(),
            );

            assert!(result.is_err());

            #[cfg(feature = "zeroize")]
            // Assert zeroization!
            {
                assert!(buf.is_zeroized());
                assert!(decode_buf.is_zeroized());
                assert!(recovered_fields_clone.is_zeroized());
            }
        }

        #[cfg(feature = "zeroize")]
        // Assert zeroization!
        {
            assert!(buf.is_zeroized());
            assert!(fields_clone.is_zeroized());
        }
    });
}

// Roundtrip

#[test]
fn test_fields_roundtrip_ok() {
    // Encode
    let mut tb1 = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100);
    let mut tb2 = CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 200);
    let mut buf = CodecBuffer::with_capacity(1024);

    let encode_refs: [&mut dyn EncodeZeroize; 2] = [
        to_encode_zeroize_dyn_mut(&mut tb1),
        to_encode_zeroize_dyn_mut(&mut tb2),
    ];
    encode_fields(encode_refs.into_iter(), &mut buf).expect("Failed to encode");

    // Assert src zeroization after encode!
    #[cfg(feature = "zeroize")]
    {
        assert!(tb1.is_zeroized());
        assert!(tb2.is_zeroized());
    }

    // Decode
    let mut decoded1 = CodecTestBreaker::default();
    let mut decoded2 = CodecTestBreaker::default();

    let decode_refs: [&mut dyn DecodeZeroize; 2] = [
        to_decode_zeroize_dyn_mut(&mut decoded1),
        to_decode_zeroize_dyn_mut(&mut decoded2),
    ];

    let mut decode_buf = buf.export_as_vec();
    let result = decode_fields(decode_refs.into_iter(), &mut decode_buf.as_mut_slice());

    assert!(result.is_ok());
    assert_eq!(decoded1.usize.data, 100);
    assert_eq!(decoded2.usize.data, 200);

    // Assert buf zeroization after decode!
    #[cfg(feature = "zeroize")]
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
    }
}
