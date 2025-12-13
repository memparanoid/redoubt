// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use memzer::ZeroizationProbe;

use crate::codec_buffer::CodecBuffer;
use crate::support::test_utils::tamper_encoded_bytes_for_tests;
use crate::support::test_utils::{CodecTestBreaker, CodecTestBreakerBehaviour};
use crate::{BytesRequired, Decode, Encode};

#[test]
fn test_tamper_encoded_bytes_for_tests() {
    let mut vec = vec![
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 100),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 200),
        CodecTestBreaker::new(CodecTestBreakerBehaviour::None, 300),
    ];
    let bytes_required = vec
        .encode_bytes_required()
        .expect("Failed to get encode_bytes_required()");
    let mut buf = CodecBuffer::with_capacity(bytes_required);

    vec.encode_into(&mut buf)
        .expect("Failed to encode_into(..)");

    tamper_encoded_bytes_for_tests(buf.as_mut_slice());

    let mut decode_buf = buf.export_as_vec();
    let mut recovered: Vec<CodecTestBreaker> = vec![];
    let result = recovered.decode_from(&mut decode_buf.as_mut_slice());

    assert!(result.is_err());

    #[cfg(feature = "zeroize")]
    // Assert zeroization!
    {
        assert!(buf.is_zeroized());
        assert!(decode_buf.is_zeroized());
        assert!(vec.is_zeroized());
        assert!(recovered.is_zeroized());
    }
}
