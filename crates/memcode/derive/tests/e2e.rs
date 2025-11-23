// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// @todo: Assert zeroization!
#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use zeroize::Zeroize;

    use memcode_core::{MemBytesRequired, MemDecode, MemEncode, MemEncodeBuf, MemNumElements};
    use memcode_derive::MemCodec;

    #[test]
    fn e2e_memcodec_roundtrip() {
        #[derive(MemCodec, Debug, Eq, PartialEq, Zeroize)]
        struct Very {
            pub nested: Nested,
            pub data: [u8; 64],
            #[memcode(default)]
            pub default: [u8; 32],
        }

        impl Default for Very {
            fn default() -> Self {
                Self {
                    data: [u8::MAX; 64],
                    nested: Nested::default(),
                    default: [0u8; 32],
                }
            }
        }

        #[derive(MemCodec, Debug, Eq, PartialEq, Zeroize)]
        struct Nested {
            pub deep: Deep,
            pub data: [u8; 64],
        }

        impl Default for Nested {
            fn default() -> Self {
                Self {
                    data: [u8::MAX; 64],
                    deep: Deep::default(),
                }
            }
        }

        #[derive(MemCodec, Debug, Eq, PartialEq, Zeroize)]
        struct Deep {
            pub structure: Structure,
            pub data: [u8; 64],
        }

        impl Default for Deep {
            fn default() -> Self {
                Self {
                    data: [u8::MAX; 64],
                    structure: Structure::default(),
                }
            }
        }

        #[derive(MemCodec, Debug, Eq, PartialEq, Zeroize)]
        struct Structure {
            pub data: [u8; 64],
        }

        impl Default for Structure {
            fn default() -> Self {
                Self {
                    data: [u8::MAX; 64],
                }
            }
        }

        let mut very = Very::default();

        let snapshot_1 = format!("{:?}", very);
        assert_snapshot!(snapshot_1);

        let bytes_required = very
            .mem_bytes_required()
            .expect("Failed to get mem_bytes_required()");
        let num_elements = very.mem_num_elements();

        let snapshot_2 = format!(
            "bytes_required: {}, num_elements: {}",
            bytes_required, num_elements
        );
        assert_snapshot!(snapshot_2);

        let mut buf = MemEncodeBuf::new(bytes_required);
        let result = very.drain_into(&mut buf);

        assert!(result.is_ok());

        // Assert zeroization!
        {
            // zeroized snapshot
            let snapshot_3 = format!("{:?}", very);
            assert_snapshot!(snapshot_3);
        }

        // Fulfilled buf
        let snapshot_4 = format!("buffer length: {}", buf.as_slice().len());
        assert_snapshot!(snapshot_4);

        // struct should be zeroized
        let snapshot_5 = format!("{:?}", buf.as_mut_slice());
        assert_snapshot!(snapshot_5);

        let result = very.drain_from(buf.as_mut_slice());
        assert!(result.is_ok());

        let snapshot_6 = format!("{:?}", very);
        assert_eq!(snapshot_6, snapshot_1);

        // Assert zeroization!
        assert!(buf.as_slice().iter().all(|b| *b == 0));
    }
}
