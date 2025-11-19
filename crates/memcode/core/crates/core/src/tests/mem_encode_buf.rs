// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use speculate::speculate;

use crate::error::MemEncodeBufError;
use crate::mem_encode_buf::MemEncodeBuf;

speculate! {
    describe "MemEncodeBuf::new" {
        it "creates buffer with correct capacity" {
            let buf = MemEncodeBuf::new(4);
            assert_eq!(buf.len(), 4);
        }

        it "zero-fills all elements" {
            let buf = MemEncodeBuf::new(4);
            assert!(buf.as_slice().iter().all(|w| *w == 0));
        }

        it "resets cursor to zero" {
            let buf = MemEncodeBuf::new(8);
            assert_eq!(buf.cursor(), 0);
        }
    }

    describe "MemEncodeBuf::is_empty" {
        it "returns false for is_empty when buffer has capacity" {
            let buf = MemEncodeBuf::new(4);
            assert!(!buf.is_empty());
        }

        it "returns true for is_empty when buffer has zero capacity" {
            let buf = MemEncodeBuf::new(0);
            assert!(buf.is_empty());
        }
    }

    describe "MemEncodeBuf::drain_byte" {
        it "appends a byte and increments cursor" {
            let mut buf = MemEncodeBuf::new(2);
            let mut u8 = u8::MAX;

            buf.drain_byte(&mut u8).unwrap();

            assert_eq!(buf.cursor(), 1);
            assert_eq!(buf.as_slice()[0], u8::MAX);

            // Assert zeroization!
            assert_eq!(u8, 0);
        }

        it "returns error when capacity is exceeded" {
            let mut buf = MemEncodeBuf::new(1);
            let mut u8_1 = 127u8;
            let mut u8_2 = u8::MAX;

            buf.drain_byte(&mut u8_1).unwrap();

            let result = buf.drain_byte(&mut u8_2);

            assert!(result.is_err());
            assert!(matches!(result, Err(MemEncodeBufError::CapacityExceededError)));

            // Assert zeroization!
            assert_eq!(u8_1, 0);
            assert_eq!(u8_2, 0);
            assert!(buf.as_slice().iter().all(|b| *b == 0));
        }

        it "writes bytes in correct positions" {
            let mut buf = MemEncodeBuf::new(2);
            let mut u8_1 = 127u8;
            let mut u8_2 = u8::MAX;

            buf.drain_byte(&mut u8_1).unwrap();
            buf.drain_byte(&mut u8_2).unwrap();

            assert_eq!(buf.as_slice(), [127u8, u8::MAX]);

            // Assert zeroization!
            assert_eq!(u8_1, 0);
            assert_eq!(u8_2, 0);
        }
    }

    describe "MemEncodeBuf::reset_with_capacity" {
        it "clears previous contents with zeroization and resets cursor" {
            let mut buf = MemEncodeBuf::new(2);
            let mut u8_1 = 127u8;
            let mut u8_2 = u8::MAX;

            buf.drain_byte(&mut u8_1).unwrap();
            buf.drain_byte(&mut u8_2).unwrap();

            buf.reset_with_capacity(2);
            assert_eq!(buf.cursor(), 0);

            // Assert zeroization!
            assert!(buf.as_slice().iter().all(|w| *w == 0));
            assert_eq!(u8_1, 0);
            assert_eq!(u8_2, 0);
        }

        it "reallocates with new capacity" {
            let mut buf = MemEncodeBuf::new(2);
            assert_eq!(buf.len(), 2);

            buf.reset_with_capacity(5);
            assert_eq!(buf.len(), 5);
        }
    }

    describe "MemEncodeBuf::drain_bytes" {
        it "drains bytes and zeroizes src on success" {
            let mut buf = MemEncodeBuf::new(2);
            let mut bytes = [1u8, 2u8];

            buf.drain_bytes(&mut bytes).unwrap();

            // Assert zeroization!
            assert!(bytes.iter().all(|b| *b == 0));
            assert_eq!(buf.as_slice(), [1u8, 2u8]);
        }

        it "zeroizes buf and src on capacity error" {
            let mut buf = MemEncodeBuf::new(1);
            let mut bytes = [1u8, 2u8];

            let result = buf.drain_bytes(&mut bytes);

            assert!(result.is_err());
            assert!(matches!(result, Err(MemEncodeBufError::CapacityExceededError)));

            // Assert zeroization!
            assert!(bytes.iter().all(|b| *b == 0));
            assert!(buf.as_mut_slice().iter().all(|b| *b == 0));
        }

        it "returns error when cursor addition would overflow" {
            let mut buf = MemEncodeBuf::new(10);
            buf.set_cursor_for_test(usize::MAX - 5);

            let mut bytes = [1u8; 10];

            let result = buf.drain_bytes(&mut bytes);

            assert!(result.is_err());
            assert!(matches!(result, Err(MemEncodeBufError::CapacityExceededError)));

            // Assert zeroization!
            assert!(bytes.iter().all(|b| *b == 0));
        }
    }
}
