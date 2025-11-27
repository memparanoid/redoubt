// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use zeroize::Zeroize;

use membuffer::Buffer;

use crate::error::{CodecBufferError, DecodeBufferError};
use crate::traits::{CodecBuffer, DecodeBuffer};

#[test]
fn test_write() {
    let elements = 10;
    let bytes_required = elements * size_of::<usize>();
    let mut buf = Buffer::new(bytes_required);

    for mut elem in 0..elements {
        buf.write(&mut elem).expect("Failed to drain(..)");
    }

    println!("Buf: {:?}", buf.as_slice());
}

#[test]
fn test_read_usize() {
    // LE bytes for usize values 42 and 123
    let mut bytes: [u8; 16] = [0; 16];

    // Write 42 in LE
    bytes[0] = 42;
    // Write 123 in LE at offset 8
    bytes[8] = 123;

    let mut slice: &mut [u8] = &mut bytes;

    let mut first: usize = 0;
    slice.read_usize(&mut first).expect("read_usize failed");
    assert_eq!(first, 42);
    assert_eq!(slice.len(), 8); // Slice shrunk

    let mut second: usize = 0;
    slice.read_usize(&mut second).expect("read_usize failed");
    assert_eq!(second, 123);
    assert_eq!(slice.len(), 0); // Slice fully consumed
}

#[test]
fn test_read_usize_out_of_bounds() {
    let mut bytes: [u8; 4] = [0; 4]; // Too small for usize (8 bytes)
    let mut slice: &mut [u8] = &mut bytes;

    let mut dst: usize = 0;
    let result = slice.read_usize(&mut dst);
    assert_eq!(result, Err(DecodeBufferError::OutOfBounds));
}

#[test]
fn test_read() {
    let mut bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    let mut slice: &mut [u8] = &mut bytes;

    let mut dst: u32 = 0;
    slice.read(&mut dst).expect("read failed");

    // LE: 0x78563412
    assert_eq!(dst, 0x78563412);
}

#[test]
fn test_read_slice() {
    let mut bytes: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut slice: &mut [u8] = &mut bytes;

    let mut dst: [u8; 4] = [0; 4];
    slice.read_slice(&mut dst, 4).expect("read_slice failed");

    assert_eq!(dst, [1, 2, 3, 4]);
}

#[test]
fn test_read_slice_out_of_bounds() {
    let mut bytes: [u8; 4] = [1, 2, 3, 4];
    let mut slice: &mut [u8] = &mut bytes;

    let mut dst: [u8; 8] = [0; 8];
    let result = slice.read_slice(&mut dst, 8);

    assert_eq!(result, Err(DecodeBufferError::OutOfBounds));
}
