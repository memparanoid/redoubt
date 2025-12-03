// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Helper functions for working with collections during encoding/decoding.

use zeroize::Zeroize;

use crate::error::{MemDecodeError, MemEncodeError, OverflowError};
use crate::mem_encode_buf::MemEncodeBuf;
use crate::traits::{
    CollectionDecode, CollectionEncode, MemBytesRequired, MemDecodable, MemEncodable, FastZeroizable,
};

/// Converts a reference to a trait object (`&dyn MemBytesRequired`).
///
/// Helper for creating heterogeneous collections of types implementing `MemBytesRequired`.
#[inline(always)]
pub fn to_bytes_required_dyn_ref<'a, T: MemBytesRequired>(
    x: &'a T,
) -> &'a (dyn MemBytesRequired + 'a) {
    x
}

/// Converts a mutable reference to a trait object (`&mut dyn FastZeroizable`).
///
/// Helper for creating heterogeneous collections of types implementing `FastZeroizable`.
#[inline(always)]
pub fn to_zeroizable_dyn_mut<'a, T: FastZeroizable>(x: &'a mut T) -> &'a mut (dyn FastZeroizable + 'a) {
    x
}

/// Converts a mutable reference to a trait object (`&mut dyn MemEncodable`).
///
/// Helper for creating heterogeneous collections of types implementing `MemEncodable`.
#[inline(always)]
pub fn to_encode_dyn_mut<'a, T: MemEncodable>(x: &'a mut T) -> &'a mut (dyn MemEncodable + 'a) {
    x
}

/// Converts a mutable reference to a trait object (`&mut dyn MemDecodable`).
///
/// Helper for creating heterogeneous collections of types implementing `MemDecodable`.
#[inline(always)]
pub fn to_decode_dyn_mut<'a, T: MemDecodable>(x: &'a mut T) -> &'a mut (dyn MemDecodable + 'a) {
    x
}

/// Zeroizes all elements in a collection via an iterator.
pub fn zeroize_collection_iter_mut<T>(collection_iter_mut: &mut dyn Iterator<Item = &mut T>)
where
    T: FastZeroizable + ?Sized,
{
    for elem in collection_iter_mut {
        (*elem).fast_zeroize();
    }
}

/// Validates that the expected element count matches the actual count.
///
/// Returns an error if `len != num_elements`.
pub fn mem_decode_assert_num_elements(
    len: usize,
    num_elements: usize,
) -> Result<(), MemDecodeError> {
    if len != num_elements {
        return Err(MemDecodeError::InvariantViolated);
    }

    Ok(())
}

/// Calculates total bytes required for a collection of elements.
///
/// Sums the `mem_bytes_required()` for all elements in the iterator.
pub fn mem_bytes_required(
    collection_iter: &mut dyn Iterator<Item = &dyn MemBytesRequired>,
) -> Result<usize, OverflowError> {
    let mut collection_bytes_required: usize = 0;

    for elem in collection_iter {
        let elem_bytes_required = elem.mem_bytes_required().map_err(|_| OverflowError {
            reason: "Overflow while getting the element mem_bytes_required()".into(),
        })?;

        collection_bytes_required = collection_bytes_required
            .checked_add(elem_bytes_required)
            .ok_or(OverflowError {
                reason: "Overflow while summing collection bytes required".into(),
            })?;
    }

    let collection_le_len = size_of::<usize>();
    let collection_le_bytes_required = size_of::<usize>();
    let header_bytes_size = collection_le_len + collection_le_bytes_required;

    collection_bytes_required
        .checked_add(header_bytes_size)
        .ok_or(OverflowError {
            reason: "Overflow while summing collection total bytes required".into(),
        })
}

fn try_drain_into<T>(
    buf: &mut MemEncodeBuf,
    collection_encode: &mut T,
) -> Result<(), MemEncodeError>
where
    T: CollectionEncode + ?Sized,
{
    let num_elements = collection_encode.mem_num_elements();
    let bytes_required = collection_encode.mem_bytes_required().map_err(|_| {
        MemEncodeError::OverflowError(OverflowError {
            reason: "Overflow while getting element mem_bytes_required()".into(),
        })
    })?;

    let mut num_elements_le_bytes = num_elements.to_le_bytes();
    let mut bytes_required_le_bytes = bytes_required.to_le_bytes();

    buf.drain_bytes(num_elements_le_bytes.as_mut_slice())?;
    buf.drain_bytes(bytes_required_le_bytes.as_mut_slice())?;

    let collection_encode_iter_mut = collection_encode.encode_iter_mut();

    for elem in collection_encode_iter_mut {
        elem.drain_into(buf)?;
    }

    Ok(())
}

/// Encodes a collection into a buffer with header and element iteration.
///
/// This function encodes collections with the wire format:
/// `[ num_elements: usize LE ] [ bytes_required: usize LE ] [ elem1 ] [ elem2 ] ... [ elemN ]`
///
/// On success, the source collection is zeroized.
/// On error, both the buffer and source collection are zeroized.
pub fn drain_into<T>(
    buf: &mut MemEncodeBuf,
    collection_encode: &mut T,
) -> Result<(), MemEncodeError>
where
    T: CollectionEncode + FastZeroizable + ?Sized,
{
    let result: Result<(), MemEncodeError> = try_drain_into(buf, collection_encode);

    if result.is_err() {
        buf.zeroize();
        collection_encode.fast_zeroize();
    }

    result
}

pub(crate) fn extract_collection_header(
    bytes: &mut [u8],
    cursor: &mut usize,
) -> Result<(usize, usize), MemDecodeError> {
    let num_elements_le_bytes_size = size_of::<usize>();
    let bytes_required_le_bytes_size = size_of::<usize>();
    let header_size = num_elements_le_bytes_size + bytes_required_le_bytes_size;

    if *cursor != 0 || bytes.len() < header_size {
        return Err(MemDecodeError::InvariantViolated);
    }

    let (num_elements_le_bytes_slice, bytes_required_le_bytes_slice) =
        bytes[0..header_size].split_at_mut(num_elements_le_bytes_size);

    let mut num_elements_le_bytes = [0u8; size_of::<usize>()];
    let mut bytes_required_le_bytes = [0u8; size_of::<usize>()];

    num_elements_le_bytes.copy_from_slice(num_elements_le_bytes_slice);
    bytes_required_le_bytes.copy_from_slice(bytes_required_le_bytes_slice);

    // wipe unused
    num_elements_le_bytes_slice.zeroize();
    bytes_required_le_bytes_slice.zeroize();

    // Decode to semantic values
    let num_elements = usize::from_le_bytes(num_elements_le_bytes);
    let bytes_required = usize::from_le_bytes(bytes_required_le_bytes);

    // wipe unused
    num_elements_le_bytes.zeroize();
    bytes_required_le_bytes.zeroize();

    *cursor = header_size;

    Ok((num_elements, bytes_required))
}

pub(crate) fn try_drain_from<T>(
    bytes: &mut [u8],
    collection_decode: &mut T,
) -> Result<usize, MemDecodeError>
where
    T: CollectionDecode + ?Sized,
{
    let mut cursor: usize = 0;
    let (num_elements, bytes_required) = extract_collection_header(bytes, &mut cursor)?;

    if bytes.len() < bytes_required {
        return Err(MemDecodeError::InvariantViolated);
    }

    collection_decode.prepare_with_num_elements(num_elements)?;

    let collection_iter_mut = collection_decode.decode_iter_mut();

    for elem in collection_iter_mut {
        // Pass remaining bytes to elem, it will consume what it needs
        let consumed = elem.drain_from(&mut bytes[cursor..])?;

        cursor = cursor.checked_add(consumed).ok_or(OverflowError {
            reason: "Overflow while adding consumed bytes to cursor".into(),
        })?;

        if cursor > bytes.len() {
            return Err(MemDecodeError::InvariantViolated);
        }
    }

    // Verify we consumed exactly what the header said
    if cursor != bytes_required {
        return Err(MemDecodeError::InvariantViolated);
    }

    Ok(bytes_required)
}

/// Decodes a collection from bytes with header validation and element iteration.
///
/// This function decodes collections encoded with the wire format:
/// `[ num_elements: usize LE ] [ bytes_required: usize LE ] [ elem1 ] [ elem2 ] ... [ elemN ]`
///
/// On success, the source bytes are zeroized.
/// On error, both the source bytes and destination collection are zeroized.
pub fn drain_from<T>(bytes: &mut [u8], collection_decode: &mut T) -> Result<usize, MemDecodeError>
where
    T: CollectionDecode + FastZeroizable + ?Sized,
{
    let result = try_drain_from(bytes, collection_decode);

    if let Err(ref _e) = result {
        bytes.zeroize();
        collection_decode.fast_zeroize();
    }

    result
}
