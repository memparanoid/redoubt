// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Core traits for systematic, zeroizing serialization.

use super::error::{MemDecodeError, MemEncodeError, OverflowError};
use super::mem_encode_buf::MemEncodeBuf;

/// Trait for types that can be systematically zeroized.
///
/// This trait provides a unified interface for zeroizing types, delegating to
/// [`zeroize::Zeroize`]. `FastZeroizable` is used internally by guards and encoding/decoding
/// operations to ensure all data is zeroized after use.
///
/// # Example
///
/// ```rust
/// use memcode_core::FastZeroizable;
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// struct Data {
///     bytes: Vec<u8>,
/// }
///
/// impl FastZeroizable for Data {
///     fn self_zeroize(&mut self) {
///         self.zeroize(); // Delegate to Zeroize
///     }
/// }
/// ```
pub trait FastZeroizable {
    /// Zeroizes the value in place.
    ///
    /// After calling this method, the value should be in a "zeroed" state
    /// (all bytes set to 0).
    fn self_zeroize(&mut self);
}

/// Trait for encoding data into a buffer with move semantics.
///
/// Types implementing `MemEncode` can serialize themselves into a [`MemEncodeBuf`],
/// **consuming and zeroizing** the source data in the process. This prevents
/// plaintext copies from remaining in memory after encoding.
///
/// # Design
///
/// - **Move semantics**: `drain_into()` consumes the source value (via `&mut self`)
/// - **Zeroization**: Source is zeroized after successful encoding
/// - **Error safety**: Source is zeroized even if encoding fails
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemEncodeBuf, MemEncode, MemBytesRequired};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// let mut value = vec![1u8, 2, 3];
/// let size = value.mem_bytes_required()?;
/// let mut buf = MemEncodeBuf::new(size);
///
/// value.drain_into(&mut buf)?;
///
/// // Source is now zeroized
/// assert!(value.iter().all(|&b| b == 0));
/// # Ok(())
/// # }
/// ```
pub trait MemEncode: FastZeroizable {
    /// Encodes `self` into the buffer, consuming and zeroizing the source.
    ///
    /// # Errors
    ///
    /// Returns [`MemEncodeError`] if the buffer is too small or encoding fails.
    /// **Invariant:** Source is zeroized on both success and error paths.
    fn drain_into(&mut self, buf: &mut MemEncodeBuf) -> Result<(), MemEncodeError>;
}

/// Trait for decoding data from bytes with zeroization of consumed input.
///
/// Types implementing `MemDecode` can deserialize themselves from a byte slice,
/// **zeroizing the consumed bytes** in the process. This prevents plaintext from
/// remaining in buffers after decoding.
///
/// # Design
///
/// - **Partial consumption**: Returns number of bytes consumed
/// - **Zeroization**: Consumed bytes are zeroized before returning
/// - **Error safety**: Partial data is zeroized even if decoding fails
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemDecode, MemEncode, MemEncodeBuf, MemBytesRequired};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// let mut original = vec![1u8, 2, 3];
/// let size = original.mem_bytes_required()?;
/// let mut buf = MemEncodeBuf::new(size);
/// original.drain_into(&mut buf)?;
///
/// let mut decoded = Vec::<u8>::new();
/// let consumed = decoded.drain_from(buf.as_mut_slice())?;
///
/// assert_eq!(decoded, vec![1, 2, 3]);
/// assert_eq!(consumed, size);
/// # Ok(())
/// # }
/// ```
pub trait MemDecode: FastZeroizable {
    /// Decodes data from bytes and returns the number of bytes consumed.
    ///
    /// # Precondition
    ///
    /// `bytes.len()` must be >= the required bytes for this type.
    /// The implementation will consume only what it needs and return that amount.
    ///
    /// # Errors
    ///
    /// Returns [`MemDecodeError`] if:
    /// - Buffer is too small
    /// - Data is corrupted/invalid
    /// - Collection size mismatch
    ///
    /// **Invariant:** Consumed bytes are zeroized on both success and error paths.
    fn drain_from(&mut self, bytes: &mut [u8]) -> Result<usize, MemDecodeError>;
}

/// Trait for types that report the number of elements (fields) they contain.
///
/// Used for collection headers to encode `num_elements` upfront, enabling
/// decoders to validate structure before allocating/decoding.
///
/// # Example
///
/// ```rust
/// use memcode_core::MemNumElements;
///
/// struct Data {
///     field_a: Vec<u8>,
///     field_b: [u8; 32],
///     field_c: u64,
/// }
///
/// impl MemNumElements for Data {
///     fn mem_num_elements(&self) -> usize {
///         3 // Three fields
///     }
/// }
/// ```
pub trait MemNumElements {
    /// Returns the number of elements (fields) in this type.
    ///
    /// For structs, this is the field count. For collections, this is the element count.
    fn mem_num_elements(&self) -> usize;
}

/// Trait for calculating exact serialization size before encoding.
///
/// This trait enables **allocation-free** encoding: calculate size upfront,
/// pre-allocate buffer once, then encode without re-allocations.
///
/// # Example
///
/// ```rust
/// use memcode_core::{MemBytesRequired, MemEncodeBuf};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// let value = vec![1u8, 2, 3, 4, 5];
/// let size = value.mem_bytes_required()?;
///
/// // Pre-allocate exact size (no re-allocations needed)
/// let buf = MemEncodeBuf::new(size);
/// # Ok(())
/// # }
/// ```
pub trait MemBytesRequired {
    /// Calculates the exact number of bytes required to encode this value.
    ///
    /// # Errors
    ///
    /// Returns [`OverflowError`] if the size calculation overflows `usize`.
    fn mem_bytes_required(&self) -> Result<usize, OverflowError>;
}

/// Marker trait combining all requirements for encoding.
///
/// Types implementing `MemEncodable` can be fully encoded with size calculation,
/// element counting, and buffer draining.
///
/// # Example
///
/// ```rust,ignore
/// use memcode_core::MemEncodable;
///
/// fn encode_generic<T: MemEncodable>(value: &mut T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
///     let size = value.mem_bytes_required()?;
///     let mut buf = MemEncodeBuf::new(size);
///     value.drain_into(&mut buf)?;
///     Ok(buf.into_vec())
/// }
/// ```
pub trait MemEncodable: MemEncode + MemNumElements + MemBytesRequired {}

/// Marker trait for decodable types.
///
/// Types implementing `MemDecodable` can be decoded from bytes with size validation.
pub trait MemDecodable: MemDecode + MemBytesRequired {}

/// Trait for types that can iterate over encodable fields.
///
/// Used for collection-like types to encode fields sequentially.
pub trait EncodeIterator {
    /// Returns a mutable iterator over encodable fields.
    fn encode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemEncodable>;
}

/// Trait for types that can iterate over decodable fields.
///
/// Used for collection-like types to decode fields sequentially.
pub trait DecodeIterator {
    /// Returns a mutable iterator over decodable fields.
    fn decode_iter_mut(&mut self) -> impl Iterator<Item = &mut dyn MemDecodable>;
}

/// Marker trait for types with collection-like encoding.
///
/// Combines [`EncodeIterator`], [`MemEncodable`], and [`FastZeroizable`] for struct-like types.
pub trait CollectionEncode: EncodeIterator + MemEncodable + FastZeroizable {}

/// Trait for types with collection-like decoding.
///
/// Extends [`DecodeIterator`], [`MemDecodable`], and [`FastZeroizable`] with element count validation.
pub trait CollectionDecode: DecodeIterator + MemDecodable + FastZeroizable {
    /// Prepares the collection for decoding with a known element count.
    ///
    /// # Errors
    ///
    /// Returns [`MemDecodeError::InvariantViolated`] if `num_elements` doesn't match
    /// the expected count for this type.
    fn prepare_with_num_elements(&mut self, num_elements: usize) -> Result<(), MemDecodeError>;
}
