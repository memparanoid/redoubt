// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_codec::{
    BytesRequired, Decode, DecodeBuffer, DecodeError, DecodeSlice, Encode, EncodeError,
    EncodeSlice, OverflowError, PreAlloc, RedoubtCodecBuffer,
};
use redoubt_zero::{FastZeroizable, ZeroizeMetadata};

/// Which authenticated cipher a message was sealed with.
///
/// The discriminants are written out because they are the wire, and a variant
/// inserted between two others would otherwise renumber everything after it.
///
/// **They start at one.** Zero belongs to no algorithm, so a byte that was
/// zeroized — a buffer wiped on an error path, memory nobody wrote — refuses to
/// decode instead of naming a cipher.
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum AeadAlgorithm {
    /// Software all the way down, so every machine has it.
    #[default]
    XChachaPoly1305 = 1,
    /// The AES round function used as a permutation, so only a machine with
    /// AES instructions has it.
    Aegis128L = 2,
}

/// Which call of an [`Aead`] refuses, for a caller that needs one to.
///
/// There is no variant for "nothing happens": that is an `Aead` built without
/// one, so the state where a behaviour is present and inert cannot be reached.
///
/// The ordinals are one-based and each operation is counted on its own, so
/// `FailAtNthEncrypt(2)` is about the second `encrypt` however many nonces or
/// decryptions went past in between.
///
/// [`Aead`]: crate::Aead
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum AeadBehaviour {
    /// Refuse this many encryptions in, and let the rest through.
    FailAtNthEncrypt(usize),
    /// Refuse this many decryptions in, and let the rest through.
    FailAtNthDecrypt(usize),
    /// Refuse this many nonces in, and let the rest through.
    FailAtNthGenerateNonce(usize),
}

impl AeadAlgorithm {
    pub(crate) const fn said(self) -> u8 {
        self as u8
    }

    /// Each arm asks the variant for its own byte rather than repeating it.
    ///
    /// Written as literals, the two lists are two places to change and the
    /// mapping can invert without anything failing to compile — a message
    /// sealed with one cipher then opens as the other.
    pub(crate) const fn read(said: u8) -> Option<Self> {
        match said {
            _ if said == Self::XChachaPoly1305.said() => Some(Self::XChachaPoly1305),
            _ if said == Self::Aegis128L.said() => Some(Self::Aegis128L),
            _ => None,
        }
    }

}

impl ZeroizeMetadata for AeadAlgorithm {
    /// A memset would leave a byte that is no algorithm.
    ///
    /// Bulk zeroization writes zeros over the whole value, and zero is not one
    /// of the discriminants — deliberately, so that a wiped byte refuses to
    /// decode. For a `repr(u8)` enum that byte is not a bit pattern the type
    /// admits, and reading it back is undefined.
    const CAN_BE_BULK_ZEROIZED: bool = false;
}

impl FastZeroizable for AeadAlgorithm {
    /// The default, which is the one algorithm every machine has.
    ///
    /// There is nothing secret here to destroy: what is wanted is that a value
    /// wiped alongside its neighbours names something that can actually be run.
    #[inline(always)]
    fn fast_zeroize(&mut self) {
        *self = Self::default();
    }
}

impl BytesRequired for AeadAlgorithm {
    #[inline(always)]
    fn encode_bytes_required(&self) -> Result<usize, OverflowError> {
        Ok(core::mem::size_of::<u8>())
    }
}

impl Encode for AeadAlgorithm {
    #[inline(always)]
    fn encode_into(&mut self, buf: &mut RedoubtCodecBuffer) -> Result<(), EncodeError> {
        let mut said = self.said();

        // The buffer is emptied and the value is not: which cipher sealed a
        // message travels in the clear beside it, and what the buffer may
        // already hold from other fields does not.
        if let Err(why) = buf.write(&mut said) {
            buf.fast_zeroize();

            return Err(EncodeError::from(why));
        }

        Ok(())
    }
}

impl Decode for AeadAlgorithm {
    #[inline(always)]
    fn decode_from(&mut self, buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        let mut said = 0_u8;

        if let Err(why) = buf.read(&mut said) {
            buf.fast_zeroize();

            return Err(DecodeError::from(why));
        }

        let Some(read) = Self::read(said) else {
            buf.fast_zeroize();

            return Err(DecodeError::PreconditionViolated);
        };

        *self = read;

        Ok(())
    }
}

impl PreAlloc for AeadAlgorithm {
    /// All-zeros is not a value this type admits, which is what the
    /// discriminants starting at one is for.
    const ZERO_INIT: bool = false;

    #[inline(always)]
    fn prealloc(&mut self, _size: usize) {}
}

impl EncodeSlice for AeadAlgorithm {
    /// One at a time, not a bulk copy.
    ///
    /// A primitive hands its whole slice to the buffer because its bytes are
    /// the wire. These are not: what travels is the discriminant, and reading
    /// it out is what `encode_into` does.
    #[inline(always)]
    fn encode_slice_into(
        slice: &mut [Self],
        buf: &mut RedoubtCodecBuffer,
    ) -> Result<(), EncodeError> {
        for algorithm in slice.iter_mut() {
            algorithm.encode_into(buf)?;
        }

        Ok(())
    }
}

impl DecodeSlice for AeadAlgorithm {
    #[inline(always)]
    fn decode_slice_from(slice: &mut [Self], buf: &mut &mut [u8]) -> Result<(), DecodeError> {
        for algorithm in slice.iter_mut() {
            algorithm.decode_from(buf)?;
        }

        Ok(())
    }
}
