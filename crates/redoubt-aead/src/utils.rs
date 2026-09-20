// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::mem::size_of;

use redoubt_aead_aegis128l::Aegis128L;
use redoubt_aead_core::AeadSizes;
use redoubt_aead_xchachapoly1305::XChaCha20Poly1305;

use crate::enums::AeadAlgorithm;
use crate::errors::AeadError;

type Key<A> = <A as AeadSizes>::Key;
type Nonce<A> = <A as AeadSizes>::Nonce;
type Tag<A> = <A as AeadSizes>::Tag;

/// What a cipher is handed, borrowed from the caller and in the order it takes
/// them, with a tag it will read.
type Widths<'a, A> = (&'a Key<A>, &'a Nonce<A>, &'a Tag<A>);

/// What a cipher is handed, borrowed from the caller and in the order it takes
/// them, with a tag it will write.
type WidthsMut<'a, A> = (&'a Key<A>, &'a Nonce<A>, &'a mut Tag<A>);

/// The three widths XChaCha20-Poly1305 takes, with a tag it will read.
pub(crate) fn chacha_widths<'a>(
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a [u8],
) -> Result<Widths<'a, XChaCha20Poly1305>, AeadError> {
    widths::<XChaCha20Poly1305>(AeadAlgorithm::XChachaPoly1305, key, nonce, tag)
}

/// The three widths XChaCha20-Poly1305 takes, with a tag it will write.
pub(crate) fn chacha_widths_mut<'a>(
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a mut [u8],
) -> Result<WidthsMut<'a, XChaCha20Poly1305>, AeadError> {
    widths_mut::<XChaCha20Poly1305>(AeadAlgorithm::XChachaPoly1305, key, nonce, tag)
}

/// The three widths AEGIS-128L takes, with a tag it will read.
pub(crate) fn aegis_widths<'a>(
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a [u8],
) -> Result<Widths<'a, Aegis128L>, AeadError> {
    widths::<Aegis128L>(AeadAlgorithm::Aegis128L, key, nonce, tag)
}

/// The three widths AEGIS-128L takes, with a tag it will write.
pub(crate) fn aegis_widths_mut<'a>(
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a mut [u8],
) -> Result<WidthsMut<'a, Aegis128L>, AeadError> {
    widths_mut::<Aegis128L>(AeadAlgorithm::Aegis128L, key, nonce, tag)
}

/// Each slice as the array of that width, borrowed rather than copied.
///
/// `<&[u8; N]>::try_from` reads a length and hands back a pointer into the
/// caller's own memory. The owning form copies, and a copy of a key is a second
/// one that nothing here is in a position to empty.
fn widths<'a, A>(
    algorithm: AeadAlgorithm,
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a [u8],
) -> Result<Widths<'a, A>, AeadError>
where
    A: AeadSizes,
    &'a Key<A>: TryFrom<&'a [u8]>,
    &'a Nonce<A>: TryFrom<&'a [u8]>,
    &'a Tag<A>: TryFrom<&'a [u8]>,
{
    let taken = <&Key<A>>::try_from(key).map_err(|_| AeadError::KeyWidth {
        algorithm,
        expected: size_of::<Key<A>>(),
        given: key.len(),
    })?;
    let with = <&Nonce<A>>::try_from(nonce).map_err(|_| AeadError::NonceWidth {
        algorithm,
        expected: size_of::<Nonce<A>>(),
        given: nonce.len(),
    })?;
    let sealed = <&Tag<A>>::try_from(tag).map_err(|_| AeadError::TagWidth {
        algorithm,
        expected: size_of::<Tag<A>>(),
        given: tag.len(),
    })?;

    Ok((taken, with, sealed))
}

/// Each slice as the array of that width, with the tag borrowed to be written.
///
/// Its length is read before the conversion takes it: the error names what
/// arrived, and by then the slice has been handed over.
fn widths_mut<'a, A>(
    algorithm: AeadAlgorithm,
    key: &'a [u8],
    nonce: &'a [u8],
    tag: &'a mut [u8],
) -> Result<WidthsMut<'a, A>, AeadError>
where
    A: AeadSizes,
    &'a Key<A>: TryFrom<&'a [u8]>,
    &'a Nonce<A>: TryFrom<&'a [u8]>,
    &'a mut Tag<A>: TryFrom<&'a mut [u8]>,
{
    let taken = <&Key<A>>::try_from(key).map_err(|_| AeadError::KeyWidth {
        algorithm,
        expected: size_of::<Key<A>>(),
        given: key.len(),
    })?;
    let with = <&Nonce<A>>::try_from(nonce).map_err(|_| AeadError::NonceWidth {
        algorithm,
        expected: size_of::<Nonce<A>>(),
        given: nonce.len(),
    })?;

    let width = tag.len();
    let sealed = <&mut Tag<A>>::try_from(tag).map_err(|_| AeadError::TagWidth {
        algorithm,
        expected: size_of::<Tag<A>>(),
        given: width,
    })?;

    Ok((taken, with, sealed))
}
