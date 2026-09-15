// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! A second way of getting the same answer.
//!
//! Eleven vectors pin down eleven inputs. What they cannot pin down is the
//! twelfth, and a carry chain has more shapes than an appendix has room for —
//! so the crate is also held against this, on whatever a property test cares
//! to generate.
//!
//! What makes it worth anything is that it is not the same code twice. The
//! arithmetic is `num-bigint`'s, written by other people for other reasons;
//! the modulus is constructed here rather than transcribed, so a mistyped row
//! of hexadecimal cannot make both sides wrong together; and there are no
//! limbs, no radix and no deferred carries, which is where every mistake this
//! is looking for lives.
//!
//! Slow, allocating, and branching on the numbers. All three are fine: nothing
//! here runs outside a test.

use num_bigint::BigUint;

use redoubt_aead_v2_core::consts::poly1305::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

/// The tag RFC 8439 §2.5 asks for, straight off the definition.
pub(crate) fn tag(key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE] {
    let modulus = (BigUint::from(1u8) << 130u32) - BigUint::from(5u8);

    let mut clamped = [0u8; BLOCK_SIZE];
    clamped.copy_from_slice(&key[..BLOCK_SIZE]);
    clamp(&mut clamped);

    let r = BigUint::from_bytes_le(&clamped);
    let s = BigUint::from_bytes_le(&key[BLOCK_SIZE..]);

    let mut acc = BigUint::from(0u8);

    for block in message.chunks(BLOCK_SIZE) {
        let mut number = block.to_vec();
        // The one above the block, which is what keeps a short block from
        // reading as a longer one that ended in zeros.
        number.push(1);

        acc = ((acc + BigUint::from_bytes_le(&number)) * &r) % &modulus;
    }

    acc += s;

    // Taking the low sixteen bytes is the modulo 2^128 the last step asks for.
    let mut out = [0u8; TAG_SIZE];
    let bytes = acc.to_bytes_le();
    let take = core::cmp::min(bytes.len(), TAG_SIZE);
    out[..take].copy_from_slice(&bytes[..take]);

    out
}

/// RFC 8439 §2.5: the top half of four bytes goes, and the bottom two bits of
/// three others.
fn clamp(r: &mut [u8; BLOCK_SIZE]) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

#[cfg(test)]
mod tests {
    use super::super::vectors::{VECTORS, Vector};
    use super::tag;

    // === === === === === === === === === ===
    // tag
    // === === === === === === === === === ===

    #[test]
    fn test_tag_returns_the_appendix_tag() {
        for Vector {
            number,
            asks,
            key,
            message,
            tag: expected,
        } in VECTORS
        {
            assert_eq!(
                &tag(key, message),
                expected,
                "RFC 8439 A.3 vector #{number} asks about {asks}"
            );
        }
    }
}
