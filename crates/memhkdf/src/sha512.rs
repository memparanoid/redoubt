// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-512 implementation per RFC 6234 Section 6.4

use crate::{BLOCK_LEN, HASH_LEN, zeroize_128};

/// SHA-512 constants K per RFC 6234 Section 5.2
/// First 64 bits of fractional parts of cube roots of first 80 primes
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// Initial hash values H(0) per RFC 6234 Section 6.4.1
/// First 64 bits of fractional parts of square roots of first 8 primes
const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Rotate right
#[inline(always)]
const fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// SHA-512 logical functions per RFC 6234 Section 5.4
#[inline(always)]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
const fn bsig0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

#[inline(always)]
const fn bsig1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

#[inline(always)]
const fn ssig0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

#[inline(always)]
const fn ssig1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

/// SHA-512 streaming state
pub struct Sha512State {
    h: [u64; 8],
    buffer: [u8; BLOCK_LEN],
    buffer_len: usize,
    total_len: u128,
}

impl Sha512State {
    /// Create new SHA-512 state
    pub fn new() -> Self {
        Self {
            h: H0,
            buffer: [0u8; BLOCK_LEN],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update state with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u128;

        // Fill buffer if partially filled
        if self.buffer_len > 0 {
            let space = BLOCK_LEN - self.buffer_len;
            let copy_len = core::cmp::min(space, data.len());

            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;

            offset = copy_len;

            if self.buffer_len == BLOCK_LEN {
                self.compress_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + BLOCK_LEN <= data.len() {
            let block: [u8; BLOCK_LEN] = data[offset..offset + BLOCK_LEN].try_into().unwrap();
            self.compress_block(&block);

            offset += BLOCK_LEN;
        }

        // Buffer remaining
        if offset < data.len() {
            let remaining = data.len() - offset;

            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and output hash
    pub fn finalize(mut self, out: &mut [u8; HASH_LEN]) {
        // Padding: append 1 bit, then zeros, then 128-bit length
        let bit_len = self.total_len * 8;

        // Append 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length (16 bytes), pad and compress
        if self.buffer_len > BLOCK_LEN - 16 {
            // Fill rest with zeros
            for i in self.buffer_len..BLOCK_LEN {
                self.buffer[i] = 0;
            }

            self.compress_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        // Pad with zeros up to length field
        for i in self.buffer_len..BLOCK_LEN - 16 {
            self.buffer[i] = 0;
        }

        // Append 128-bit length in big-endian
        self.buffer[BLOCK_LEN - 16..BLOCK_LEN].copy_from_slice(&bit_len.to_be_bytes());

        self.compress_block(&self.buffer.clone());

        // Output hash
        for (i, &word) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        // Zeroize state
        self.zeroize();
    }

    /// Compress one 128-byte block
    fn compress_block(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u64; 80];

        // Prepare message schedule
        for t in 0..16 {
            w[t] = u64::from_be_bytes(block[t * 8..(t + 1) * 8].try_into().unwrap());
        }
        for t in 16..80 {
            w[t] = ssig1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssig0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // 80 rounds
        for t in 0..80 {
            let t1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Update hash values
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);

        // Zeroize w
        for word in &mut w {
            unsafe {
                core::ptr::write_volatile(word, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Zeroize internal state
    fn zeroize(&mut self) {
        for word in &mut self.h {
            unsafe {
                core::ptr::write_volatile(word, 0);
            }
        }
        zeroize_128(&mut self.buffer);
        unsafe {
            core::ptr::write_volatile(&mut self.buffer_len, 0);
            core::ptr::write_volatile(&mut self.total_len, 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// One-shot SHA-512
pub fn sha512(data: &[u8], out: &mut [u8; HASH_LEN]) {
    let mut state = Sha512State::new();
    state.update(data);
    state.finalize(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from RFC 6234 Section 8.5
    /// SHA-512("")
    #[test]
    fn test_sha512_empty() {
        let mut out = [0u8; 64];
        sha512(b"", &mut out);
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(out, expected);
    }

    /// Test vector from RFC 6234 Section 8.5
    /// SHA-512("abc")
    #[test]
    fn test_sha512_abc() {
        let mut out = [0u8; 64];
        sha512(b"abc", &mut out);
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(out, expected);
    }

    /// Test vector from RFC 6234 Section 8.5
    /// SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    #[test]
    fn test_sha512_long() {
        let mut out = [0u8; 64];
        sha512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", &mut out);
        let expected = [
            0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc,
            0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad,
            0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b,
            0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
            0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
        ];
        assert_eq!(out, expected);
    }
}
