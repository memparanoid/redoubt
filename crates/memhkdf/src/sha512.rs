// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-512 implementation per RFC 6234 Section 6.4

use memzer::{DropSentinel, FastZeroizable, MemZer};

use super::consts::{BLOCK_LEN, HASH_LEN};
use super::word::Word64;

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

/// SHA-512 streaming state per RFC 6234 Section 6.4.
///
/// All sensitive working variables live in the struct for guaranteed zeroization.
/// No stack allocations for sensitive data that persists across rounds.
#[derive(MemZer)]
#[memzer(drop)]
pub(crate) struct Sha512State {
    // ═══════════════════════════════════════════════════════════════════════════
    // Hash state H(i) per RFC 6234 Section 6.4.1
    // ═══════════════════════════════════════════════════════════════════════════
    h: [Word64; 8],

    // ═══════════════════════════════════════════════════════════════════════════
    // Message schedule W[0..79] per RFC 6234 Section 6.4.2 step 1
    // ═══════════════════════════════════════════════════════════════════════════
    w: [Word64; 80],

    // ═══════════════════════════════════════════════════════════════════════════
    // Working variables per RFC 6234 Section 6.4.2 step 2
    // ═══════════════════════════════════════════════════════════════════════════
    /// Working variable a
    wv_a: Word64,
    /// Working variable b
    wv_b: Word64,
    /// Working variable c
    wv_c: Word64,
    /// Working variable d
    wv_d: Word64,
    /// Working variable e
    wv_e: Word64,
    /// Working variable f
    wv_f: Word64,
    /// Working variable g
    wv_g: Word64,
    /// Working variable h
    wv_h: Word64,

    // ═══════════════════════════════════════════════════════════════════════════
    // Temporaries per RFC 6234 Section 6.4.2 step 3
    // ═══════════════════════════════════════════════════════════════════════════
    /// T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
    t1: Word64,
    /// T2 = Σ0(a) + Maj(a,b,c)
    t2: Word64,
    /// Scratch for σ/Σ/Ch/Maj results
    scratch: Word64,

    // ═══════════════════════════════════════════════════════════════════════════
    // Input buffering
    // ═══════════════════════════════════════════════════════════════════════════
    /// Input buffer for partial blocks
    buffer: [u8; BLOCK_LEN],
    /// Temporary block for compression (avoids aliasing buffer)
    tmp_block: [u8; BLOCK_LEN],
    /// Temporary 8-byte buffer for big-endian word parsing
    tmp_word: [u8; 8],
    /// Current position in buffer
    buffer_len: usize,
    /// Total message length in bytes
    total_len: u128,

    /// Drop sentinel for zeroization verification
    __drop_sentinel: DropSentinel,
}

impl Sha512State {
    /// Create new SHA-512 state initialized with H(0)
    pub fn new() -> Self {
        Self {
            h: [
                Word64::new(H0[0]),
                Word64::new(H0[1]),
                Word64::new(H0[2]),
                Word64::new(H0[3]),
                Word64::new(H0[4]),
                Word64::new(H0[5]),
                Word64::new(H0[6]),
                Word64::new(H0[7]),
            ],
            w: core::array::from_fn(|_| Word64::zero()),
            wv_a: Word64::zero(),
            wv_b: Word64::zero(),
            wv_c: Word64::zero(),
            wv_d: Word64::zero(),
            wv_e: Word64::zero(),
            wv_f: Word64::zero(),
            wv_g: Word64::zero(),
            wv_h: Word64::zero(),
            t1: Word64::zero(),
            t2: Word64::zero(),
            scratch: Word64::zero(),
            buffer: [0u8; BLOCK_LEN],
            tmp_block: [0u8; BLOCK_LEN],
            tmp_word: [0u8; 8],
            buffer_len: 0,
            total_len: 0,
            __drop_sentinel: DropSentinel::default(),
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
                self.tmp_block.copy_from_slice(&self.buffer);
                self.compress();
                self.tmp_block.fast_zeroize();
                self.buffer.fast_zeroize();
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + BLOCK_LEN <= data.len() {
            self.tmp_block
                .copy_from_slice(&data[offset..offset + BLOCK_LEN]);
            self.compress();
            self.tmp_block.fast_zeroize();
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
        // Padding per RFC 6234 Section 4.2
        let bit_len = self.total_len * 8;

        // Append 0x80 (1 bit followed by zeros)
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for 128-bit length, pad and compress
        if self.buffer_len > BLOCK_LEN - 16 {
            for i in self.buffer_len..BLOCK_LEN {
                self.buffer[i] = 0;
            }

            self.tmp_block.copy_from_slice(&self.buffer);
            self.compress();
            self.tmp_block.fast_zeroize();
            self.buffer.fast_zeroize();
            self.buffer_len = 0;
        }

        // Pad with zeros up to length field
        for i in self.buffer_len..BLOCK_LEN - 16 {
            self.buffer[i] = 0;
        }

        // Append 128-bit length in big-endian
        self.buffer[BLOCK_LEN - 16..BLOCK_LEN].copy_from_slice(&bit_len.to_be_bytes());

        self.tmp_block.copy_from_slice(&self.buffer);
        self.compress();
        self.tmp_block.fast_zeroize();

        // Output hash H(N)
        for (i, word) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.get().to_be_bytes());
        }
        // Drop zeroizes via MemZer derive
    }

    /// Compress one block per RFC 6234 Section 6.4.2
    fn compress(&mut self) {
        // ═══════════════════════════════════════════════════════════════════════
        // Step 1: Prepare message schedule W[0..79]
        // ═══════════════════════════════════════════════════════════════════════

        // W[0..15] from block (big-endian)
        for t in 0..16 {
            self.tmp_word
                .copy_from_slice(&self.tmp_block[t * 8..(t + 1) * 8]);
            self.w[t].set(u64::from_be_bytes(self.tmp_word));
            self.tmp_word.fast_zeroize();
        }

        // W[16..79]: W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
        for t in 16..80 {
            // W[t] = 0
            self.w[t].fast_zeroize();

            // + σ1(W[t-2])
            Word64::set_ssig1(&mut self.scratch, &self.w[t - 2]);
            self.w[t].wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + W[t-7]
            self.w[t].wrapping_add_assign_val(self.w[t - 7].get());

            // + σ0(W[t-15])
            Word64::set_ssig0(&mut self.scratch, &self.w[t - 15]);
            self.w[t].wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + W[t-16]
            self.w[t].wrapping_add_assign_val(self.w[t - 16].get());
        }

        // ═══════════════════════════════════════════════════════════════════════
        // Step 2: Initialize working variables with H(i-1)
        // ═══════════════════════════════════════════════════════════════════════
        self.wv_a.set(self.h[0].get());
        self.wv_b.set(self.h[1].get());
        self.wv_c.set(self.h[2].get());
        self.wv_d.set(self.h[3].get());
        self.wv_e.set(self.h[4].get());
        self.wv_f.set(self.h[5].get());
        self.wv_g.set(self.h[6].get());
        self.wv_h.set(self.h[7].get());

        // ═══════════════════════════════════════════════════════════════════════
        // Step 3: 80 rounds
        // ═══════════════════════════════════════════════════════════════════════
        for t in 0..80 {
            // T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
            self.t1.set(self.wv_h.get());

            // + Σ1(e)
            Word64::set_bsig1(&mut self.scratch, &self.wv_e);
            self.t1.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + Ch(e,f,g)
            Word64::set_ch(&mut self.scratch, &self.wv_e, &self.wv_f, &self.wv_g);
            self.t1.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + K[t]
            self.t1.wrapping_add_assign_val(K[t]);

            // + W[t]
            self.t1.wrapping_add_assign(&self.w[t]);

            // W[t] no longer needed - zeroize immediately
            self.w[t].fast_zeroize();

            // T2 = Σ0(a) + Maj(a,b,c)
            self.t2.fast_zeroize();

            // + Σ0(a)
            Word64::set_bsig0(&mut self.scratch, &self.wv_a);
            self.t2.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + Maj(a,b,c)
            Word64::set_maj(&mut self.scratch, &self.wv_a, &self.wv_b, &self.wv_c);
            self.t2.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // Rotate working variables: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
            self.wv_h.set(self.wv_g.get());
            self.wv_g.set(self.wv_f.get());
            self.wv_f.set(self.wv_e.get());
            self.wv_e.set(self.wv_d.get());
            self.wv_e.wrapping_add_assign(&self.t1);
            self.wv_d.set(self.wv_c.get());
            self.wv_c.set(self.wv_b.get());
            self.wv_b.set(self.wv_a.get());
            self.wv_a.set(self.t1.get());
            self.wv_a.wrapping_add_assign(&self.t2);

            // Zeroize T1, T2 after each round
            self.t1.fast_zeroize();
            self.t2.fast_zeroize();
        }

        // ═══════════════════════════════════════════════════════════════════════
        // Step 4: Compute H(i) = H(i-1) + working variables
        // ═══════════════════════════════════════════════════════════════════════
        self.h[0].wrapping_add_assign(&self.wv_a);
        self.wv_a.fast_zeroize();
        self.h[1].wrapping_add_assign(&self.wv_b);
        self.wv_b.fast_zeroize();
        self.h[2].wrapping_add_assign(&self.wv_c);
        self.wv_c.fast_zeroize();
        self.h[3].wrapping_add_assign(&self.wv_d);
        self.wv_d.fast_zeroize();
        self.h[4].wrapping_add_assign(&self.wv_e);
        self.wv_e.fast_zeroize();
        self.h[5].wrapping_add_assign(&self.wv_f);
        self.wv_f.fast_zeroize();
        self.h[6].wrapping_add_assign(&self.wv_g);
        self.wv_g.fast_zeroize();
        self.h[7].wrapping_add_assign(&self.wv_h);
        self.wv_h.fast_zeroize();
    }
}
