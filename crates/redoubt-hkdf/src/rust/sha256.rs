// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! SHA-256 implementation per RFC 6234 Section 6.2

use redoubt_zero::{FastZeroizable, RedoubtZero, ZeroizeOnDropSentinel};

use super::word32::Word32;

/// SHA-256 constants K per RFC 6234 Section 5.1
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash values H(0) per RFC 6234 Section 6.2.1
/// First 32 bits of fractional parts of square roots of first 8 primes
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLOCK_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// SHA-256 streaming state per RFC 6234 Section 6.2
///
/// All sensitive working variables live in the struct for guaranteed zeroization.
#[derive(RedoubtZero)]
#[fast_zeroize(drop)]
pub(crate) struct Sha256State {
    // Hash state H(i) per RFC 6234 Section 6.2.1
    h: [Word32; 8],

    // Message schedule W[0..63]
    w: [Word32; 64],

    // Working variables per RFC 6234 Section 6.2.2
    wv: [Word32; 8],

    // Temporaries
    t1: Word32,
    t2: Word32,
    scratch: Word32,
    w_tmp: Word32,

    // Input buffering
    buffer: [u8; BLOCK_LEN],
    tmp_block: [u8; BLOCK_LEN],
    tmp_word: [u8; 4],
    buffer_len: usize,
    total_len: u64,

    __sentinel: ZeroizeOnDropSentinel,
}

impl Sha256State {
    /// Create new SHA-256 state initialized with H(0)
    pub fn new() -> Self {
        Self {
            h: [
                Word32::new(H0[0]),
                Word32::new(H0[1]),
                Word32::new(H0[2]),
                Word32::new(H0[3]),
                Word32::new(H0[4]),
                Word32::new(H0[5]),
                Word32::new(H0[6]),
                Word32::new(H0[7]),
            ],
            w: core::array::from_fn(|_| Word32::zero()),
            wv: core::array::from_fn(|_| Word32::zero()),
            t1: Word32::zero(),
            t2: Word32::zero(),
            scratch: Word32::zero(),
            w_tmp: Word32::zero(),
            buffer: [0u8; BLOCK_LEN],
            tmp_block: [0u8; BLOCK_LEN],
            tmp_word: [0u8; 4],
            buffer_len: 0,
            total_len: 0,
            __sentinel: ZeroizeOnDropSentinel::default(),
        }
    }

    /// SHA-256 compression function (single block)
    ///
    /// Updates hash state H with a single 512-bit message block.
    ///
    /// # Arguments
    /// * `h` - Hash state (8 × u32, input/output)
    /// * `block` - Message block (64 bytes)
    #[cfg(test)]
    pub fn compress_block(&mut self, h: &mut [u32; 8], block: &[u8; 64]) {
        // Initialize working variables with H
        // SAFETY: Word32 is repr(transparent) over u32, same layout
        unsafe {
            core::ptr::copy_nonoverlapping(
                h.as_ptr(),
                &mut self.wv as *mut [Word32; 8] as *mut u32,
                8,
            );
        }

        // Copy block
        self.tmp_block.copy_from_slice(block);

        // Compress (updates self.wv)
        self.compress();

        // H = H + working variables (take zeroizes wv automatically)
        for i in 0..8 {
            h[i] = h[i].wrapping_add(core::mem::take(self.wv[i].as_mut_u32()));
        }
    }

    /// Compress internal - per RFC 6234 Section 6.2.2
    fn compress(&mut self) {
        // Step 1: Prepare message schedule W[0..63]
        // W[0..15] from block (big-endian)
        for t in 0..16 {
            self.tmp_word
                .copy_from_slice(&self.tmp_block[t * 4..(t + 1) * 4]);
            self.w[t].fill_with_be_bytes(&mut self.tmp_word);
        }

        // W[16..63]: W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
        for t in 16..64 {
            self.w[t].fast_zeroize();

            // + σ1(W[t-2])
            Word32::set_ssig1(&mut self.scratch, &self.w[t - 2]);
            self.w[t].wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + W[t-7]
            self.w_tmp.copy_from(&self.w[t - 7]);
            self.w[t].wrapping_add_assign(&self.w_tmp);
            self.w_tmp.fast_zeroize();

            // + σ0(W[t-15])
            Word32::set_ssig0(&mut self.scratch, &self.w[t - 15]);
            self.w[t].wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + W[t-16]
            self.w_tmp.copy_from(&self.w[t - 16]);
            self.w[t].wrapping_add_assign(&self.w_tmp);
            self.w_tmp.fast_zeroize();
        }

        // Step 3: 64 rounds
        for (k, wt) in K256.iter().zip(self.w.iter_mut()) {
            // T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
            self.t1.copy_from(&self.wv[7]);

            // + Σ1(e)
            Word32::set_bsig1(&mut self.scratch, &self.wv[4]);
            self.t1.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + Ch(e,f,g)
            Word32::set_ch(&mut self.scratch, &self.wv[4], &self.wv[5], &self.wv[6]);
            self.t1.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + K[t]
            self.t1.wrapping_add_assign_val(*k);

            // + W[t]
            self.t1.wrapping_add_assign(wt);

            // W[t] no longer needed
            wt.fast_zeroize();

            // T2 = Σ0(a) + Maj(a,b,c)
            self.t2.fast_zeroize();

            // + Σ0(a)
            Word32::set_bsig0(&mut self.scratch, &self.wv[0]);
            self.t2.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // + Maj(a,b,c)
            Word32::set_maj(&mut self.scratch, &self.wv[0], &self.wv[1], &self.wv[2]);
            self.t2.wrapping_add_assign(&self.scratch);
            self.scratch.fast_zeroize();

            // Rotate working variables: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
            self.w_tmp.copy_from(&self.wv[6]);
            self.wv[7].copy_from(&self.w_tmp);

            self.w_tmp.copy_from(&self.wv[5]);
            self.wv[6].copy_from(&self.w_tmp);

            self.w_tmp.copy_from(&self.wv[4]);
            self.wv[5].copy_from(&self.w_tmp);

            self.w_tmp.copy_from(&self.wv[3]);
            self.wv[4].copy_from(&self.w_tmp);
            self.wv[4].wrapping_add_assign(&self.t1);

            self.w_tmp.copy_from(&self.wv[2]);
            self.wv[3].copy_from(&self.w_tmp);

            self.w_tmp.copy_from(&self.wv[1]);
            self.wv[2].copy_from(&self.w_tmp);

            self.w_tmp.copy_from(&self.wv[0]);
            self.wv[1].copy_from(&self.w_tmp);

            self.wv[0].copy_from(&self.t1);
            self.wv[0].wrapping_add_assign(&self.t2);

            // Zeroize temporaries
            self.w_tmp.fast_zeroize();
            self.t1.fast_zeroize();
            self.t2.fast_zeroize();
        }
    }

    /// Compress one block (internal - works on self.h)
    fn compress_internal(&mut self) {
        // Initialize wv from h
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.h as *const [Word32; 8] as *const u32,
                &mut self.wv as *mut [Word32; 8] as *mut u32,
                8,
            );
        }

        // Compress (processes wv using tmp_block)
        self.compress();

        // h += wv (using take to zeroize wv)
        for i in 0..8 {
            let wv_val = core::mem::take(self.wv[i].as_mut_u32());
            *self.h[i].as_mut_u32() = self.h[i].as_mut_u32().wrapping_add(wv_val);
        }
    }

    /// Update state with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

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
                self.compress_internal();
                self.tmp_block.fast_zeroize();
                self.buffer.fast_zeroize();
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + BLOCK_LEN <= data.len() {
            self.tmp_block
                .copy_from_slice(&data[offset..offset + BLOCK_LEN]);
            self.compress_internal();
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
    pub fn finalize(&mut self, out: &mut [u8; HASH_LEN]) {
        // Padding per RFC 6234 Section 4.1
        let bit_len = self.total_len * 8;

        // Append 0x80 (1 bit followed by zeros)
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for 64-bit length, pad and compress
        if self.buffer_len > BLOCK_LEN - 8 {
            for i in self.buffer_len..BLOCK_LEN {
                self.buffer[i] = 0;
            }

            self.tmp_block.copy_from_slice(&self.buffer);
            self.compress_internal();
            self.tmp_block.fast_zeroize();
            self.buffer.fast_zeroize();
            self.buffer_len = 0;
        }

        // Pad with zeros up to length field
        for i in self.buffer_len..BLOCK_LEN - 8 {
            self.buffer[i] = 0;
        }

        // Append 64-bit length in big-endian
        self.buffer[BLOCK_LEN - 8..BLOCK_LEN].copy_from_slice(&bit_len.to_be_bytes());

        self.tmp_block.copy_from_slice(&self.buffer);
        self.compress_internal();
        self.tmp_block.fast_zeroize();

        // Output hash H(N)
        for (i, word) in self.h.iter_mut().enumerate() {
            word.export_as_be_bytes(&mut self.tmp_word);
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.tmp_word);
        }
    }

    /// Reset to H(0) for reuse
    pub fn reset(&mut self) {
        self.fast_zeroize();
        self.h[0] = Word32::new(H0[0]);
        self.h[1] = Word32::new(H0[1]);
        self.h[2] = Word32::new(H0[2]);
        self.h[3] = Word32::new(H0[3]);
        self.h[4] = Word32::new(H0[4]);
        self.h[5] = Word32::new(H0[5]);
        self.h[6] = Word32::new(H0[6]);
        self.h[7] = Word32::new(H0[7]);
    }

    /// Hash complete message (convenience method -- test only)
    #[cfg(test)]
    pub fn hash(&mut self, data: &[u8], out: &mut [u8; HASH_LEN]) {
        self.update(data);
        self.finalize(out);
        self.fast_zeroize();
    }
}
