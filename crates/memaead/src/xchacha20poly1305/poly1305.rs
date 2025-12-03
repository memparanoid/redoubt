// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Minimal Poly1305 implementation with guaranteed zeroization.
//!
//! Implements the Poly1305 one-time authenticator (RFC 8439).
//! All sensitive state is zeroized on drop using memzer.

use zeroize::Zeroize;

use memutil::{u32_from_le, u32_to_le};
use memzer::{DropSentinel, MemZer};

use super::consts::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

/// Work variables for block processing.
#[derive(Default, Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Poly1305Block {
    t: [u32; 4],
    s: [u64; 4],
    d: [u64; 5],
    tmp: [u8; 16],
    le_bytes_tmp: [u8; 4],
    shifting_tmp_a: u32,
    shifting_tmp_b: u32,
    __drop_sentinel: DropSentinel,
}

impl core::fmt::Debug for Poly1305Block {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Poly1305Block {{ [protected] }}")
    }
}

/// Work variables for finalization.
#[derive(Default, Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Poly1305Final {
    d: [u64; 5], // reduced accumulator
    g: [u64; 4], // h + 5 for comparison
    h: [u64; 4], // h0-h3 for tag
    g4: u64,     // overflow check
    mask: u64,
    shifting_tmp_a: u64,
    shifting_tmp_b: u64,
    le_bytes_tmp: [u8; 4],
    s_u32: u32,
    __drop_sentinel: DropSentinel,
}

impl core::fmt::Debug for Poly1305Final {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Poly1305Final {{ [protected] }}")
    }
}

/// Poly1305 authenticator state.
#[derive(Default, Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Poly1305 {
    r: [u32; 5],
    s: [u8; 16],
    acc: [u64; 5],
    buffer: [u8; 16],
    buffer_len: usize,
    block: Poly1305Block,
    finalize: Poly1305Final,
    __drop_sentinel: DropSentinel,
}

impl Poly1305 {
    pub fn init(&mut self, key: &[u8; KEY_SIZE]) {
        self.acc = [0; 5];
        self.buffer_len = 0;
        self.clamp_r(&key[0..16]);
        self.s.copy_from_slice(&key[16..32]);
    }

    fn clamp_r(&mut self, r_bytes: &[u8]) {
        self.block.le_bytes_tmp[0] = r_bytes[0];
        self.block.le_bytes_tmp[1] = r_bytes[1];
        self.block.le_bytes_tmp[2] = r_bytes[2];
        self.block.le_bytes_tmp[3] = r_bytes[3] & 0x0f;
        u32_from_le(&mut self.block.t[0], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = r_bytes[4] & 0xfc;
        self.block.le_bytes_tmp[1] = r_bytes[5];
        self.block.le_bytes_tmp[2] = r_bytes[6];
        self.block.le_bytes_tmp[3] = r_bytes[7] & 0x0f;
        u32_from_le(&mut self.block.t[1], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = r_bytes[8] & 0xfc;
        self.block.le_bytes_tmp[1] = r_bytes[9];
        self.block.le_bytes_tmp[2] = r_bytes[10];
        self.block.le_bytes_tmp[3] = r_bytes[11] & 0x0f;
        u32_from_le(&mut self.block.t[2], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = r_bytes[12] & 0xfc;
        self.block.le_bytes_tmp[1] = r_bytes[13];
        self.block.le_bytes_tmp[2] = r_bytes[14];
        self.block.le_bytes_tmp[3] = r_bytes[15] & 0x0f;
        u32_from_le(&mut self.block.t[3], &mut self.block.le_bytes_tmp);

        self.r[0] = self.block.t[0] & 0x3ffffff;

        self.block.shifting_tmp_a = self.block.t[0] >> 26;
        self.block.shifting_tmp_b = self.block.t[1] << 6;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.r[1] = self.block.shifting_tmp_a & 0x3ffffff;

        self.block.shifting_tmp_a = self.block.t[1] >> 20;
        self.block.shifting_tmp_b = self.block.t[2] << 12;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.r[2] = self.block.shifting_tmp_a & 0x3ffffff;

        self.block.shifting_tmp_a = self.block.t[2] >> 14;
        self.block.shifting_tmp_b = self.block.t[3] << 18;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.r[3] = self.block.shifting_tmp_a & 0x3ffffff;

        self.r[4] = self.block.t[3] >> 8;

        self.block.zeroize();
    }

    fn process_block(&mut self, block: &[u8], hibit: u32) {
        self.block.tmp.copy_from_slice(block);
        self.process_block_from_tmp(hibit);
    }

    fn process_block_from_tmp(&mut self, hibit: u32) {
        self.block.le_bytes_tmp[0] = self.block.tmp[0];
        self.block.le_bytes_tmp[1] = self.block.tmp[1];
        self.block.le_bytes_tmp[2] = self.block.tmp[2];
        self.block.le_bytes_tmp[3] = self.block.tmp[3];
        u32_from_le(&mut self.block.t[0], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = self.block.tmp[4];
        self.block.le_bytes_tmp[1] = self.block.tmp[5];
        self.block.le_bytes_tmp[2] = self.block.tmp[6];
        self.block.le_bytes_tmp[3] = self.block.tmp[7];
        u32_from_le(&mut self.block.t[1], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = self.block.tmp[8];
        self.block.le_bytes_tmp[1] = self.block.tmp[9];
        self.block.le_bytes_tmp[2] = self.block.tmp[10];
        self.block.le_bytes_tmp[3] = self.block.tmp[11];
        u32_from_le(&mut self.block.t[2], &mut self.block.le_bytes_tmp);

        self.block.le_bytes_tmp[0] = self.block.tmp[12];
        self.block.le_bytes_tmp[1] = self.block.tmp[13];
        self.block.le_bytes_tmp[2] = self.block.tmp[14];
        self.block.le_bytes_tmp[3] = self.block.tmp[15];
        u32_from_le(&mut self.block.t[3], &mut self.block.le_bytes_tmp);

        self.acc[0] += (self.block.t[0] & 0x3ffffff) as u64;

        self.block.shifting_tmp_a = self.block.t[0] >> 26;
        self.block.shifting_tmp_b = self.block.t[1] << 6;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.acc[1] += (self.block.shifting_tmp_a & 0x3ffffff) as u64;

        self.block.shifting_tmp_a = self.block.t[1] >> 20;
        self.block.shifting_tmp_b = self.block.t[2] << 12;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.acc[2] += (self.block.shifting_tmp_a & 0x3ffffff) as u64;

        self.block.shifting_tmp_a = self.block.t[2] >> 14;
        self.block.shifting_tmp_b = self.block.t[3] << 18;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.acc[3] += (self.block.shifting_tmp_a & 0x3ffffff) as u64;

        self.block.shifting_tmp_a = self.block.t[3] >> 8;
        self.block.shifting_tmp_b = hibit << 24;
        self.block.shifting_tmp_a |= self.block.shifting_tmp_b;
        self.acc[4] += self.block.shifting_tmp_a as u64;

        self.block.s[0] = (self.r[1] as u64) * 5;
        self.block.s[1] = (self.r[2] as u64) * 5;
        self.block.s[2] = (self.r[3] as u64) * 5;
        self.block.s[3] = (self.r[4] as u64) * 5;

        self.block.d[0] = self.acc[0] * (self.r[0] as u64)
            + self.acc[1] * self.block.s[3]
            + self.acc[2] * self.block.s[2]
            + self.acc[3] * self.block.s[1]
            + self.acc[4] * self.block.s[0];
        self.block.d[1] = self.acc[0] * (self.r[1] as u64)
            + self.acc[1] * (self.r[0] as u64)
            + self.acc[2] * self.block.s[3]
            + self.acc[3] * self.block.s[2]
            + self.acc[4] * self.block.s[1];
        self.block.d[2] = self.acc[0] * (self.r[2] as u64)
            + self.acc[1] * (self.r[1] as u64)
            + self.acc[2] * (self.r[0] as u64)
            + self.acc[3] * self.block.s[3]
            + self.acc[4] * self.block.s[2];
        self.block.d[3] = self.acc[0] * (self.r[3] as u64)
            + self.acc[1] * (self.r[2] as u64)
            + self.acc[2] * (self.r[1] as u64)
            + self.acc[3] * (self.r[0] as u64)
            + self.acc[4] * self.block.s[3];
        self.block.d[4] = self.acc[0] * (self.r[4] as u64)
            + self.acc[1] * (self.r[3] as u64)
            + self.acc[2] * (self.r[2] as u64)
            + self.acc[3] * (self.r[1] as u64)
            + self.acc[4] * (self.r[0] as u64);

        self.block.d[1] += self.block.d[0] >> 26;
        self.block.d[0] &= 0x3ffffff;
        self.block.d[2] += self.block.d[1] >> 26;
        self.block.d[1] &= 0x3ffffff;
        self.block.d[3] += self.block.d[2] >> 26;
        self.block.d[2] &= 0x3ffffff;
        self.block.d[4] += self.block.d[3] >> 26;
        self.block.d[3] &= 0x3ffffff;
        self.block.d[0] += (self.block.d[4] >> 26) * 5;
        self.block.d[4] &= 0x3ffffff;
        self.block.d[1] += self.block.d[0] >> 26;
        self.block.d[0] &= 0x3ffffff;

        self.acc[0] = self.block.d[0];
        self.acc[1] = self.block.d[1];
        self.acc[2] = self.block.d[2];
        self.acc[3] = self.block.d[3];
        self.acc[4] = self.block.d[4];

        self.block.zeroize();
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = core::cmp::min(need, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            pos = take;

            if self.buffer_len == BLOCK_SIZE {
                self.block.tmp.copy_from_slice(&self.buffer);
                self.buffer.zeroize();
                self.buffer_len = 0;
                self.process_block_from_tmp(1);
            }
        }

        while pos + BLOCK_SIZE <= data.len() {
            self.process_block(&data[pos..pos + BLOCK_SIZE], 1);
            pos += BLOCK_SIZE;
        }

        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_len = remaining;
        }
    }

    /// Update with data and pad to 16-byte boundary with zeros (RFC 8439 AEAD)
    pub fn update_padded(&mut self, data: &[u8]) {
        self.update(data);
        let pad_len = (BLOCK_SIZE - (data.len() % BLOCK_SIZE)) % BLOCK_SIZE;
        if pad_len > 0 {
            self.update(&[0u8; BLOCK_SIZE][..pad_len]);
        }
    }

    pub fn finalize(&mut self, output: &mut [u8; TAG_SIZE]) {
        // Process remaining buffered bytes with padding
        if self.buffer_len > 0 {
            // Zero pad then set 0x01 marker after data
            for i in (self.buffer_len + 1)..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            self.buffer[self.buffer_len] = 0x01;
            self.block.tmp.copy_from_slice(&self.buffer);
            self.buffer.zeroize();
            self.buffer_len = 0;
            self.process_block_from_tmp(0); // hibit=0 for partial block
        }

        // Copy accumulator to work area
        self.finalize.d[0] = self.acc[0];
        self.finalize.d[1] = self.acc[1];
        self.finalize.d[2] = self.acc[2];
        self.finalize.d[3] = self.acc[3];
        self.finalize.d[4] = self.acc[4];

        // Full carry propagation
        self.finalize.d[1] += self.finalize.d[0] >> 26;
        self.finalize.d[0] &= 0x3ffffff;
        self.finalize.d[2] += self.finalize.d[1] >> 26;
        self.finalize.d[1] &= 0x3ffffff;
        self.finalize.d[3] += self.finalize.d[2] >> 26;
        self.finalize.d[2] &= 0x3ffffff;
        self.finalize.d[4] += self.finalize.d[3] >> 26;
        self.finalize.d[3] &= 0x3ffffff;

        // Reduce: if d[4] overflows, reduce mod 2^130-5
        self.finalize.d[0] += (self.finalize.d[4] >> 26) * 5;
        self.finalize.d[4] &= 0x3ffffff;

        // One more carry after reduction
        self.finalize.d[1] += self.finalize.d[0] >> 26;
        self.finalize.d[0] &= 0x3ffffff;

        // Compute h + 5
        self.finalize.g[0] = self.finalize.d[0] + 5;
        self.finalize.g[1] = self.finalize.d[1] + (self.finalize.g[0] >> 26);
        self.finalize.g[0] &= 0x3ffffff;
        self.finalize.g[2] = self.finalize.d[2] + (self.finalize.g[1] >> 26);
        self.finalize.g[1] &= 0x3ffffff;
        self.finalize.g[3] = self.finalize.d[3] + (self.finalize.g[2] >> 26);
        self.finalize.g[2] &= 0x3ffffff;

        // If (d[4] + carry from g[3]) overflows, h >= 2^130-5
        self.finalize.g4 = self.finalize.d[4] + (self.finalize.g[3] >> 26);
        self.finalize.g[3] &= 0x3ffffff;

        // mask = all 1s if NO overflow (use h), all 0s if overflow (use g)
        self.finalize.mask = (self.finalize.g4 >> 26).wrapping_sub(1);

        // Select h (mask=1s) or g (mask=0s)
        self.finalize.d[0] =
            (self.finalize.d[0] & self.finalize.mask) | (self.finalize.g[0] & !self.finalize.mask);
        self.finalize.d[1] =
            (self.finalize.d[1] & self.finalize.mask) | (self.finalize.g[1] & !self.finalize.mask);
        self.finalize.d[2] =
            (self.finalize.d[2] & self.finalize.mask) | (self.finalize.g[2] & !self.finalize.mask);
        self.finalize.d[3] =
            (self.finalize.d[3] & self.finalize.mask) | (self.finalize.g[3] & !self.finalize.mask);
        // d[4] is zeroed if overflow (g has no 5th limb)
        self.finalize.d[4] &= self.finalize.mask;

        // Convert radix 2^26 to 4x32-bit
        // Map 130-bit N = sum(d[i]*2^(26i)) to h[0..3] where h[i] = bits 32i..32i+31 of N
        // Mask each d contribution so h[i] is exactly 32 bits (no overflow)
        self.finalize.shifting_tmp_a = self.finalize.d[1] & 0x3f;
        self.finalize.shifting_tmp_a <<= 26;
        self.finalize.h[0] = self.finalize.d[0] | self.finalize.shifting_tmp_a;

        self.finalize.shifting_tmp_a = self.finalize.d[1] >> 6;
        self.finalize.shifting_tmp_b = self.finalize.d[2] & 0xfff;
        self.finalize.shifting_tmp_b <<= 20;
        self.finalize.h[1] = self.finalize.shifting_tmp_a | self.finalize.shifting_tmp_b;

        self.finalize.shifting_tmp_a = self.finalize.d[2] >> 12;
        self.finalize.shifting_tmp_b = self.finalize.d[3] & 0x3ffff;
        self.finalize.shifting_tmp_b <<= 14;
        self.finalize.h[2] = self.finalize.shifting_tmp_a | self.finalize.shifting_tmp_b;

        self.finalize.shifting_tmp_a = self.finalize.d[3] >> 18;
        self.finalize.shifting_tmp_b = self.finalize.d[4] & 0xffffff;
        self.finalize.shifting_tmp_b <<= 8;
        self.finalize.h[3] = self.finalize.shifting_tmp_a | self.finalize.shifting_tmp_b;

        // Add s with carry propagation
        self.finalize.le_bytes_tmp[0] = self.s[0];
        self.finalize.le_bytes_tmp[1] = self.s[1];
        self.finalize.le_bytes_tmp[2] = self.s[2];
        self.finalize.le_bytes_tmp[3] = self.s[3];
        u32_from_le(&mut self.finalize.s_u32, &mut self.finalize.le_bytes_tmp);
        self.finalize.h[0] += self.finalize.s_u32 as u64;

        self.finalize.le_bytes_tmp[0] = self.s[4];
        self.finalize.le_bytes_tmp[1] = self.s[5];
        self.finalize.le_bytes_tmp[2] = self.s[6];
        self.finalize.le_bytes_tmp[3] = self.s[7];
        u32_from_le(&mut self.finalize.s_u32, &mut self.finalize.le_bytes_tmp);
        self.finalize.h[1] += self.finalize.s_u32 as u64 + (self.finalize.h[0] >> 32);
        self.finalize.h[0] &= 0xffffffff;

        self.finalize.le_bytes_tmp[0] = self.s[8];
        self.finalize.le_bytes_tmp[1] = self.s[9];
        self.finalize.le_bytes_tmp[2] = self.s[10];
        self.finalize.le_bytes_tmp[3] = self.s[11];
        u32_from_le(&mut self.finalize.s_u32, &mut self.finalize.le_bytes_tmp);
        self.finalize.h[2] += self.finalize.s_u32 as u64 + (self.finalize.h[1] >> 32);
        self.finalize.h[1] &= 0xffffffff;

        self.finalize.le_bytes_tmp[0] = self.s[12];
        self.finalize.le_bytes_tmp[1] = self.s[13];
        self.finalize.le_bytes_tmp[2] = self.s[14];
        self.finalize.le_bytes_tmp[3] = self.s[15];
        u32_from_le(&mut self.finalize.s_u32, &mut self.finalize.le_bytes_tmp);
        self.finalize.h[3] += self.finalize.s_u32 as u64 + (self.finalize.h[2] >> 32);
        self.finalize.h[2] &= 0xffffffff;
        self.finalize.h[3] &= 0xffffffff;

        // Write tag
        self.finalize.s_u32 = self.finalize.h[0] as u32;
        u32_to_le(
            &mut self.finalize.s_u32,
            (&mut output[0..4])
                .try_into()
                .expect("infallible: output[0..4] is exactly 4 bytes"),
        );
        self.finalize.s_u32 = self.finalize.h[1] as u32;
        u32_to_le(
            &mut self.finalize.s_u32,
            (&mut output[4..8])
                .try_into()
                .expect("infallible: output[4..8] is exactly 4 bytes"),
        );
        self.finalize.s_u32 = self.finalize.h[2] as u32;
        u32_to_le(
            &mut self.finalize.s_u32,
            (&mut output[8..12])
                .try_into()
                .expect("infallible: output[8..12] is exactly 4 bytes"),
        );
        self.finalize.s_u32 = self.finalize.h[3] as u32;
        u32_to_le(
            &mut self.finalize.s_u32,
            (&mut output[12..16])
                .try_into()
                .expect("infallible: output[12..16] is exactly 4 bytes"),
        );

        self.finalize.zeroize();
    }

    #[cfg(test)]
    pub fn compute(key: &[u8; KEY_SIZE], data: &[u8], output: &mut [u8; TAG_SIZE]) {
        let mut state = Self::default();
        state.init(key);
        state.update(data);
        state.finalize(output);
        state.zeroize();
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Poly1305 {{ [protected] }}")
    }
}
