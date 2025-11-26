// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Minimal Poly1305 implementation with guaranteed zeroization.
//!
//! Implements the Poly1305 one-time authenticator (RFC 8439).
//! All sensitive state is zeroized on drop using memzer.

use memzer::{DropSentinel, MemZer};
use zeroize::Zeroize;

use crate::consts::{BLOCK_SIZE, KEY_SIZE, TAG_SIZE};

/// Work variables for block processing.
#[derive(Default, Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Poly1305Block {
    t: [u32; 4],
    s: [u64; 4],
    d: [u64; 5],
    tmp: [u8; 16],
    __drop_sentinel: DropSentinel,
}

/// Work variables for finalization.
#[derive(Default, Zeroize, MemZer)]
#[zeroize(drop)]
pub(crate) struct Poly1305Final {
    d: [u64; 5], // reduced accumulator
    g: [u64; 4], // h + 5 for comparison
    h: [u64; 4], // h0-h3 for tag
    mask: u64,
    __drop_sentinel: DropSentinel,
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
        self.clamp_r(&key[0..16]);
        self.s.copy_from_slice(&key[16..32]);
    }

    fn clamp_r(&mut self, r_bytes: &[u8]) {
        self.block.t[0] =
            u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3] & 0x0f]);
        self.block.t[1] =
            u32::from_le_bytes([r_bytes[4] & 0xfc, r_bytes[5], r_bytes[6], r_bytes[7] & 0x0f]);
        self.block.t[2] = u32::from_le_bytes([
            r_bytes[8] & 0xfc,
            r_bytes[9],
            r_bytes[10],
            r_bytes[11] & 0x0f,
        ]);
        self.block.t[3] = u32::from_le_bytes([
            r_bytes[12] & 0xfc,
            r_bytes[13],
            r_bytes[14],
            r_bytes[15] & 0x0f,
        ]);

        self.r[0] = self.block.t[0] & 0x3ffffff;
        self.r[1] = ((self.block.t[0] >> 26) | (self.block.t[1] << 6)) & 0x3ffffff;
        self.r[2] = ((self.block.t[1] >> 20) | (self.block.t[2] << 12)) & 0x3ffffff;
        self.r[3] = ((self.block.t[2] >> 14) | (self.block.t[3] << 18)) & 0x3ffffff;
        self.r[4] = self.block.t[3] >> 8;

        self.block.zeroize();
    }

    fn process_block(&mut self, block: &[u8], hibit: u32) {
        self.block.tmp.copy_from_slice(block);
        self.process_block_from_tmp(hibit);
    }

    fn process_block_from_tmp(&mut self, hibit: u32) {
        self.block.t[0] = u32::from_le_bytes([
            self.block.tmp[0],
            self.block.tmp[1],
            self.block.tmp[2],
            self.block.tmp[3],
        ]);
        self.block.t[1] = u32::from_le_bytes([
            self.block.tmp[4],
            self.block.tmp[5],
            self.block.tmp[6],
            self.block.tmp[7],
        ]);
        self.block.t[2] = u32::from_le_bytes([
            self.block.tmp[8],
            self.block.tmp[9],
            self.block.tmp[10],
            self.block.tmp[11],
        ]);
        self.block.t[3] = u32::from_le_bytes([
            self.block.tmp[12],
            self.block.tmp[13],
            self.block.tmp[14],
            self.block.tmp[15],
        ]);

        self.acc[0] += (self.block.t[0] & 0x3ffffff) as u64;
        self.acc[1] += (((self.block.t[0] >> 26) | (self.block.t[1] << 6)) & 0x3ffffff) as u64;
        self.acc[2] += (((self.block.t[1] >> 20) | (self.block.t[2] << 12)) & 0x3ffffff) as u64;
        self.acc[3] += (((self.block.t[2] >> 14) | (self.block.t[3] << 18)) & 0x3ffffff) as u64;
        self.acc[4] += ((self.block.t[3] >> 8) | (hibit << 24)) as u64;

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
        let g4 = self.finalize.d[4] + (self.finalize.g[3] >> 26);
        self.finalize.g[3] &= 0x3ffffff;

        // mask = all 1s if NO overflow (use h), all 0s if overflow (use g)
        self.finalize.mask = (g4 >> 26).wrapping_sub(1);

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
        self.finalize.h[0] = self.finalize.d[0] | ((self.finalize.d[1] & 0x3f) << 26);
        self.finalize.h[1] = (self.finalize.d[1] >> 6) | ((self.finalize.d[2] & 0xfff) << 20);
        self.finalize.h[2] = (self.finalize.d[2] >> 12) | ((self.finalize.d[3] & 0x3ffff) << 14);
        self.finalize.h[3] = (self.finalize.d[3] >> 18) | ((self.finalize.d[4] & 0xffffff) << 8);

        // Add s with carry propagation
        self.finalize.h[0] +=
            u32::from_le_bytes([self.s[0], self.s[1], self.s[2], self.s[3]]) as u64;
        self.finalize.h[1] += u32::from_le_bytes([self.s[4], self.s[5], self.s[6], self.s[7]])
            as u64
            + (self.finalize.h[0] >> 32);
        self.finalize.h[0] &= 0xffffffff;
        self.finalize.h[2] += u32::from_le_bytes([self.s[8], self.s[9], self.s[10], self.s[11]])
            as u64
            + (self.finalize.h[1] >> 32);
        self.finalize.h[1] &= 0xffffffff;
        self.finalize.h[3] += u32::from_le_bytes([self.s[12], self.s[13], self.s[14], self.s[15]])
            as u64
            + (self.finalize.h[2] >> 32);
        self.finalize.h[2] &= 0xffffffff;
        self.finalize.h[3] &= 0xffffffff;

        // Write tag
        output[0..4].copy_from_slice(&(self.finalize.h[0] as u32).to_le_bytes());
        output[4..8].copy_from_slice(&(self.finalize.h[1] as u32).to_le_bytes());
        output[8..12].copy_from_slice(&(self.finalize.h[2] as u32).to_le_bytes());
        output[12..16].copy_from_slice(&(self.finalize.h[3] as u32).to_le_bytes());

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
