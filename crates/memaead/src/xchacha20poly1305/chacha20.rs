// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! ChaCha20 stream cipher implementation (RFC 8439)
//!
//! All sensitive state is zeroized on drop using memzer.

use memutil::{u32_from_le, u32_to_le};
use memzer::{DropSentinel, FastZeroizable, MemZer};

use super::consts::{
    CHACHA20_BLOCK_SIZE, CHACHA20_NONCE_SIZE, HCHACHA20_NONCE_SIZE, KEY_SIZE, XNONCE_SIZE,
};
use super::types::{AeadKey, XNonce};

/// ChaCha20 cipher state with guaranteed zeroization.
#[derive(MemZer)]
#[memzer(drop)]
pub(crate) struct ChaCha20 {
    initial: [u32; 16],
    working: [u32; 16],
    le_bytes_tmp: [u8; 4],
    keystream: [u8; CHACHA20_BLOCK_SIZE],
    // Temporaries for fallback quarter_round (zeroized on drop)
    qr_a: u32,
    qr_b: u32,
    qr_c: u32,
    qr_d: u32,
    __drop_sentinel: DropSentinel,
}

impl Default for ChaCha20 {
    fn default() -> Self {
        Self {
            initial: [0; 16],
            working: [0; 16],
            le_bytes_tmp: [0; 4],
            keystream: [0; CHACHA20_BLOCK_SIZE],
            qr_a: 0,
            qr_b: 0,
            qr_c: 0,
            qr_d: 0,
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl ChaCha20 {
    #[inline(always)]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            super::asm::x86_64::quarter_round(&mut self.working, a, b, c, d);
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            super::asm::aarch64::quarter_round(&mut self.working, a, b, c, d);
        }

        // Full Rust implementation as fallback (uses struct temporaries for zeroization)
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.qr_a = self.working[a];
            self.qr_b = self.working[b];
            self.qr_c = self.working[c];
            self.qr_d = self.working[d];

            self.qr_a = self.qr_a.wrapping_add(self.qr_b);
            self.qr_d ^= self.qr_a;
            self.qr_d = self.qr_d.rotate_left(16);

            self.qr_c = self.qr_c.wrapping_add(self.qr_d);
            self.qr_b ^= self.qr_c;
            self.qr_b = self.qr_b.rotate_left(12);

            self.qr_a = self.qr_a.wrapping_add(self.qr_b);
            self.qr_d ^= self.qr_a;
            self.qr_d = self.qr_d.rotate_left(8);

            self.qr_c = self.qr_c.wrapping_add(self.qr_d);
            self.qr_b ^= self.qr_c;
            self.qr_b = self.qr_b.rotate_left(7);

            self.working[a] = self.qr_a;
            self.working[b] = self.qr_b;
            self.working[c] = self.qr_c;
            self.working[d] = self.qr_d;
        }
    }

    #[inline(always)]
    fn init_state(
        &mut self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        counter: u32,
    ) {
        self.initial[0] = 0x61707865;
        self.initial[1] = 0x3320646e;
        self.initial[2] = 0x79622d32;
        self.initial[3] = 0x6b206574;

        for i in 0..8 {
            self.le_bytes_tmp[0] = key[i * 4];
            self.le_bytes_tmp[1] = key[i * 4 + 1];
            self.le_bytes_tmp[2] = key[i * 4 + 2];
            self.le_bytes_tmp[3] = key[i * 4 + 3];
            u32_from_le(&mut self.initial[4 + i], &mut self.le_bytes_tmp);
        }

        self.initial[12] = counter;

        for i in 0..3 {
            self.le_bytes_tmp[0] = nonce[i * 4];
            self.le_bytes_tmp[1] = nonce[i * 4 + 1];
            self.le_bytes_tmp[2] = nonce[i * 4 + 2];
            self.le_bytes_tmp[3] = nonce[i * 4 + 3];
            u32_from_le(&mut self.initial[13 + i], &mut self.le_bytes_tmp);
        }
    }

    #[inline(always)]
    fn do_rounds(&mut self) {
        for _ in 0..10 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);

            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }
    }

    /// Generate keystream block into self.keystream
    #[inline(always)]
    fn generate_block(
        &mut self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        counter: u32,
    ) {
        self.init_state(key, nonce, counter);
        self.working.copy_from_slice(&self.initial);

        self.do_rounds();

        for i in 0..16 {
            self.working[i] = self.working[i].wrapping_add(self.initial[i]);
            u32_to_le(
                &mut self.working[i],
                (&mut self.keystream[i * 4..i * 4 + 4])
                    .try_into()
                    .expect("infallible: keystream slice is exactly 4 bytes"),
            );
        }

        self.initial.fast_zeroize();
    }

    #[cfg(test)]
    pub fn block(
        &mut self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        counter: u32,
        output: &mut [u8; CHACHA20_BLOCK_SIZE],
    ) {
        self.generate_block(key, nonce, counter);
        output.copy_from_slice(&self.keystream);
        self.keystream.fast_zeroize();
    }

    #[inline(always)]
    pub fn crypt(
        &mut self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) {
        for (i, chunk) in data.chunks_mut(CHACHA20_BLOCK_SIZE).enumerate() {
            self.generate_block(key, nonce, counter.wrapping_add(i as u32));

            for (byte, ks_byte) in chunk.iter_mut().zip(self.keystream.iter()) {
                *byte ^= ks_byte;
            }
        }

        self.keystream.fast_zeroize();
    }
}

impl core::fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChaCha20 {{ [protected] }}")
    }
}

/// HChaCha20 state for subkey derivation.
#[derive(MemZer)]
#[memzer(drop)]
pub(crate) struct HChaCha20 {
    state: [u32; 16],
    le_bytes_tmp: [u8; 4],
    // Temporaries for fallback quarter_round (zeroized on drop)
    qr_a: u32,
    qr_b: u32,
    qr_c: u32,
    qr_d: u32,
    __drop_sentinel: DropSentinel,
}

impl Default for HChaCha20 {
    fn default() -> Self {
        Self {
            state: [0; 16],
            le_bytes_tmp: [0; 4],
            qr_a: 0,
            qr_b: 0,
            qr_c: 0,
            qr_d: 0,
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl HChaCha20 {
    #[inline(always)]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            super::asm::x86_64::quarter_round(&mut self.state, a, b, c, d);
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            super::asm::aarch64::quarter_round(&mut self.state, a, b, c, d);
        }

        // Full Rust implementation as fallback (uses struct temporaries for zeroization)
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.qr_a = self.state[a];
            self.qr_b = self.state[b];
            self.qr_c = self.state[c];
            self.qr_d = self.state[d];

            self.qr_a = self.qr_a.wrapping_add(self.qr_b);
            self.qr_d ^= self.qr_a;
            self.qr_d = self.qr_d.rotate_left(16);

            self.qr_c = self.qr_c.wrapping_add(self.qr_d);
            self.qr_b ^= self.qr_c;
            self.qr_b = self.qr_b.rotate_left(12);

            self.qr_a = self.qr_a.wrapping_add(self.qr_b);
            self.qr_d ^= self.qr_a;
            self.qr_d = self.qr_d.rotate_left(8);

            self.qr_c = self.qr_c.wrapping_add(self.qr_d);
            self.qr_b ^= self.qr_c;
            self.qr_b = self.qr_b.rotate_left(7);

            self.state[a] = self.qr_a;
            self.state[b] = self.qr_b;
            self.state[c] = self.qr_c;
            self.state[d] = self.qr_d;
        }
    }

    #[inline(always)]
    pub fn derive(
        &mut self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; HCHACHA20_NONCE_SIZE],
        output: &mut [u8; KEY_SIZE],
    ) {
        self.state[0] = 0x61707865;
        self.state[1] = 0x3320646e;
        self.state[2] = 0x79622d32;
        self.state[3] = 0x6b206574;

        for i in 0..8 {
            self.le_bytes_tmp[0] = key[i * 4];
            self.le_bytes_tmp[1] = key[i * 4 + 1];
            self.le_bytes_tmp[2] = key[i * 4 + 2];
            self.le_bytes_tmp[3] = key[i * 4 + 3];
            u32_from_le(&mut self.state[4 + i], &mut self.le_bytes_tmp);
        }

        for i in 0..4 {
            self.le_bytes_tmp[0] = nonce[i * 4];
            self.le_bytes_tmp[1] = nonce[i * 4 + 1];
            self.le_bytes_tmp[2] = nonce[i * 4 + 2];
            self.le_bytes_tmp[3] = nonce[i * 4 + 3];
            u32_from_le(&mut self.state[12 + i], &mut self.le_bytes_tmp);
        }

        for _ in 0..10 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);

            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        for i in 0..4 {
            u32_to_le(
                &mut self.state[i],
                (&mut output[i * 4..i * 4 + 4])
                    .try_into()
                    .expect("infallible: output slice is exactly 4 bytes"),
            );
        }
        for i in 0..4 {
            u32_to_le(
                &mut self.state[12 + i],
                (&mut output[16 + i * 4..16 + i * 4 + 4])
                    .try_into()
                    .expect("infallible: output slice is exactly 4 bytes"),
            );
        }

        // state[4..12] not written to output, zeroize remaining
        self.state[4..12].fast_zeroize();
    }
}

impl core::fmt::Debug for HChaCha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HChaCha20 {{ [protected] }}")
    }
}

/// XChaCha20 cipher state with guaranteed zeroization.
#[derive(MemZer)]
#[memzer(drop)]
pub(crate) struct XChaCha20 {
    subkey: [u8; KEY_SIZE],
    nonce: [u8; CHACHA20_NONCE_SIZE],
    hchacha: HChaCha20,
    chacha: ChaCha20,
    __drop_sentinel: DropSentinel,
}

impl Default for XChaCha20 {
    fn default() -> Self {
        Self {
            subkey: [0; KEY_SIZE],
            nonce: [0; CHACHA20_NONCE_SIZE],
            hchacha: HChaCha20::default(),
            chacha: ChaCha20::default(),
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl XChaCha20 {
    /// Generate Poly1305 key from XChaCha20 keystream (counter=0)
    #[inline(always)]
    pub fn generate_poly_key(&mut self, key: &AeadKey, xnonce: &XNonce, output: &mut AeadKey) {
        self.hchacha.derive(
            key,
            xnonce[0..HCHACHA20_NONCE_SIZE]
                .try_into()
                .expect("infallible: xnonce[0..16] is exactly 16 bytes"),
            &mut self.subkey,
        );

        self.nonce[4..CHACHA20_NONCE_SIZE]
            .copy_from_slice(&xnonce[HCHACHA20_NONCE_SIZE..XNONCE_SIZE]);

        self.chacha.generate_block(&self.subkey, &self.nonce, 0);
        output.copy_from_slice(&self.chacha.keystream[0..KEY_SIZE]);

        self.subkey.fast_zeroize();
        self.nonce.fast_zeroize();
        self.chacha.keystream.fast_zeroize();
    }

    /// Encrypt/decrypt data in-place (counter=1)
    #[inline(always)]
    pub fn crypt(&mut self, key: &AeadKey, xnonce: &XNonce, data: &mut [u8]) {
        self.hchacha.derive(
            key,
            xnonce[0..HCHACHA20_NONCE_SIZE]
                .try_into()
                .expect("infallible: xnonce[0..16] is exactly 16 bytes"),
            &mut self.subkey,
        );

        self.nonce[4..CHACHA20_NONCE_SIZE]
            .copy_from_slice(&xnonce[HCHACHA20_NONCE_SIZE..XNONCE_SIZE]);

        self.chacha.crypt(&self.subkey, &self.nonce, 1, data);

        self.subkey.fast_zeroize();
        self.nonce.fast_zeroize();
    }
}

impl core::fmt::Debug for XChaCha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XChaCha20 {{ [protected] }}")
    }
}
