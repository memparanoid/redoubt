// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L state implementation with guaranteed zeroization.

use zeroize::Zeroize;

use memutil::u64_to_le;
use memzer::{DropSentinel, MemZer};

use crate::aegis::intrinsics::Intrinsics;

/// Fibonacci constant C0
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];

/// Fibonacci constant C1
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

/// AEGIS-128L state: 8 x 128-bit blocks with guaranteed zeroization.
#[derive(Zeroize, MemZer)]
#[zeroize(drop)]
pub struct Aegis128LState {
    /// The 8 state blocks S0..S7
    s0: Intrinsics,
    s1: Intrinsics,
    s2: Intrinsics,
    s3: Intrinsics,
    s4: Intrinsics,
    s5: Intrinsics,
    s6: Intrinsics,
    s7: Intrinsics,

    /// Temporary blocks for intermediate calculations (avoid stack temporaries)
    tmp_m0: Intrinsics,
    tmp_m1: Intrinsics,
    tmp_z0: Intrinsics,
    tmp_z1: Intrinsics,
    tmp_t: Intrinsics,

    /// Temporary for new state during update
    new_s0: Intrinsics,
    new_s1: Intrinsics,
    new_s2: Intrinsics,
    new_s3: Intrinsics,
    new_s4: Intrinsics,
    new_s5: Intrinsics,
    new_s6: Intrinsics,
    new_s7: Intrinsics,

    /// Temporary byte buffers for conversions
    len_block: [u8; 16],
    block_tmp: [u8; 32],
    tag_tmp: [u8; 16],

    /// Drop sentinel for testing
    __drop_sentinel: DropSentinel,
}

impl Default for Aegis128LState {
    fn default() -> Self {
        Self {
            s0: Intrinsics::default(),
            s1: Intrinsics::default(),
            s2: Intrinsics::default(),
            s3: Intrinsics::default(),
            s4: Intrinsics::default(),
            s5: Intrinsics::default(),
            s6: Intrinsics::default(),
            s7: Intrinsics::default(),
            tmp_m0: Intrinsics::default(),
            tmp_m1: Intrinsics::default(),
            tmp_z0: Intrinsics::default(),
            tmp_z1: Intrinsics::default(),
            tmp_t: Intrinsics::default(),
            new_s0: Intrinsics::default(),
            new_s1: Intrinsics::default(),
            new_s2: Intrinsics::default(),
            new_s3: Intrinsics::default(),
            new_s4: Intrinsics::default(),
            new_s5: Intrinsics::default(),
            new_s6: Intrinsics::default(),
            new_s7: Intrinsics::default(),
            len_block: [0; 16],
            block_tmp: [0; 32],
            tag_tmp: [0; 16],
            __drop_sentinel: DropSentinel::default(),
        }
    }
}

impl core::fmt::Debug for Aegis128LState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aegis128LState {{ [protected] }}")
    }
}

impl Aegis128LState {
    /// Access the scratch buffer for partial block operations.
    #[inline]
    pub fn block_tmp(&mut self) -> &mut [u8; 32] {
        &mut self.block_tmp
    }

    /// Initialize state from key and nonce.
    ///
    /// # Safety
    /// Caller must ensure AES hardware support is available.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn init(&mut self, key: &[u8; 16], nonce: &[u8; 16]) {
        // Load key, nonce, constants
        self.tmp_m0 = Intrinsics::load(key);
        self.tmp_m1 = Intrinsics::load(nonce);
        self.tmp_z0 = Intrinsics::load(&C0);
        self.tmp_z1 = Intrinsics::load(&C1);

        // key_xor_nonce
        self.tmp_t = self.tmp_m0.xor(&self.tmp_m1);

        // S0 = key ^ nonce
        self.s0 = Intrinsics::load(key);
        self.s0 = self.s0.xor(&Intrinsics::load(nonce));

        // S1 = C1
        self.s1 = Intrinsics::load(&C1);

        // S2 = C0
        self.s2 = Intrinsics::load(&C0);

        // S3 = C1
        self.s3 = Intrinsics::load(&C1);

        // S4 = key ^ nonce
        self.s4 = Intrinsics::load(key);
        self.s4 = self.s4.xor(&Intrinsics::load(nonce));

        // S5 = key ^ C0
        self.s5 = Intrinsics::load(key);
        self.s5 = self.s5.xor(&Intrinsics::load(&C0));

        // S6 = key ^ C1
        self.s6 = Intrinsics::load(key);
        self.s6 = self.s6.xor(&Intrinsics::load(&C1));

        // S7 = key ^ C0
        self.s7 = Intrinsics::load(key);
        self.s7 = self.s7.xor(&Intrinsics::load(&C0));

        // Run 10 Update rounds with (nonce, key)
        for _ in 0..10 {
            self.tmp_m0 = Intrinsics::load(nonce);
            self.tmp_m1 = Intrinsics::load(key);
            unsafe { self.update() };
        }
    }

    /// Core state update function.
    ///
    /// Uses tmp_m0 and tmp_m1 as input (M0, M1).
    /// ```text
    /// S'0 = AESRound(S7, S0 ^ M0)
    /// S'1 = AESRound(S0, S1)
    /// S'2 = AESRound(S1, S2)
    /// S'3 = AESRound(S2, S3)
    /// S'4 = AESRound(S3, S4 ^ M1)
    /// S'5 = AESRound(S4, S5)
    /// S'6 = AESRound(S5, S6)
    /// S'7 = AESRound(S6, S7)
    /// ```
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn update(&mut self) {
        // S0 ^ M0
        self.tmp_t = self.s0.xor(&self.tmp_m0);
        self.new_s0 = self.s7.aes_enc(&self.tmp_t);

        self.new_s1 = self.s0.aes_enc(&self.s1);
        self.new_s2 = self.s1.aes_enc(&self.s2);
        self.new_s3 = self.s2.aes_enc(&self.s3);

        // S4 ^ M1
        self.tmp_t = self.s4.xor(&self.tmp_m1);
        self.new_s4 = self.s3.aes_enc(&self.tmp_t);

        self.new_s5 = self.s4.aes_enc(&self.s5);
        self.new_s6 = self.s5.aes_enc(&self.s6);
        self.new_s7 = self.s6.aes_enc(&self.s7);

        // Move new state to current state
        core::mem::swap(&mut self.s0, &mut self.new_s0);
        core::mem::swap(&mut self.s1, &mut self.new_s1);
        core::mem::swap(&mut self.s2, &mut self.new_s2);
        core::mem::swap(&mut self.s3, &mut self.new_s3);
        core::mem::swap(&mut self.s4, &mut self.new_s4);
        core::mem::swap(&mut self.s5, &mut self.new_s5);
        core::mem::swap(&mut self.s6, &mut self.new_s6);
        core::mem::swap(&mut self.s7, &mut self.new_s7);
    }

    /// Absorb a 256-bit block of associated data.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn absorb(&mut self, ad: &[u8; 32]) {
        self.tmp_m0 = Intrinsics::load(ad[..16].try_into().unwrap());
        self.tmp_m1 = Intrinsics::load(ad[16..].try_into().unwrap());
        unsafe { self.update() };
    }

    /// Encrypt a 256-bit plaintext block in-place.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn enc(&mut self, block: &mut [u8; 32]) {
        // z0 = S1 ^ S6 ^ (S2 & S3)
        self.tmp_t = self.s2.and(&self.s3);
        self.tmp_z0 = self.s1.xor(&self.s6);
        self.tmp_z0 = self.tmp_z0.xor(&self.tmp_t);

        // z1 = S2 ^ S5 ^ (S6 & S7)
        self.tmp_t = self.s6.and(&self.s7);
        self.tmp_z1 = self.s2.xor(&self.s5);
        self.tmp_z1 = self.tmp_z1.xor(&self.tmp_t);

        // Load plaintext into tmp_m0, tmp_m1
        self.tmp_m0 = Intrinsics::load(block[..16].try_into().unwrap());
        self.tmp_m1 = Intrinsics::load(block[16..].try_into().unwrap());

        // out0 = t0 ^ z0, out1 = t1 ^ z1
        self.tmp_t = self.tmp_m0.xor(&self.tmp_z0);
        self.tmp_t.store((&mut block[..16]).try_into().unwrap());

        self.tmp_t = self.tmp_m1.xor(&self.tmp_z1);
        self.tmp_t.store((&mut block[16..]).try_into().unwrap());

        // Update state with plaintext (tmp_m0, tmp_m1 still hold plaintext)
        unsafe { self.update() };
    }

    /// Encrypt a partial plaintext block (< 32 bytes) in-place.
    ///
    /// Uses block_tmp as scratch space. The `len` bytes at the start of
    /// block_tmp are the plaintext, and will be replaced with ciphertext.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn enc_partial(&mut self, len: usize) {
        debug_assert!(len > 0 && len < 32);

        // Zero-pad the partial plaintext (already in block_tmp[..len])
        self.block_tmp[len..].fill(0);

        // z0 = S1 ^ S6 ^ (S2 & S3)
        self.tmp_t = self.s2.and(&self.s3);
        self.tmp_z0 = self.s1.xor(&self.s6);
        self.tmp_z0 = self.tmp_z0.xor(&self.tmp_t);

        // z1 = S2 ^ S5 ^ (S6 & S7)
        self.tmp_t = self.s6.and(&self.s7);
        self.tmp_z1 = self.s2.xor(&self.s5);
        self.tmp_z1 = self.tmp_z1.xor(&self.tmp_t);

        // Load zero-padded plaintext
        self.tmp_m0 = Intrinsics::load(self.block_tmp[..16].try_into().unwrap());
        self.tmp_m1 = Intrinsics::load(self.block_tmp[16..].try_into().unwrap());

        // Encrypt: ciphertext = plaintext ^ z
        self.tmp_t = self.tmp_m0.xor(&self.tmp_z0);
        self.tmp_t.store((&mut self.block_tmp[..16]).try_into().unwrap());

        self.tmp_t = self.tmp_m1.xor(&self.tmp_z1);
        self.tmp_t.store((&mut self.block_tmp[16..]).try_into().unwrap());

        // Update with zero-padded plaintext (tmp_m0, tmp_m1 still hold it)
        unsafe { self.update() };
    }

    /// Decrypt a 256-bit ciphertext block in-place.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn dec(&mut self, block: &mut [u8; 32]) {
        // z0 = S1 ^ S6 ^ (S2 & S3)
        self.tmp_t = self.s2.and(&self.s3);
        self.tmp_z0 = self.s1.xor(&self.s6);
        self.tmp_z0 = self.tmp_z0.xor(&self.tmp_t);

        // z1 = S2 ^ S5 ^ (S6 & S7)
        self.tmp_t = self.s6.and(&self.s7);
        self.tmp_z1 = self.s2.xor(&self.s5);
        self.tmp_z1 = self.tmp_z1.xor(&self.tmp_t);

        // Load ciphertext
        self.tmp_t = Intrinsics::load(block[..16].try_into().unwrap());
        // Decrypt: plaintext = ciphertext ^ z0
        self.tmp_m0 = self.tmp_t.xor(&self.tmp_z0);
        self.tmp_m0.store((&mut block[..16]).try_into().unwrap());

        self.tmp_t = Intrinsics::load(block[16..].try_into().unwrap());
        // Decrypt: plaintext = ciphertext ^ z1
        self.tmp_m1 = self.tmp_t.xor(&self.tmp_z1);
        self.tmp_m1.store((&mut block[16..]).try_into().unwrap());

        // Update state with PLAINTEXT (tmp_m0, tmp_m1)
        unsafe { self.update() };
    }

    /// Decrypt a partial ciphertext block (< 32 bytes) in-place.
    ///
    /// Uses block_tmp as scratch space. The `len` bytes at the start of
    /// block_tmp are the ciphertext, and will be replaced with plaintext.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn dec_partial(&mut self, len: usize) {
        debug_assert!(len > 0 && len < 32);

        // Zero-pad the partial ciphertext (already in block_tmp[..len])
        self.block_tmp[len..].fill(0);

        // z0 = S1 ^ S6 ^ (S2 & S3)
        self.tmp_t = self.s2.and(&self.s3);
        self.tmp_z0 = self.s1.xor(&self.s6);
        self.tmp_z0 = self.tmp_z0.xor(&self.tmp_t);

        // z1 = S2 ^ S5 ^ (S6 & S7)
        self.tmp_t = self.s6.and(&self.s7);
        self.tmp_z1 = self.s2.xor(&self.s5);
        self.tmp_z1 = self.tmp_z1.xor(&self.tmp_t);

        // Decrypt: padded_plaintext = padded_ciphertext ^ z
        self.tmp_t = Intrinsics::load(self.block_tmp[..16].try_into().unwrap());
        self.tmp_m0 = self.tmp_t.xor(&self.tmp_z0);
        self.tmp_m0.store((&mut self.block_tmp[..16]).try_into().unwrap());

        self.tmp_t = Intrinsics::load(self.block_tmp[16..].try_into().unwrap());
        self.tmp_m1 = self.tmp_t.xor(&self.tmp_z1);
        self.tmp_m1.store((&mut self.block_tmp[16..]).try_into().unwrap());

        // Zero the padding bytes (keep only actual plaintext)
        self.block_tmp[len..].fill(0);

        // Update with zero-padded plaintext
        self.tmp_m0 = Intrinsics::load(self.block_tmp[..16].try_into().unwrap());
        self.tmp_m1 = Intrinsics::load(self.block_tmp[16..].try_into().unwrap());
        unsafe { self.update() };
    }

    /// Finalize and produce 128-bit tag.
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn finalize(&mut self, ad_len: usize, msg_len: usize, tag: &mut [u8; 16]) {
        // t = S2 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))
        let mut ad_bits = (ad_len as u64) * 8;
        let mut msg_bits = (msg_len as u64) * 8;

        u64_to_le(
            &mut ad_bits,
            (&mut self.len_block[..8]).try_into().unwrap(),
        );
        u64_to_le(
            &mut msg_bits,
            (&mut self.len_block[8..]).try_into().unwrap(),
        );

        // t = S2 ^ len_block (computed once and stored)
        self.tmp_t = Intrinsics::load(&self.len_block);
        self.tmp_t = self.s2.xor(&self.tmp_t);
        self.tmp_t.store(&mut self.tag_tmp);

        // Run 7 Update rounds with (t, t)
        for _ in 0..7 {
            self.tmp_m0 = Intrinsics::load(&self.tag_tmp);
            self.tmp_m1 = Intrinsics::load(&self.tag_tmp);
            unsafe { self.update() };
        }

        // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
        self.tmp_t = self.s0.xor(&self.s1);
        self.tmp_t = self.tmp_t.xor(&self.s2);
        self.tmp_t = self.tmp_t.xor(&self.s3);
        self.tmp_t = self.tmp_t.xor(&self.s4);
        self.tmp_t = self.tmp_t.xor(&self.s5);
        self.tmp_t = self.tmp_t.xor(&self.s6);

        self.tmp_t.store(tag);
    }
}
