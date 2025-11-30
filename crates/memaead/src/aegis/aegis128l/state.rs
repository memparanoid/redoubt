// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L state implementation with guaranteed zeroization.
//!
//! All hot paths use inline assembly to keep state in SIMD registers,
//! avoiding stack temporaries that would need zeroization.

use memzer::{DropSentinel, MemZer};
use zeroize::Zeroize;

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
#[repr(C)]
pub struct Aegis128LState {
    /// The 8 state blocks S0..S7
    s: [Intrinsics; 8],

    /// Temporary byte buffers
    len_block: [u8; 16],
    block_tmp: [u8; 32],

    /// Drop sentinel for testing
    __drop_sentinel: DropSentinel,
}

impl Default for Aegis128LState {
    fn default() -> Self {
        Self {
            s: [Intrinsics::default(); 8],
            len_block: [0; 16],
            block_tmp: [0; 32],
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
    /// Initialize state from key and nonce.
    #[inline(always)]
    pub unsafe fn init(&mut self, key: &[u8; 16], nonce: &[u8; 16]) {
        core::arch::asm!(
            "ld1 {{v24.16b}}, [{key}]",
            "ld1 {{v25.16b}}, [{nonce}]",
            "ld1 {{v26.16b}}, [{c0}]",
            "ld1 {{v27.16b}}, [{c1}]",
            "eor v28.16b, v24.16b, v25.16b",

            "mov v0.16b, v28.16b",
            "mov v1.16b, v27.16b",
            "mov v2.16b, v26.16b",
            "mov v3.16b, v27.16b",
            "mov v4.16b, v28.16b",
            "eor v5.16b, v24.16b, v26.16b",
            "eor v6.16b, v24.16b, v27.16b",
            "eor v7.16b, v24.16b, v26.16b",

            "movi v31.16b, #0",
            "mov x9, #10",
            "2:",

            "eor v16.16b, v0.16b, v25.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",
            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v24.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            "mov v0.16b, v8.16b",
            "mov v1.16b, v9.16b",
            "mov v2.16b, v10.16b",
            "mov v3.16b, v11.16b",
            "mov v4.16b, v12.16b",
            "mov v5.16b, v13.16b",
            "mov v6.16b, v14.16b",
            "mov v7.16b, v15.16b",

            "subs x9, x9, #1",
            "b.ne 2b",

            "st1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp}, {state}, #64",
            "st1 {{v4.16b-v7.16b}}, [{tmp}]",

            key = in(reg) key.as_ptr(),
            nonce = in(reg) nonce.as_ptr(),
            c0 = in(reg) C0.as_ptr(),
            c1 = in(reg) C1.as_ptr(),
            state = in(reg) self.s.as_mut_ptr(),
            tmp = out(reg) _,
            out("x9") _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v24") _, out("v25") _, out("v26") _,
            out("v27") _, out("v28") _, out("v31") _,
            options(nostack),
        );
    }

    /// Absorb associated data - processes all AD in one asm block.
    #[inline(always)]
    pub unsafe fn absorb_all(&mut self, ad: &[u8]) {
        if ad.is_empty() {
            return;
        }

        let full_blocks = ad.len() / 32;
        let remaining = ad.len() % 32;

        if full_blocks > 0 {
            core::arch::asm!(
                // Load state
                "ld1 {{v0.16b-v3.16b}}, [{state}]",
                "add {tmp}, {state}, #64",
                "ld1 {{v4.16b-v7.16b}}, [{tmp}]",
                "movi v31.16b, #0",

                "20:",
                // Load AD block
                "ld1 {{v24.16b, v25.16b}}, [{ad}]",
                "add {ad}, {ad}, #32",

                // Update state
                "eor v16.16b, v0.16b, v24.16b",
                "mov v8.16b, v7.16b",
                "aese v8.16b, v31.16b",
                "aesmc v8.16b, v8.16b",
                "eor v8.16b, v8.16b, v16.16b",

                "mov v9.16b, v0.16b",
                "aese v9.16b, v31.16b",
                "aesmc v9.16b, v9.16b",
                "eor v9.16b, v9.16b, v1.16b",

                "mov v10.16b, v1.16b",
                "aese v10.16b, v31.16b",
                "aesmc v10.16b, v10.16b",
                "eor v10.16b, v10.16b, v2.16b",

                "mov v11.16b, v2.16b",
                "aese v11.16b, v31.16b",
                "aesmc v11.16b, v11.16b",
                "eor v11.16b, v11.16b, v3.16b",

                "eor v16.16b, v4.16b, v25.16b",
                "mov v12.16b, v3.16b",
                "aese v12.16b, v31.16b",
                "aesmc v12.16b, v12.16b",
                "eor v12.16b, v12.16b, v16.16b",

                "mov v13.16b, v4.16b",
                "aese v13.16b, v31.16b",
                "aesmc v13.16b, v13.16b",
                "eor v13.16b, v13.16b, v5.16b",

                "mov v14.16b, v5.16b",
                "aese v14.16b, v31.16b",
                "aesmc v14.16b, v14.16b",
                "eor v14.16b, v14.16b, v6.16b",

                "mov v15.16b, v6.16b",
                "aese v15.16b, v31.16b",
                "aesmc v15.16b, v15.16b",
                "eor v15.16b, v15.16b, v7.16b",

                "mov v0.16b, v8.16b",
                "mov v1.16b, v9.16b",
                "mov v2.16b, v10.16b",
                "mov v3.16b, v11.16b",
                "mov v4.16b, v12.16b",
                "mov v5.16b, v13.16b",
                "mov v6.16b, v14.16b",
                "mov v7.16b, v15.16b",

                "subs {blocks}, {blocks}, #1",
                "b.ne 20b",

                // Store state
                "st1 {{v0.16b-v3.16b}}, [{state}]",
                "st1 {{v4.16b-v7.16b}}, [{tmp}]",

                state = in(reg) self.s.as_mut_ptr(),
                ad = inout(reg) ad.as_ptr() => _,
                blocks = inout(reg) full_blocks => _,
                tmp = out(reg) _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v24") _, out("v25") _, out("v31") _,
                options(nostack),
            );
        }

        // Handle partial block
        if remaining > 0 {
            self.block_tmp[..remaining].copy_from_slice(&ad[full_blocks * 32..]);
            self.block_tmp[remaining..].fill(0);
            self.absorb_block(&self.block_tmp.clone());
        }
    }

    /// Absorb a single 32-byte block.
    #[inline(always)]
    unsafe fn absorb_block(&mut self, block: &[u8; 32]) {
        core::arch::asm!(
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp}]",
            "ld1 {{v24.16b, v25.16b}}, [{block}]",
            "movi v31.16b, #0",

            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",
            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            "st1 {{v8.16b-v11.16b}}, [{state}]",
            "st1 {{v12.16b-v15.16b}}, [{tmp}]",

            state = in(reg) self.s.as_mut_ptr(),
            block = in(reg) block.as_ptr(),
            tmp = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );
    }

    /// Encrypt all full blocks in one asm loop, state stays in registers.
    #[inline(always)]
    pub unsafe fn encrypt_blocks(&mut self, data: &mut [u8]) {
        let full_blocks = data.len() / 32;
        if full_blocks == 0 {
            return;
        }

        core::arch::asm!(
            // Load state once
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp}]",
            "movi v31.16b, #0",

            "30:",
            // Load plaintext
            "ld1 {{v24.16b, v25.16b}}, [{data}]",

            // z0 = s1 ^ s6 ^ (s2 & s3)
            "and v16.16b, v2.16b, v3.16b",
            "eor v17.16b, v1.16b, v6.16b",
            "eor v17.16b, v17.16b, v16.16b",

            // z1 = s2 ^ s5 ^ (s6 & s7)
            "and v16.16b, v6.16b, v7.16b",
            "eor v18.16b, v2.16b, v5.16b",
            "eor v18.16b, v18.16b, v16.16b",

            // ciphertext = plaintext ^ z
            "eor v19.16b, v24.16b, v17.16b",
            "eor v20.16b, v25.16b, v18.16b",

            // Start state update immediately (interleave with store)
            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",

            // Store ciphertext (can execute in parallel with aesmc)
            "st1 {{v19.16b, v20.16b}}, [{data}]",
            "add {data}, {data}, #32",

            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            // Move new state to current
            "mov v0.16b, v8.16b",
            "mov v1.16b, v9.16b",
            "mov v2.16b, v10.16b",
            "mov v3.16b, v11.16b",
            "mov v4.16b, v12.16b",
            "mov v5.16b, v13.16b",
            "mov v6.16b, v14.16b",
            "mov v7.16b, v15.16b",

            "subs {blocks}, {blocks}, #1",
            "b.ne 30b",

            // Store state once at end
            "st1 {{v0.16b-v3.16b}}, [{state}]",
            "st1 {{v4.16b-v7.16b}}, [{tmp}]",

            state = in(reg) self.s.as_mut_ptr(),
            data = inout(reg) data.as_mut_ptr() => _,
            blocks = inout(reg) full_blocks => _,
            tmp = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );
    }

    /// Encrypt partial block (< 32 bytes).
    ///
    /// For partial blocks we must:
    /// 1. Compute z0, z1 from current state
    /// 2. Encrypt: ciphertext = plaintext ^ z[0..len]
    /// 3. Update state with (plaintext || zeros)
    #[inline(always)]
    pub unsafe fn encrypt_partial(&mut self, data: &mut [u8]) {
        let len = data.len();
        debug_assert!(len > 0 && len < 32);

        // Prepare: plaintext || zeros
        self.block_tmp[..len].copy_from_slice(data);
        self.block_tmp[len..].fill(0);

        core::arch::asm!(
            // Load state
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp_reg}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp_reg}]",
            "movi v31.16b, #0",

            // Load plaintext||zeros
            "ld1 {{v24.16b, v25.16b}}, [{block}]",

            // z0 = s1 ^ s6 ^ (s2 & s3)
            "and v16.16b, v2.16b, v3.16b",
            "eor v17.16b, v1.16b, v6.16b",
            "eor v17.16b, v17.16b, v16.16b",

            // z1 = s2 ^ s5 ^ (s6 & s7)
            "and v16.16b, v6.16b, v7.16b",
            "eor v18.16b, v2.16b, v5.16b",
            "eor v18.16b, v18.16b, v16.16b",

            // ciphertext||garbage = plaintext||zeros ^ z0||z1
            "eor v19.16b, v24.16b, v17.16b",
            "eor v20.16b, v25.16b, v18.16b",

            // Store ciphertext||garbage (we'll truncate in Rust)
            "st1 {{v19.16b, v20.16b}}, [{block}]",

            // Update state with plaintext||zeros (v24, v25)
            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",
            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            // Store new state
            "st1 {{v8.16b-v11.16b}}, [{state}]",
            "st1 {{v12.16b-v15.16b}}, [{tmp_reg}]",

            state = in(reg) self.s.as_mut_ptr(),
            block = in(reg) self.block_tmp.as_mut_ptr(),
            tmp_reg = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );

        // Copy ciphertext back (ignore garbage beyond len)
        data.copy_from_slice(&self.block_tmp[..len]);
    }

    /// Decrypt all full blocks in one asm loop.
    #[inline(always)]
    pub unsafe fn decrypt_blocks(&mut self, data: &mut [u8]) {
        let full_blocks = data.len() / 32;
        if full_blocks == 0 {
            return;
        }

        core::arch::asm!(
            // Load state once
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp}]",
            "movi v31.16b, #0",

            "40:",
            // Load ciphertext
            "ld1 {{v19.16b, v20.16b}}, [{data}]",

            // z0 = s1 ^ s6 ^ (s2 & s3)
            "and v16.16b, v2.16b, v3.16b",
            "eor v17.16b, v1.16b, v6.16b",
            "eor v17.16b, v17.16b, v16.16b",

            // z1 = s2 ^ s5 ^ (s6 & s7)
            "and v16.16b, v6.16b, v7.16b",
            "eor v18.16b, v2.16b, v5.16b",
            "eor v18.16b, v18.16b, v16.16b",

            // plaintext = ciphertext ^ z
            "eor v24.16b, v19.16b, v17.16b",
            "eor v25.16b, v20.16b, v18.16b",

            // Start state update immediately (interleave with store)
            // This allows the store to happen in parallel with AES operations
            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",

            // Store plaintext (can execute in parallel with aesmc)
            "st1 {{v24.16b, v25.16b}}, [{data}]",
            "add {data}, {data}, #32",

            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            // Move new state to current
            "mov v0.16b, v8.16b",
            "mov v1.16b, v9.16b",
            "mov v2.16b, v10.16b",
            "mov v3.16b, v11.16b",
            "mov v4.16b, v12.16b",
            "mov v5.16b, v13.16b",
            "mov v6.16b, v14.16b",
            "mov v7.16b, v15.16b",

            "subs {blocks}, {blocks}, #1",
            "b.ne 40b",

            // Store state once at end
            "st1 {{v0.16b-v3.16b}}, [{state}]",
            "st1 {{v4.16b-v7.16b}}, [{tmp}]",

            state = in(reg) self.s.as_mut_ptr(),
            data = inout(reg) data.as_mut_ptr() => _,
            blocks = inout(reg) full_blocks => _,
            tmp = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );
    }

    /// Decrypt partial block (< 32 bytes).
    ///
    /// For partial blocks we must:
    /// 1. Compute z0, z1 from current state
    /// 2. Decrypt: plaintext = ciphertext ^ z[0..len]
    /// 3. Update state with (plaintext || zeros)
    #[inline(always)]
    pub unsafe fn decrypt_partial(&mut self, data: &mut [u8]) {
        let len = data.len();
        debug_assert!(len > 0 && len < 32);

        // Prepare: ciphertext || zeros
        self.block_tmp[..len].copy_from_slice(data);
        self.block_tmp[len..].fill(0);

        core::arch::asm!(
            // Load state
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp_reg}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp_reg}]",
            "movi v31.16b, #0",

            // Load ciphertext||zeros
            "ld1 {{v19.16b, v20.16b}}, [{block}]",

            // z0 = s1 ^ s6 ^ (s2 & s3)
            "and v16.16b, v2.16b, v3.16b",
            "eor v17.16b, v1.16b, v6.16b",
            "eor v17.16b, v17.16b, v16.16b",

            // z1 = s2 ^ s5 ^ (s6 & s7)
            "and v16.16b, v6.16b, v7.16b",
            "eor v18.16b, v2.16b, v5.16b",
            "eor v18.16b, v18.16b, v16.16b",

            // plaintext||garbage = ciphertext||zeros ^ z0||z1
            "eor v24.16b, v19.16b, v17.16b",
            "eor v25.16b, v20.16b, v18.16b",

            // Store plaintext||garbage (we'll zero-pad in Rust then reload)
            "st1 {{v24.16b, v25.16b}}, [{block}]",

            state = in(reg) self.s.as_mut_ptr(),
            block = in(reg) self.block_tmp.as_mut_ptr(),
            tmp_reg = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );

        // Copy plaintext back, zero the garbage
        data.copy_from_slice(&self.block_tmp[..len]);
        self.block_tmp[len..].fill(0);

        // Update state with zero-padded plaintext
        core::arch::asm!(
            // Load state
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp_reg}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp_reg}]",
            "movi v31.16b, #0",

            // Load plaintext||zeros
            "ld1 {{v24.16b, v25.16b}}, [{block}]",

            // Update state
            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",
            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            // Store new state
            "st1 {{v8.16b-v11.16b}}, [{state}]",
            "st1 {{v12.16b-v15.16b}}, [{tmp_reg}]",

            state = in(reg) self.s.as_mut_ptr(),
            block = in(reg) self.block_tmp.as_ptr(),
            tmp_reg = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );
    }

    /// Finalize and produce tag.
    #[inline(always)]
    pub unsafe fn finalize(&mut self, ad_len: usize, msg_len: usize, tag: &mut [u8; 16]) {
        let ad_bits = (ad_len as u64) * 8;
        let msg_bits = (msg_len as u64) * 8;

        self.len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        self.len_block[8..].copy_from_slice(&msg_bits.to_le_bytes());

        core::arch::asm!(
            "ld1 {{v0.16b-v3.16b}}, [{state}]",
            "add {tmp}, {state}, #64",
            "ld1 {{v4.16b-v7.16b}}, [{tmp}]",
            "ld1 {{v24.16b}}, [{len_block}]",

            "eor v24.16b, v2.16b, v24.16b",
            "mov v25.16b, v24.16b",
            "movi v31.16b, #0",

            "mov x9, #7",
            "50:",

            "eor v16.16b, v0.16b, v24.16b",
            "mov v8.16b, v7.16b",
            "aese v8.16b, v31.16b",
            "aesmc v8.16b, v8.16b",
            "eor v8.16b, v8.16b, v16.16b",

            "mov v9.16b, v0.16b",
            "aese v9.16b, v31.16b",
            "aesmc v9.16b, v9.16b",
            "eor v9.16b, v9.16b, v1.16b",

            "mov v10.16b, v1.16b",
            "aese v10.16b, v31.16b",
            "aesmc v10.16b, v10.16b",
            "eor v10.16b, v10.16b, v2.16b",

            "mov v11.16b, v2.16b",
            "aese v11.16b, v31.16b",
            "aesmc v11.16b, v11.16b",
            "eor v11.16b, v11.16b, v3.16b",

            "eor v16.16b, v4.16b, v25.16b",
            "mov v12.16b, v3.16b",
            "aese v12.16b, v31.16b",
            "aesmc v12.16b, v12.16b",
            "eor v12.16b, v12.16b, v16.16b",

            "mov v13.16b, v4.16b",
            "aese v13.16b, v31.16b",
            "aesmc v13.16b, v13.16b",
            "eor v13.16b, v13.16b, v5.16b",

            "mov v14.16b, v5.16b",
            "aese v14.16b, v31.16b",
            "aesmc v14.16b, v14.16b",
            "eor v14.16b, v14.16b, v6.16b",

            "mov v15.16b, v6.16b",
            "aese v15.16b, v31.16b",
            "aesmc v15.16b, v15.16b",
            "eor v15.16b, v15.16b, v7.16b",

            "mov v0.16b, v8.16b",
            "mov v1.16b, v9.16b",
            "mov v2.16b, v10.16b",
            "mov v3.16b, v11.16b",
            "mov v4.16b, v12.16b",
            "mov v5.16b, v13.16b",
            "mov v6.16b, v14.16b",
            "mov v7.16b, v15.16b",

            "subs x9, x9, #1",
            "b.ne 50b",

            // tag = s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6
            "eor v0.16b, v0.16b, v1.16b",
            "eor v0.16b, v0.16b, v2.16b",
            "eor v0.16b, v0.16b, v3.16b",
            "eor v0.16b, v0.16b, v4.16b",
            "eor v0.16b, v0.16b, v5.16b",
            "eor v0.16b, v0.16b, v6.16b",
            "st1 {{v0.16b}}, [{tag}]",

            // Store final state
            "st1 {{v8.16b-v11.16b}}, [{state}]",
            "st1 {{v12.16b-v15.16b}}, [{tmp}]",

            state = in(reg) self.s.as_mut_ptr(),
            len_block = in(reg) self.len_block.as_ptr(),
            tag = in(reg) tag.as_mut_ptr(),
            tmp = out(reg) _,
            out("x9") _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v24") _, out("v25") _, out("v31") _,
            options(nostack),
        );
    }
}
