// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L implementation with in-place operations for guaranteed zeroization.
//!
//! Uses local variables with explicit zeroization of all intermediates.
//! All Intrinsics are either zeroized explicitly or via move_to.

use memutil::u64_to_le;
use memzer::FastZeroizable;

use crate::aegis::aegis128l::consts::BLOCK_SIZE;
use crate::aegis::intrinsics::Intrinsics;

/// Fibonacci constant C0
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];

/// Fibonacci constant C1
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

/// AEGIS-128L encrypt.
///
/// # Safety
/// Caller must ensure AES hardware support is available.
#[inline(always)]
pub unsafe fn encrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    aad: &[u8],
    data: &mut [u8],
    tag: &mut [u8; 16],
) {
    // === Initialize state ===
    let mut key_block = Intrinsics::load(key);
    let mut nonce_block = Intrinsics::load(nonce);
    let mut c0 = Intrinsics::load(&C0);
    let mut c1 = Intrinsics::load(&C1);

    // s0 = key ^ nonce
    let mut s0 = key_block.xor(&nonce_block);
    let mut s1 = Intrinsics::load(&C1);
    let mut s2 = Intrinsics::load(&C0);
    let mut s3 = Intrinsics::load(&C1);
    let mut s4 = key_block.xor(&nonce_block);
    let mut s5 = key_block.xor(&c0);
    let mut s6 = key_block.xor(&c1);
    let mut s7 = key_block.xor(&c0);

    // Clean up init temps
    c0.fast_zeroize();
    c1.fast_zeroize();

    // 10 init rounds with (nonce, key)
    for _ in 0..10 {
        update(
            &mut s0,
            &mut s1,
            &mut s2,
            &mut s3,
            &mut s4,
            &mut s5,
            &mut s6,
            &mut s7,
            &nonce_block,
            &key_block,
        );
    }

    // Clean up key/nonce blocks
    key_block.fast_zeroize();
    nonce_block.fast_zeroize();

    // === Absorb AAD ===
    let mut aad_iter = aad.chunks_exact(BLOCK_SIZE);
    for block in aad_iter.by_ref() {
        let mut m0 = Intrinsics::load(block[..16].try_into().expect("Infallible: BLOCK_SIZE is 32, so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(block[16..].try_into().expect("Infallible: BLOCK_SIZE is 32, so [16..] is exactly 16 bytes"));
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
    }

    // Partial AAD block
    let aad_remainder = aad_iter.remainder();
    if !aad_remainder.is_empty() {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..aad_remainder.len()].copy_from_slice(aad_remainder);
        let mut m0 = Intrinsics::load(padded[..16].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(padded[16..].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
        padded.fast_zeroize();
    }

    // === Encrypt data ===
    let msg_len = data.len();
    let mut data_iter = data.chunks_exact_mut(BLOCK_SIZE);
    for block in data_iter.by_ref() {
        // Compute keystream: z0 = s1 ^ s6 ^ (s2 & s3)
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_in_place(&t0);
        t0.fast_zeroize();

        // z1 = s2 ^ s5 ^ (s6 & s7)
        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_in_place(&t1);
        t1.fast_zeroize();

        // Load plaintext
        let mut m0 = Intrinsics::load(block[..16].try_into().expect("Infallible: BLOCK_SIZE is 32, so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(block[16..].try_into().expect("Infallible: BLOCK_SIZE is 32, so [16..] is exactly 16 bytes"));

        // Encrypt: ciphertext = plaintext ^ keystream
        let mut c0 = m0.xor(&z0);
        let mut c1 = m1.xor(&z1);
        c0.store((&mut block[..16]).try_into().expect("Infallible: mutable slice is exactly 16 bytes"));
        c1.store((&mut block[16..]).try_into().expect("Infallible: mutable slice is exactly 16 bytes"));
        c0.fast_zeroize();
        c1.fast_zeroize();
        z0.fast_zeroize();
        z1.fast_zeroize();

        // Update state with plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
    }

    // Partial data block
    let data_remainder = data_iter.into_remainder();
    if !data_remainder.is_empty() {
        let len = data_remainder.len();
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..len].copy_from_slice(data_remainder);

        // Compute keystream
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_in_place(&t0);
        t0.fast_zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_in_place(&t1);
        t1.fast_zeroize();

        // Load padded plaintext
        let mut m0 = Intrinsics::load(padded[..16].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(padded[16..].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));

        // Encrypt
        let mut c0 = m0.xor(&z0);
        let mut c1 = m1.xor(&z1);
        z0.fast_zeroize();
        z1.fast_zeroize();

        // Store only the valid ciphertext bytes
        let mut ct_buf = [0u8; BLOCK_SIZE];
        c0.store((&mut ct_buf[..16]).try_into().expect("Infallible: ct_buf is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        c1.store((&mut ct_buf[16..]).try_into().expect("Infallible: ct_buf is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));
        data_remainder.copy_from_slice(&ct_buf[..len]);
        c0.fast_zeroize();
        c1.fast_zeroize();

        // Update state with padded plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();

        padded.fast_zeroize();
        ct_buf.fast_zeroize();
    }

    // === Finalize ===
    let mut len_block = [0u8; 16];
    let mut ad_bits = (aad.len() as u64) * 8;
    let mut msg_bits = (msg_len as u64) * 8;
    u64_to_le(&mut ad_bits, (&mut len_block[..8]).try_into().expect("Infallible: len_block is [u8; 16], so [..8] is exactly 8 bytes"));
    u64_to_le(&mut msg_bits, (&mut len_block[8..]).try_into().expect("Infallible: len_block is [u8; 16], so [8..] is exactly 8 bytes"));

    let mut len_intrinsic = Intrinsics::load(&len_block);
    let mut t = s2.xor(&len_intrinsic);
    len_intrinsic.fast_zeroize();

    let mut t_buf = [0u8; 16];
    t.store(&mut t_buf);
    t.fast_zeroize();

    // 7 finalization rounds with (t, t)
    for _ in 0..7 {
        let mut t_block = Intrinsics::load(&t_buf);
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &t_block,
            &t_block,
        );
        t_block.fast_zeroize();
    }

    // Compute tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    let mut tag_block = s0.xor(&s1);
    tag_block.xor_in_place(&s2);
    tag_block.xor_in_place(&s3);
    tag_block.xor_in_place(&s4);
    tag_block.xor_in_place(&s5);
    tag_block.xor_in_place(&s6);
    tag_block.store(tag);
    tag_block.fast_zeroize();

    // === Zeroize all state ===
    s0.fast_zeroize();
    s1.fast_zeroize();
    s2.fast_zeroize();
    s3.fast_zeroize();
    s4.fast_zeroize();
    s5.fast_zeroize();
    s6.fast_zeroize();
    s7.fast_zeroize();
    len_block.fast_zeroize();
    t_buf.fast_zeroize();
}

/// AEGIS-128L decrypt.
///
/// # Safety
/// Caller must ensure AES hardware support is available.
#[inline(always)]
pub unsafe fn decrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    aad: &[u8],
    data: &mut [u8],
    expected_tag: &[u8; 16],
) -> bool {
    // === Initialize state ===
    let mut key_block = Intrinsics::load(key);
    let mut nonce_block = Intrinsics::load(nonce);
    let mut c0 = Intrinsics::load(&C0);
    let mut c1 = Intrinsics::load(&C1);

    let mut s0 = key_block.xor(&nonce_block);
    let mut s1 = Intrinsics::load(&C1);
    let mut s2 = Intrinsics::load(&C0);
    let mut s3 = Intrinsics::load(&C1);
    let mut s4 = key_block.xor(&nonce_block);
    let mut s5 = key_block.xor(&c0);
    let mut s6 = key_block.xor(&c1);
    let mut s7 = key_block.xor(&c0);

    c0.fast_zeroize();
    c1.fast_zeroize();

    // 10 init rounds
    for _ in 0..10 {
        update(
            &mut s0,
            &mut s1,
            &mut s2,
            &mut s3,
            &mut s4,
            &mut s5,
            &mut s6,
            &mut s7,
            &nonce_block,
            &key_block,
        );
    }

    key_block.fast_zeroize();
    nonce_block.fast_zeroize();

    // === Absorb AAD ===
    let mut aad_iter = aad.chunks_exact(BLOCK_SIZE);
    for block in aad_iter.by_ref() {
        let mut m0 = Intrinsics::load(block[..16].try_into().expect("Infallible: BLOCK_SIZE is 32, so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(block[16..].try_into().expect("Infallible: BLOCK_SIZE is 32, so [16..] is exactly 16 bytes"));
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
    }

    let aad_remainder = aad_iter.remainder();
    if !aad_remainder.is_empty() {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..aad_remainder.len()].copy_from_slice(aad_remainder);
        let mut m0 = Intrinsics::load(padded[..16].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(padded[16..].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
        padded.fast_zeroize();
    }

    // === Decrypt data ===
    let ct_len = data.len();
    let mut data_iter = data.chunks_exact_mut(BLOCK_SIZE);
    for block in data_iter.by_ref() {
        // Compute keystream
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_in_place(&t0);
        t0.fast_zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_in_place(&t1);
        t1.fast_zeroize();

        // Load ciphertext
        let mut ct0 = Intrinsics::load(block[..16].try_into().expect("Infallible: BLOCK_SIZE is 32, so [..16] is exactly 16 bytes"));
        let mut ct1 = Intrinsics::load(block[16..].try_into().expect("Infallible: BLOCK_SIZE is 32, so [16..] is exactly 16 bytes"));

        // Decrypt: plaintext = ciphertext ^ keystream
        let mut m0 = ct0.xor(&z0);
        let mut m1 = ct1.xor(&z1);
        m0.store((&mut block[..16]).try_into().expect("Infallible: mutable slice is exactly 16 bytes"));
        m1.store((&mut block[16..]).try_into().expect("Infallible: mutable slice is exactly 16 bytes"));
        ct0.fast_zeroize();
        ct1.fast_zeroize();
        z0.fast_zeroize();
        z1.fast_zeroize();

        // Update state with plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();
    }

    // Partial data block
    let data_remainder = data_iter.into_remainder();
    if !data_remainder.is_empty() {
        let len = data_remainder.len();
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..len].copy_from_slice(data_remainder);

        // Compute keystream
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_in_place(&t0);
        t0.fast_zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_in_place(&t1);
        t1.fast_zeroize();

        // Load padded ciphertext
        let mut ct0 = Intrinsics::load(padded[..16].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        let mut ct1 = Intrinsics::load(padded[16..].try_into().expect("Infallible: padded is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));

        // Decrypt
        let mut pt0 = ct0.xor(&z0);
        let mut pt1 = ct1.xor(&z1);
        ct0.fast_zeroize();
        ct1.fast_zeroize();
        z0.fast_zeroize();
        z1.fast_zeroize();

        // Store plaintext to temp buffer
        let mut pt_buf = [0u8; BLOCK_SIZE];
        pt0.store((&mut pt_buf[..16]).try_into().expect("Infallible: pt_buf is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        pt1.store((&mut pt_buf[16..]).try_into().expect("Infallible: pt_buf is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));

        // Copy only valid plaintext bytes
        data_remainder.copy_from_slice(&pt_buf[..len]);

        // Update state with zero-padded plaintext
        pt_buf[len..].fill(0);
        let mut m0 = Intrinsics::load(pt_buf[..16].try_into().expect("Infallible: pt_buf is [u8; BLOCK_SIZE], so [..16] is exactly 16 bytes"));
        let mut m1 = Intrinsics::load(pt_buf[16..].try_into().expect("Infallible: pt_buf is [u8; BLOCK_SIZE], so [16..] is exactly 16 bytes"));
        pt0.fast_zeroize();
        pt1.fast_zeroize();

        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &m0, &m1,
        );
        m0.fast_zeroize();
        m1.fast_zeroize();

        padded.fast_zeroize();
        pt_buf.fast_zeroize();
    }

    // === Finalize ===
    let mut len_block = [0u8; 16];
    let mut ad_bits = (aad.len() as u64) * 8;
    let mut msg_bits = (ct_len as u64) * 8;
    u64_to_le(&mut ad_bits, (&mut len_block[..8]).try_into().expect("Infallible: len_block is [u8; 16], so [..8] is exactly 8 bytes"));
    u64_to_le(&mut msg_bits, (&mut len_block[8..]).try_into().expect("Infallible: len_block is [u8; 16], so [8..] is exactly 8 bytes"));

    let mut len_intrinsic = Intrinsics::load(&len_block);
    let mut t = s2.xor(&len_intrinsic);
    len_intrinsic.fast_zeroize();

    let mut t_buf = [0u8; 16];
    t.store(&mut t_buf);
    t.fast_zeroize();

    // 7 finalization rounds
    for _ in 0..7 {
        let mut t_block = Intrinsics::load(&t_buf);
        update(
            &mut s0, &mut s1, &mut s2, &mut s3, &mut s4, &mut s5, &mut s6, &mut s7, &t_block,
            &t_block,
        );
        t_block.fast_zeroize();
    }

    // Compute tag
    let mut tag_block = s0.xor(&s1);
    tag_block.xor_in_place(&s2);
    tag_block.xor_in_place(&s3);
    tag_block.xor_in_place(&s4);
    tag_block.xor_in_place(&s5);
    tag_block.xor_in_place(&s6);

    let mut computed_tag = [0u8; 16];
    tag_block.store(&mut computed_tag);
    tag_block.fast_zeroize();

    // Constant-time tag comparison
    let tag_ok = memutil::constant_time_eq(&computed_tag, expected_tag);

    // === Zeroize all state ===
    s0.fast_zeroize();
    s1.fast_zeroize();
    s2.fast_zeroize();
    s3.fast_zeroize();
    s4.fast_zeroize();
    s5.fast_zeroize();
    s6.fast_zeroize();
    s7.fast_zeroize();
    len_block.fast_zeroize();
    t_buf.fast_zeroize();
    computed_tag.fast_zeroize();

    // Zeroize data on tag mismatch
    if !tag_ok {
        data.fast_zeroize();
    }

    tag_ok
}

/// Core state update function.
///
/// Updates state in-place using mutable references.
/// All intermediate values are explicitly zeroized.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn update(
    s0: &mut Intrinsics,
    s1: &mut Intrinsics,
    s2: &mut Intrinsics,
    s3: &mut Intrinsics,
    s4: &mut Intrinsics,
    s5: &mut Intrinsics,
    s6: &mut Intrinsics,
    s7: &mut Intrinsics,
    m0: &Intrinsics,
    m1: &Intrinsics,
) {
    // Compute XOR temps for s0^m0 and s4^m1
    let mut t0 = s0.xor(m0);
    let mut t4 = s4.xor(m1);

    // Compute all new state values
    let mut ns0 = s7.aes_enc(&t0);
    let mut ns1 = s0.aes_enc(s1);
    let mut ns2 = s1.aes_enc(s2);
    let mut ns3 = s2.aes_enc(s3);
    let mut ns4 = s3.aes_enc(&t4);
    let mut ns5 = s4.aes_enc(s5);
    let mut ns6 = s5.aes_enc(s6);
    let mut ns7 = s6.aes_enc(s7);

    // Zeroize XOR temps
    t0.fast_zeroize();
    t4.fast_zeroize();

    // Move new state to old state (zeroizes ns* via move_to)
    ns0.move_to(s0);
    ns1.move_to(s1);
    ns2.move_to(s2);
    ns3.move_to(s3);
    ns4.move_to(s4);
    ns5.move_to(s5);
    ns6.move_to(s6);
    ns7.move_to(s7);
}
