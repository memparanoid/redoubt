// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! AEGIS-128L implementation with in-place operations for guaranteed zeroization.
//!
//! Uses local variables with explicit zeroization of all intermediates.
//! All Intrinsics are either zeroized explicitly or via move_to.

use zeroize::Zeroize;

use memutil::u64_to_le;

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
#[inline]
#[target_feature(enable = "aes")]
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
    c0.zeroize();
    c1.zeroize();

    // 10 init rounds with (nonce, key)
    for _ in 0..10 {
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &nonce_block, &key_block,
        );
    }

    // Clean up key/nonce blocks
    key_block.zeroize();
    nonce_block.zeroize();

    // === Absorb AAD ===
    let mut aad_iter = aad.chunks_exact(BLOCK_SIZE);
    for block in aad_iter.by_ref() {
        let mut m0 = Intrinsics::load(block[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(block[16..].try_into().unwrap());
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
    }

    // Partial AAD block
    let aad_remainder = aad_iter.remainder();
    if !aad_remainder.is_empty() {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..aad_remainder.len()].copy_from_slice(aad_remainder);
        let mut m0 = Intrinsics::load(padded[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(padded[16..].try_into().unwrap());
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
        padded.zeroize();
    }

    // === Encrypt data ===
    let msg_len = data.len();
    let mut data_iter = data.chunks_exact_mut(BLOCK_SIZE);
    for block in data_iter.by_ref() {
        // Compute keystream: z0 = s1 ^ s6 ^ (s2 & s3)
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_assign(&t0);
        t0.zeroize();

        // z1 = s2 ^ s5 ^ (s6 & s7)
        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_assign(&t1);
        t1.zeroize();

        // Load plaintext
        let mut m0 = Intrinsics::load(block[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(block[16..].try_into().unwrap());

        // Encrypt: ciphertext = plaintext ^ keystream
        let mut c0 = m0.xor(&z0);
        let mut c1 = m1.xor(&z1);
        c0.store((&mut block[..16]).try_into().unwrap());
        c1.store((&mut block[16..]).try_into().unwrap());
        c0.zeroize();
        c1.zeroize();
        z0.zeroize();
        z1.zeroize();

        // Update state with plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
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
        z0.xor_assign(&t0);
        t0.zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_assign(&t1);
        t1.zeroize();

        // Load padded plaintext
        let mut m0 = Intrinsics::load(padded[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(padded[16..].try_into().unwrap());

        // Encrypt
        let mut c0 = m0.xor(&z0);
        let mut c1 = m1.xor(&z1);
        z0.zeroize();
        z1.zeroize();

        // Store only the valid ciphertext bytes
        let mut ct_buf = [0u8; BLOCK_SIZE];
        c0.store((&mut ct_buf[..16]).try_into().unwrap());
        c1.store((&mut ct_buf[16..]).try_into().unwrap());
        data_remainder.copy_from_slice(&ct_buf[..len]);
        c0.zeroize();
        c1.zeroize();

        // Update state with padded plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();

        padded.zeroize();
        ct_buf.zeroize();
    }

    // === Finalize ===
    let mut len_block = [0u8; 16];
    let mut ad_bits = (aad.len() as u64) * 8;
    let mut msg_bits = (msg_len as u64) * 8;
    u64_to_le(&mut ad_bits, (&mut len_block[..8]).try_into().unwrap());
    u64_to_le(&mut msg_bits, (&mut len_block[8..]).try_into().unwrap());

    let mut len_intrinsic = Intrinsics::load(&len_block);
    let mut t = s2.xor(&len_intrinsic);
    len_intrinsic.zeroize();

    let mut t_buf = [0u8; 16];
    t.store(&mut t_buf);
    t.zeroize();

    // 7 finalization rounds with (t, t)
    for _ in 0..7 {
        let mut t_block = Intrinsics::load(&t_buf);
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &t_block, &t_block,
        );
        t_block.zeroize();
    }

    // Compute tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
    let mut tag_block = s0.xor(&s1);
    tag_block.xor_assign(&s2);
    tag_block.xor_assign(&s3);
    tag_block.xor_assign(&s4);
    tag_block.xor_assign(&s5);
    tag_block.xor_assign(&s6);
    tag_block.store(tag);
    tag_block.zeroize();

    // === Zeroize all state ===
    s0.zeroize();
    s1.zeroize();
    s2.zeroize();
    s3.zeroize();
    s4.zeroize();
    s5.zeroize();
    s6.zeroize();
    s7.zeroize();
    len_block.zeroize();
    t_buf.zeroize();
}

/// AEGIS-128L decrypt.
///
/// # Safety
/// Caller must ensure AES hardware support is available.
#[inline]
#[target_feature(enable = "aes")]
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

    c0.zeroize();
    c1.zeroize();

    // 10 init rounds
    for _ in 0..10 {
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &nonce_block, &key_block,
        );
    }

    key_block.zeroize();
    nonce_block.zeroize();

    // === Absorb AAD ===
    let mut aad_iter = aad.chunks_exact(BLOCK_SIZE);
    for block in aad_iter.by_ref() {
        let mut m0 = Intrinsics::load(block[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(block[16..].try_into().unwrap());
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
    }

    let aad_remainder = aad_iter.remainder();
    if !aad_remainder.is_empty() {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..aad_remainder.len()].copy_from_slice(aad_remainder);
        let mut m0 = Intrinsics::load(padded[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(padded[16..].try_into().unwrap());
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
        padded.zeroize();
    }

    // === Decrypt data ===
    let ct_len = data.len();
    let mut data_iter = data.chunks_exact_mut(BLOCK_SIZE);
    for block in data_iter.by_ref() {
        // Compute keystream
        let mut z0 = s1.xor(&s6);
        let mut t0 = s2.and(&s3);
        z0.xor_assign(&t0);
        t0.zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_assign(&t1);
        t1.zeroize();

        // Load ciphertext
        let mut ct0 = Intrinsics::load(block[..16].try_into().unwrap());
        let mut ct1 = Intrinsics::load(block[16..].try_into().unwrap());

        // Decrypt: plaintext = ciphertext ^ keystream
        let mut m0 = ct0.xor(&z0);
        let mut m1 = ct1.xor(&z1);
        m0.store((&mut block[..16]).try_into().unwrap());
        m1.store((&mut block[16..]).try_into().unwrap());
        ct0.zeroize();
        ct1.zeroize();
        z0.zeroize();
        z1.zeroize();

        // Update state with plaintext
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();
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
        z0.xor_assign(&t0);
        t0.zeroize();

        let mut z1 = s2.xor(&s5);
        let mut t1 = s6.and(&s7);
        z1.xor_assign(&t1);
        t1.zeroize();

        // Load padded ciphertext
        let mut ct0 = Intrinsics::load(padded[..16].try_into().unwrap());
        let mut ct1 = Intrinsics::load(padded[16..].try_into().unwrap());

        // Decrypt
        let mut pt0 = ct0.xor(&z0);
        let mut pt1 = ct1.xor(&z1);
        ct0.zeroize();
        ct1.zeroize();
        z0.zeroize();
        z1.zeroize();

        // Store plaintext to temp buffer
        let mut pt_buf = [0u8; BLOCK_SIZE];
        pt0.store((&mut pt_buf[..16]).try_into().unwrap());
        pt1.store((&mut pt_buf[16..]).try_into().unwrap());

        // Copy only valid plaintext bytes
        data_remainder.copy_from_slice(&pt_buf[..len]);

        // Update state with zero-padded plaintext
        pt_buf[len..].fill(0);
        let mut m0 = Intrinsics::load(pt_buf[..16].try_into().unwrap());
        let mut m1 = Intrinsics::load(pt_buf[16..].try_into().unwrap());
        pt0.zeroize();
        pt1.zeroize();

        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &m0, &m1,
        );
        m0.zeroize();
        m1.zeroize();

        padded.zeroize();
        pt_buf.zeroize();
    }

    // === Finalize ===
    let mut len_block = [0u8; 16];
    let mut ad_bits = (aad.len() as u64) * 8;
    let mut msg_bits = (ct_len as u64) * 8;
    u64_to_le(&mut ad_bits, (&mut len_block[..8]).try_into().unwrap());
    u64_to_le(&mut msg_bits, (&mut len_block[8..]).try_into().unwrap());

    let mut len_intrinsic = Intrinsics::load(&len_block);
    let mut t = s2.xor(&len_intrinsic);
    len_intrinsic.zeroize();

    let mut t_buf = [0u8; 16];
    t.store(&mut t_buf);
    t.zeroize();

    // 7 finalization rounds
    for _ in 0..7 {
        let mut t_block = Intrinsics::load(&t_buf);
        update(
            &mut s0, &mut s1, &mut s2, &mut s3,
            &mut s4, &mut s5, &mut s6, &mut s7,
            &t_block, &t_block,
        );
        t_block.zeroize();
    }

    // Compute tag
    let mut tag_block = s0.xor(&s1);
    tag_block.xor_assign(&s2);
    tag_block.xor_assign(&s3);
    tag_block.xor_assign(&s4);
    tag_block.xor_assign(&s5);
    tag_block.xor_assign(&s6);

    let mut computed_tag = [0u8; 16];
    tag_block.store(&mut computed_tag);
    tag_block.zeroize();

    // Constant-time tag comparison
    let tag_ok = memutil::constant_time_eq(&computed_tag, expected_tag);

    // === Zeroize all state ===
    s0.zeroize();
    s1.zeroize();
    s2.zeroize();
    s3.zeroize();
    s4.zeroize();
    s5.zeroize();
    s6.zeroize();
    s7.zeroize();
    len_block.zeroize();
    t_buf.zeroize();
    computed_tag.zeroize();

    // Zeroize data on tag mismatch
    if !tag_ok {
        data.zeroize();
    }

    tag_ok
}

/// Core state update function.
///
/// Updates state in-place using mutable references.
/// All intermediate values are explicitly zeroized.
#[inline(always)]
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
    t0.zeroize();
    t4.zeroize();

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
