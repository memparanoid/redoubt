// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::decrypt::decrypt_mem_decodable;
use crate::encrypt::encrypt_mem_encodable;

use super::support::{
    MemCodeTestBreaker, MemCodeTestBreakerBehaviour, create_key_from_array,
    create_xnonce_from_array,
};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let mut aead_key = create_key_from_array([1u8; 32]);
    let mut xnonce = create_xnonce_from_array([2u8; 24]);
    let mut test_breaker = MemCodeTestBreaker::new(MemCodeTestBreakerBehaviour::None);

    let test_breaker_snapshot = format!("{:?}", test_breaker);

    let mut ciphertext = {
        let mut aead_key_clone = create_key_from_array([1u8; 32]);
        let mut xnonce_clone = create_xnonce_from_array([2u8; 24]);
        encrypt_mem_encodable(&mut aead_key_clone, &mut xnonce_clone, &mut test_breaker)
            .expect("Failed to encrypt_mem_encodable(..)")
    };

    let recovered_test_breaker =
        decrypt_mem_decodable::<MemCodeTestBreaker>(&mut aead_key, &mut xnonce, &mut ciphertext)
            .expect("Failed to decrypt_mem_decodable(..)");

    let recovered_test_breaker_snapshot = format!("{:?}", &*recovered_test_breaker);

    assert_eq!(test_breaker_snapshot, recovered_test_breaker_snapshot);
}
