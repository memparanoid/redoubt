// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use crate::generate_random_key::generate_random_key;

#[test]
fn test_generate_random_key_supports_empty_key() {
    let mut empty = [];
    let result = generate_random_key(b"test.empty", &mut empty);

    assert!(result.is_ok());
}

#[test]
fn test_generate_random_key_supports_common_key_sizes() -> Result<(), Box<dyn std::error::Error>> {
    // Verify function succeeds for typical cryptographic key sizes
    let mut key16 = [0u8; 16];
    generate_random_key(b"test.aes128", &mut key16)?;

    let mut key32 = [0u8; 32];
    generate_random_key(b"test.xchacha20", &mut key32)?;

    let mut key64 = [0u8; 64];
    generate_random_key(b"test.hmac512", &mut key64)?;

    // Edge cases
    let mut key1 = [0u8; 1];
    generate_random_key(b"test.tiny", &mut key1)?;

    let mut key128 = [0u8; 128];
    generate_random_key(b"test.large", &mut key128)?;

    Ok(())
}

#[test]
fn test_generate_random_key_info_provides_domain_separation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut master_key = [0u8; 32];
    generate_random_key(b"app.master_key.v1", &mut master_key)?;

    let mut encryption_key = [0u8; 32];
    generate_random_key(b"app.encryption_key.v1", &mut encryption_key)?;

    let mut signing_key = [0u8; 32];
    generate_random_key(b"app.signing_key.v1", &mut signing_key)?;

    // All keys must be different due to info parameter
    assert_ne!(master_key, encryption_key);
    assert_ne!(master_key, signing_key);
    assert_ne!(encryption_key, signing_key);

    Ok(())
}

#[cfg(target_os = "linux")]
mod seccomp_getrandom {
    use redoubt_test_utils::run_test_as_subprocess;

    use crate::error::EntropyError;
    use crate::generate_random_key::generate_random_key;

    use crate::tests::utils::block_getrandom;

    #[test]
    #[ignore]
    fn subprocess_test_generate_random_key_propagates_entropy_not_available() {
        let mut key = [0_u8; 32];

        block_getrandom();

        let result = generate_random_key(b"test.refused", &mut key);

        assert!(matches!(result, Err(EntropyError::EntropyNotAvailable)));
    }

    #[test]
    fn test_generate_random_key_propagates_entropy_not_available() {
        let exit_code = run_test_as_subprocess(
            "tests::generate_random_key::seccomp_getrandom::subprocess_test_generate_random_key_propagates_entropy_not_available",
        );

        assert_eq!(exit_code, Some(0), "the refused fill did not propagate");
    }
}
