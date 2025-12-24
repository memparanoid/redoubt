// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod tests {
    use redoubt_codec::RedoubtCodec;
    use redoubt_vault_derive::cipherbox;
    use redoubt_zero::{RedoubtZero, ZeroizationProbe};

    #[cipherbox(WalletSecretsCipherBox)]
    #[derive(Default, RedoubtZero, RedoubtCodec)]
    #[fast_zeroize(drop)]
    struct WalletSecrets {
        master_seed: [u8; 32],
        encryption_key: [u8; 32],
        signing_key: [u8; 32],
        pin_hash: [u8; 32],
    }

    #[test]
    fn test_cipherbox_wrapper_new() {
        let _cb = WalletSecretsCipherBox::new();
    }

    #[test]
    fn test_cipherbox_wrapper_default() {
        let _cb = WalletSecretsCipherBox::default();
    }

    #[test]
    fn test_cipherbox_wrapper_open() {
        let mut cb = WalletSecretsCipherBox::new();

        cb.open(|ws| {
            assert!(ws.master_seed.is_zeroized());
            assert!(ws.encryption_key.is_zeroized());
            assert!(ws.signing_key.is_zeroized());
            assert!(ws.pin_hash.is_zeroized());

            Ok(())
        })
        .expect("Failed to open(..)");
    }

    #[test]
    fn test_cipherbox_wrapper_open_mut() {
        let mut cb = WalletSecretsCipherBox::new();

        cb.open_mut(|ws| {
            ws.master_seed = [0x42; 32];
            ws.encryption_key = [0xAB; 32];
            ws.signing_key = [0xCD; 32];
            ws.pin_hash = [0xEF; 32];

            Ok(())
        })
        .expect("Failed to open_mut(..)");

        cb.open(|ws| {
            assert_eq!(ws.master_seed, [0x42; 32]);
            assert_eq!(ws.encryption_key, [0xAB; 32]);
            assert_eq!(ws.signing_key, [0xCD; 32]);
            assert_eq!(ws.pin_hash, [0xEF; 32]);

            Ok(())
        })
        .expect("Failed to open(..)");
    }

    #[test]
    fn test_cipherbox_wrapper_open_field() {
        let mut cb = WalletSecretsCipherBox::new();

        // Set values
        cb.open_mut(|ws| {
            ws.master_seed = [0x42; 32];
            ws.encryption_key = [0xAB; 32];
            ws.signing_key = [0xCD; 32];
            ws.pin_hash = [0xEF; 32];

            Ok(())
        })
        .expect("Failed to open_mut(..)");

        // Read individual fields
        cb.open_master_seed(|seed| {
            assert_eq!(*seed, [0x42; 32]);
            Ok(())
        })
        .expect("Failed to open_master_seed(..)");

        cb.open_encryption_key(|key| {
            assert_eq!(*key, [0xAB; 32]);
            Ok(())
        })
        .expect("Failed to open_encryption_key(..)");

        cb.open_signing_key(|key| {
            assert_eq!(*key, [0xCD; 32]);
            Ok(())
        })
        .expect("Failed to open_signing_key(..)");

        cb.open_pin_hash(|hash| {
            assert_eq!(*hash, [0xEF; 32]);
            Ok(())
        })
        .expect("Failed to open_pin_hash(..)");
    }

    #[test]
    fn test_cipherbox_wrapper_open_field_mut() {
        let mut cb = WalletSecretsCipherBox::new();

        // Modify individual fields
        cb.open_master_seed_mut(|seed| {
            *seed = [0x42; 32];
            Ok(())
        })
        .expect("Failed to open_master_seed_mut(..)");

        cb.open_encryption_key_mut(|key| {
            *key = [0xAB; 32];
            Ok(())
        })
        .expect("Failed to open_encryption_key_mut(..)");

        cb.open_signing_key_mut(|key| {
            *key = [0xCD; 32];
            Ok(())
        })
        .expect("Failed to open_signing_key_mut(..)");

        cb.open_pin_hash_mut(|hash| {
            *hash = [0xEF; 32];
            Ok(())
        })
        .expect("Failed to open_pin_hash_mut(..)");

        // Verify all fields
        cb.open(|ws| {
            assert_eq!(ws.master_seed, [0x42; 32]);
            assert_eq!(ws.encryption_key, [0xAB; 32]);
            assert_eq!(ws.signing_key, [0xCD; 32]);
            assert_eq!(ws.pin_hash, [0xEF; 32]);

            Ok(())
        })
        .expect("Failed to open(..)");
    }

    #[test]
    fn test_cipherbox_wrapper_leak_field() {
        let mut cb = WalletSecretsCipherBox::new();

        // Set values
        cb.open_mut(|ws| {
            ws.master_seed = [0x42; 32];
            ws.encryption_key = [0xAB; 32];

            Ok(())
        })
        .expect("Failed to open_mut(..)");

        // Leak individual fields
        let seed = cb
            .leak_master_seed()
            .expect("Failed to leak_master_seed(..)");
        assert_eq!(*seed, [0x42; 32]);

        let key = cb
            .leak_encryption_key()
            .expect("Failed to leak_encryption_key(..)");
        assert_eq!(*key, [0xAB; 32]);

        // Verify original cipherbox is unchanged
        cb.open(|ws| {
            assert_eq!(ws.master_seed, [0x42; 32]);
            assert_eq!(ws.encryption_key, [0xAB; 32]);

            Ok(())
        })
        .expect("Failed to open(..)");
    }

    #[test]
    fn test_cipherbox_api() {
        let mut cb = WalletSecretsCipherBox::new();

        // Set values
        cb.open_mut(|ws| {
            ws.master_seed = [0x42; 32];
            ws.encryption_key = [0xAB; 32];

            Ok(())
        })
        .expect("Failed to open_mut(..)");

        // Extract the first byte from each field
        let first_master_seed_byte = cb
            .open(|ws| Ok(ws.master_seed[0]))
            .expect("Failed to open(..)");
        let first_encryption_key_byte = cb
            .open(|ws| Ok(ws.encryption_key[0]))
            .expect("Failed to open(..)");

        assert_eq!(first_master_seed_byte, 0x42);
        assert_eq!(first_encryption_key_byte, 0xAB);
    }

    // Custom error type for testing
    // Note: CipherBox field required for From impl, but not inspected in tests
    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum CustomError {
        CipherBox(redoubt_vault_core::CipherBoxError),
        IntentionalCustomError,
    }

    impl From<redoubt_vault_core::CipherBoxError> for CustomError {
        fn from(e: redoubt_vault_core::CipherBoxError) -> Self {
            CustomError::CipherBox(e)
        }
    }

    #[cipherbox(CustomErrorBox, error = CustomError)]
    #[derive(Default, RedoubtZero, RedoubtCodec)]
    #[fast_zeroize(drop)]
    struct CustomErrorSecrets {
        data: [u8; 32],
    }

    #[test]
    fn test_custom_error_intentional_failure() {
        let mut cb = CustomErrorBox::new();
        let result: Result<(), CustomError> = cb.open(|_| Err(CustomError::IntentionalCustomError));

        assert!(matches!(result, Err(CustomError::IntentionalCustomError)));
    }
}
