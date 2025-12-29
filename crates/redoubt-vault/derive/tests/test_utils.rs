// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for test-utils feature (failure injection)

#[cfg(test)]
mod test_utils {
    use redoubt_alloc::{RedoubtArray, RedoubtOption, RedoubtString};
    use redoubt_codec::RedoubtCodec;
    use redoubt_secret::RedoubtSecret;
    use redoubt_vault_core::CipherBoxError;
    use redoubt_vault_derive::cipherbox;
    use redoubt_zero::RedoubtZero;

    const MAX_ITERATIONS: usize = 100;

    // Global CipherBox for testing global failure injection
    #[cipherbox(TestGlobalBox, global = true)]
    #[derive(Default, RedoubtCodec, RedoubtZero)]
    struct TestGlobalData {
        field_a: RedoubtArray<u8, 32>,
    }

    #[cipherbox(TestBox)]
    #[derive(Default, RedoubtCodec, RedoubtZero)]
    struct TestData {
        field_a: RedoubtArray<u8, 32>,
        field_b: RedoubtSecret<u64>,
        field_c: RedoubtString,
        field_d: RedoubtOption<RedoubtArray<u8, 16>>,
    }

    /// Macro to test callback-based methods
    macro_rules! test_callback_method {
        ($method:ident) => {
            let mut test_box = TestBox::new();

            for i in 1..=MAX_ITERATIONS {
                test_box.set_failure_mode(TestBoxFailureMode::FailOnNthOperation(i));

                // Make i calls to the method
                for call_num in 1..=i {
                    let result = test_box.$method(|_| Ok(()));

                    if call_num == i {
                        // The ith call should fail
                        assert!(result.is_err());
                        assert!(matches!(
                            result.unwrap_err(),
                            CipherBoxError::IntentionalCipherBoxError
                        ));
                    } else {
                        // Previous calls should succeed
                        assert!(result.is_ok());
                    }
                }
            }

            // Test FailureMode::None - all calls should succeed
            test_box.set_failure_mode(TestBoxFailureMode::None);
            for _ in 0..MAX_ITERATIONS {
                let result = test_box.$method(|_| Ok(()));
                assert!(result.is_ok());
            }
        };
    }

    /// Macro to test leak methods
    macro_rules! test_leak_method {
        ($method:ident) => {
            let mut test_box = TestBox::new();

            for i in 1..=MAX_ITERATIONS {
                test_box.set_failure_mode(TestBoxFailureMode::FailOnNthOperation(i));

                // Make i calls to the method
                for call_num in 1..=i {
                    let result = test_box.$method();

                    if call_num == i {
                        // The ith call should fail
                        assert!(result.is_err());
                        assert!(matches!(
                            result.unwrap_err(),
                            CipherBoxError::IntentionalCipherBoxError
                        ));
                    } else {
                        // Previous calls should succeed
                        assert!(result.is_ok());
                    }
                }
            }

            // Test FailureMode::None - all calls should succeed
            test_box.set_failure_mode(TestBoxFailureMode::None);
            for _ in 0..MAX_ITERATIONS {
                let result = test_box.$method();
                assert!(result.is_ok());
            }
        };
    }

    // Global open methods
    #[test]
    fn test_failure_injection_open() {
        test_callback_method!(open);
    }

    #[test]
    fn test_failure_injection_open_mut() {
        test_callback_method!(open_mut);
    }

    // Field-specific open methods
    #[test]
    fn test_failure_injection_open_field_a() {
        test_callback_method!(open_field_a);
    }

    #[test]
    fn test_failure_injection_open_field_a_mut() {
        test_callback_method!(open_field_a_mut);
    }

    #[test]
    fn test_failure_injection_open_field_b() {
        test_callback_method!(open_field_b);
    }

    #[test]
    fn test_failure_injection_open_field_b_mut() {
        test_callback_method!(open_field_b_mut);
    }

    #[test]
    fn test_failure_injection_open_field_c() {
        test_callback_method!(open_field_c);
    }

    #[test]
    fn test_failure_injection_open_field_c_mut() {
        test_callback_method!(open_field_c_mut);
    }

    #[test]
    fn test_failure_injection_open_field_d() {
        test_callback_method!(open_field_d);
    }

    #[test]
    fn test_failure_injection_open_field_d_mut() {
        test_callback_method!(open_field_d_mut);
    }

    // Global CipherBox tests
    #[test]
    fn test_failure_injection_global_set_failure_mode() {
        // Set failure mode on global
        TEST_GLOBAL_BOX::set_failure_mode(TestGlobalBoxFailureMode::FailOnNthOperation(1));

        // First call should fail
        let result = TEST_GLOBAL_BOX::open(|_| Ok(()));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CipherBoxError::IntentionalCipherBoxError
        ));

        // Reset and try again - should succeed
        TEST_GLOBAL_BOX::set_failure_mode(TestGlobalBoxFailureMode::None);
        let result = TEST_GLOBAL_BOX::open(|_| Ok(()));
        assert!(result.is_ok());
    }

    // Leak methods
    #[test]
    fn test_failure_injection_leak_field_a() {
        test_leak_method!(leak_field_a);
    }

    #[test]
    fn test_failure_injection_leak_field_b() {
        test_leak_method!(leak_field_b);
    }

    #[test]
    fn test_failure_injection_leak_field_c() {
        test_leak_method!(leak_field_c);
    }

    #[test]
    fn test_failure_injection_leak_field_d() {
        test_leak_method!(leak_field_d);
    }
}
