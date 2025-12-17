// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// AEGIS-128L assembly implementations

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    /// Performs one AEGIS-128L state update round with message absorption.
    ///
    /// # Safety
    /// - `state` must point to 128 bytes (8 blocks of 16 bytes each) and be 16-byte aligned
    /// - `m0` must point to 16 bytes (first message block)
    /// - `m1` must point to 16 bytes (second message block)
    pub fn aegis128l_update(state: *mut [u8; 128], m0: *const [u8; 16], m1: *const [u8; 16]);

    /// Initializes AEGIS-128L state with key and nonce.
    ///
    /// # Safety
    /// - `state` must point to 128 bytes (8 blocks of 16 bytes each) and be 16-byte aligned
    /// - `key` must point to 16 bytes
    /// - `nonce` must point to 16 bytes
    pub fn aegis128l_init(state: *mut [u8; 128], key: *const [u8; 16], nonce: *const [u8; 16]);

    /// Performs complete AEGIS-128L encryption.
    ///
    /// # Safety
    /// - All pointers must be valid for their specified lengths
    /// - `ciphertext` buffer must be at least `plaintext_len` bytes
    /// - `tag` must point to 16 bytes
    pub fn aegis128l_encrypt(
        key: *const [u8; 16],
        nonce: *const [u8; 16],
        aad: *const u8,
        aad_len: usize,
        plaintext: *const u8,
        plaintext_len: usize,
        ciphertext: *mut u8,
        tag: *mut [u8; 16],
    );

    pub fn aegis128l_decrypt(
        key: *const [u8; 16],
        nonce: *const [u8; 16],
        aad: *const u8,
        aad_len: usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
        plaintext: *mut u8,
        expected_tag: *const [u8; 16],
        computed_tag: *mut [u8; 16],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_aegis128l_update_rfc_vectors() {
        // Test vectors from AEGIS RFC: (Section A.2.1)

        // S0   : 9b7e60b24cc873ea894ecc07911049a3
        // S1   : 330be08f35300faa2ebf9a7b0d274658
        // S2   : 7bbd5bd2b049f7b9b515cf26fbe7756c
        // S3   : c35a00f55ea86c3886ec5e928f87db18
        // S4   : 9ebccafce87cab446396c4334592c91f
        // S5   : 58d83e31f256371e60fc6bb257114601
        // S6   : 1639b56ea322c88568a176585bc915de
        // S7   : 640818ffb57dc0fbc2e72ae93457e39a

        // M0   : 033e6975b94816879e42917650955aa0
        // M1   : fcc1968a46b7e97861bd6e89af6aa55f

        // After Update:

        // S0   : 596ab773e4433ca0127c73f60536769d
        // S1   : 790394041a3d26ab697bde865014652d
        // S2   : 38cf49e4b65248acd533041b64dd0611
        // S3   : 16d8e58748f437bfff1797f780337cee
        // S4   : 9689ecdf08228c74d7e3360cca53d0a5
        // S5   : a21746bb193a569e331e1aa985d0d729
        // S6   : 09d714e6fcf9177a8ed1cde7e3d259a6
        // S7   : 61279ba73167f0ab76f0a11bf203bdff

        // Initial state S0-S7
        let mut state: [u8; 128] = [
            // S0
            0x9b, 0x7e, 0x60, 0xb2, 0x4c, 0xc8, 0x73, 0xea, 0x89, 0x4e, 0xcc, 0x07, 0x91, 0x10,
            0x49, 0xa3, // S1
            0x33, 0x0b, 0xe0, 0x8f, 0x35, 0x30, 0x0f, 0xaa, 0x2e, 0xbf, 0x9a, 0x7b, 0x0d, 0x27,
            0x46, 0x58, // S2
            0x7b, 0xbd, 0x5b, 0xd2, 0xb0, 0x49, 0xf7, 0xb9, 0xb5, 0x15, 0xcf, 0x26, 0xfb, 0xe7,
            0x75, 0x6c, // S3
            0xc3, 0x5a, 0x00, 0xf5, 0x5e, 0xa8, 0x6c, 0x38, 0x86, 0xec, 0x5e, 0x92, 0x8f, 0x87,
            0xdb, 0x18, // S4
            0x9e, 0xbc, 0xca, 0xfc, 0xe8, 0x7c, 0xab, 0x44, 0x63, 0x96, 0xc4, 0x33, 0x45, 0x92,
            0xc9, 0x1f, // S5
            0x58, 0xd8, 0x3e, 0x31, 0xf2, 0x56, 0x37, 0x1e, 0x60, 0xfc, 0x6b, 0xb2, 0x57, 0x11,
            0x46, 0x01, // S6
            0x16, 0x39, 0xb5, 0x6e, 0xa3, 0x22, 0xc8, 0x85, 0x68, 0xa1, 0x76, 0x58, 0x5b, 0xc9,
            0x15, 0xde, // S7
            0x64, 0x08, 0x18, 0xff, 0xb5, 0x7d, 0xc0, 0xfb, 0xc2, 0xe7, 0x2a, 0xe9, 0x34, 0x57,
            0xe3, 0x9a,
        ];

        // Message blocks M0 and M1
        let m0: [u8; 16] = [
            0x03, 0x3e, 0x69, 0x75, 0xb9, 0x48, 0x16, 0x87, 0x9e, 0x42, 0x91, 0x76, 0x50, 0x95,
            0x5a, 0xa0,
        ];
        let m1: [u8; 16] = [
            0xfc, 0xc1, 0x96, 0x8a, 0x46, 0xb7, 0xe9, 0x78, 0x61, 0xbd, 0x6e, 0x89, 0xaf, 0x6a,
            0xa5, 0x5f,
        ];

        // Expected state after update
        let expected: [u8; 128] = [
            // S0
            0x59, 0x6a, 0xb7, 0x73, 0xe4, 0x43, 0x3c, 0xa0, 0x12, 0x7c, 0x73, 0xf6, 0x05, 0x36,
            0x76, 0x9d, // S1
            0x79, 0x03, 0x94, 0x04, 0x1a, 0x3d, 0x26, 0xab, 0x69, 0x7b, 0xde, 0x86, 0x50, 0x14,
            0x65, 0x2d, // S2
            0x38, 0xcf, 0x49, 0xe4, 0xb6, 0x52, 0x48, 0xac, 0xd5, 0x33, 0x04, 0x1b, 0x64, 0xdd,
            0x06, 0x11, // S3
            0x16, 0xd8, 0xe5, 0x87, 0x48, 0xf4, 0x37, 0xbf, 0xff, 0x17, 0x97, 0xf7, 0x80, 0x33,
            0x7c, 0xee, // S4
            0x96, 0x89, 0xec, 0xdf, 0x08, 0x22, 0x8c, 0x74, 0xd7, 0xe3, 0x36, 0x0c, 0xca, 0x53,
            0xd0, 0xa5, // S5
            0xa2, 0x17, 0x46, 0xbb, 0x19, 0x3a, 0x56, 0x9e, 0x33, 0x1e, 0x1a, 0xa9, 0x85, 0xd0,
            0xd7, 0x29, // S6
            0x09, 0xd7, 0x14, 0xe6, 0xfc, 0xf9, 0x17, 0x7a, 0x8e, 0xd1, 0xcd, 0xe7, 0xe3, 0xd2,
            0x59, 0xa6, // S7
            0x61, 0x27, 0x9b, 0xa7, 0x31, 0x67, 0xf0, 0xab, 0x76, 0xf0, 0xa1, 0x1b, 0xf2, 0x03,
            0xbd, 0xff,
        ];

        // Perform update
        unsafe {
            aegis128l_update(&mut state, &m0, &m1);
        }

        // Verify result matches RFC expected output
        assert_eq!(
            state, expected,
            "AEGIS-128L update does not match RFC test vector"
        );
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_aegis128l_init_direct() {
        // Test init function directly
        #[repr(align(16))]
        struct Aligned16<T>(T);

        let key: Aligned16<[u8; 16]> = Aligned16([0x42; 16]);
        let nonce: Aligned16<[u8; 16]> = Aligned16([0x43; 16]);
        let mut state: Aligned16<[u8; 128]> = Aligned16([0xFF; 128]);

        unsafe {
            aegis128l_init(&mut state.0, &key.0, &nonce.0);
        }

        // Verify state was modified
        assert_ne!(&state.0[..16], &[0xFF; 16], "State S0 should have changed");
        println!("State S0-S1: {:02x?}", &state.0[..32]);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_aegis128l_encrypt_16byte_msg() {
        // AEGIS-128L RFC Test Vector A.2.2 - Test Vector 1
        // key:   10010000000000000000000000000000
        // nonce: 10000200000000000000000000000000
        // ad:    (empty)
        // msg:   00000000000000000000000000000000
        // ct:    c1c0e58bd913006feba00f4b3cc3594e
        // tag:   abe0ece80c24868a226a35d16bdae37a

        let key: [u8; 16] = [
            0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nonce: [u8; 16] = [
            0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext: [u8; 16] = [0x00; 16];
        let mut ciphertext: [u8; 16] = [0xFF; 16];
        let mut tag: [u8; 16] = [0xFF; 16];

        let expected_ciphertext: [u8; 16] = [
            0xc1, 0xc0, 0xe5, 0x8b, 0xd9, 0x13, 0x00, 0x6f,
            0xeb, 0xa0, 0x0f, 0x4b, 0x3c, 0xc3, 0x59, 0x4e,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0xe0, 0xec, 0xe8, 0x0c, 0x24, 0x86, 0x8a,
            0x22, 0x6a, 0x35, 0xd1, 0x6b, 0xda, 0xe3, 0x7a,
        ];

        unsafe {
            aegis128l_encrypt(
                &key,
                &nonce,
                std::ptr::null(),          // No AAD
                0,                          // AAD length = 0
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                &mut tag,
            );
        }

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
            ciphertext, expected_ciphertext
        );

        assert_eq!(
            tag, expected_tag,
            "Tag mismatch.\nGot:      {:02x?}\nExpected: {:02x?}",
            tag, expected_tag
        );
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    #[ignore] // Test after 16-byte works
    fn test_aegis128l_encrypt_aligned() {
        // Test with 16-byte aligned buffers to isolate alignment issue
        #[repr(align(16))]
        struct Aligned16<T>(T);

        let key: Aligned16<[u8; 16]> = Aligned16([0x42; 16]);
        let nonce: Aligned16<[u8; 16]> = Aligned16([0x43; 16]);
        let plaintext: Aligned16<[u8; 32]> = Aligned16([0x00; 32]);
        let mut ciphertext: Aligned16<[u8; 32]> = Aligned16([0xFF; 32]);
        let mut tag: Aligned16<[u8; 16]> = Aligned16([0; 16]);

        // Verify alignment
        assert_eq!((key.0.as_ptr() as usize) % 16, 0, "Key not aligned");
        assert_eq!((nonce.0.as_ptr() as usize) % 16, 0, "Nonce not aligned");
        assert_eq!((plaintext.0.as_ptr() as usize) % 16, 0, "Plaintext not aligned");
        assert_eq!((ciphertext.0.as_ptr() as usize) % 16, 0, "Ciphertext not aligned");

        unsafe {
            aegis128l_encrypt(
                &key.0,
                &nonce.0,
                std::ptr::null(),     // No AAD
                0,                     // AAD length = 0
                plaintext.0.as_ptr(),
                plaintext.0.len(),
                ciphertext.0.as_mut_ptr(),
                &mut tag.0,
            );
        }

        // Verify ciphertext was written
        assert_ne!(ciphertext.0, [0xFF; 32], "Ciphertext should have been written");
        assert_ne!(ciphertext.0, plaintext.0, "Ciphertext should differ from plaintext");

        println!("Ciphertext: {:02x?}", ciphertext.0);
        println!("Tag: {:02x?}", tag.0);
    }
}
