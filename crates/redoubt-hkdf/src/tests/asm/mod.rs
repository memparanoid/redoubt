// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

extern crate alloc;

mod sha;

// #[test]
// fn test_hkdf_sha256_simple() {
//     let salt = b"salt";
//     let ikm = b"input key material";
//     let info = b"info";
//     let mut okm = [0u8; 42];

//     unsafe {
//         crate::asm::hkdf_sha256(
//             salt.as_ptr(),
//             salt.len(),
//             ikm.as_ptr(),
//             ikm.len(),
//             info.as_ptr(),
//             info.len(),
//             okm.as_mut_ptr(),
//             okm.len(),
//         );
//     }

//     println!("HKDF-SHA256 OKM: {:02x?}", &okm[..]);
// }

// #[test]
// fn test_hkdf_extract_rfc5869_case1() {
//     // RFC 5869 Test Case 1 - Extract phase only
//     // PRK = HMAC-SHA256(salt, IKM)
//     let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//     let salt = hex::decode("000102030405060708090a0b0c").unwrap();
//     let expected_prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();

//     let mut prk = [0u8; 32];
//     unsafe {
//         crate::asm::hmac_sha256(
//             salt.as_ptr(),
//             salt.len(),
//             ikm.as_ptr(),
//             ikm.len(),
//             prk.as_mut_ptr(),
//         );
//     }

//     println!("Expected PRK: {}", hex::encode(&expected_prk));
//     println!("Got PRK:      {}", hex::encode(&prk));
//     assert_eq!(&prk[..], &expected_prk[..], "Extract (PRK) mismatch");
// }

// #[test]
// fn test_hkdf_rfc5869_case1() {
//     // RFC 5869 Test Case 1
//     let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//     let salt = hex::decode("000102030405060708090a0b0c").unwrap();
//     let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
//     let mut okm = [0u8; 42];

//     unsafe {
//         crate::asm::hkdf_sha256(
//             salt.as_ptr(),
//             salt.len(),
//             ikm.as_ptr(),
//             ikm.len(),
//             info.as_ptr(),
//             info.len(),
//             okm.as_mut_ptr(),
//             okm.len(),
//         );
//     }

//     let expected = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();
//     println!("Expected OKM: {}", hex::encode(&expected));
//     println!("Got OKM:      {}", hex::encode(&okm));
//     assert_eq!(&okm[..], &expected[..], "RFC 5869 Test Case 1 failed");
// }

// mod hex {
//     use super::alloc::string::String;
//     use super::alloc::format;
//     use super::alloc::vec::Vec;

//     pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
//         (0..s.len())
//             .step_by(2)
//             .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
//             .collect()
//     }

//     pub fn encode(data: &[u8]) -> String {
//         data.iter().map(|b| format!("{:02x}", b)).collect()
//     }
// }
