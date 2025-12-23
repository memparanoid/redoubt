// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! FFI bindings for SHA-256 assembly implementations

#[cfg(all(
    not(feature = "pure-rust"),
    any(
        all(target_arch = "aarch64", not(target_family = "wasm")),
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos"),
            not(target_family = "wasm")
        )
    )
))]
unsafe extern "C" {
    /// SHA-256 compression function (single block)
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `h_ptr` points to valid 32-byte buffer (8 × u32, little-endian)
    /// - `block_ptr` points to valid 64-byte message block
    /// - No data races
    ///
    /// # Parameters
    ///
    /// - `h_ptr`: Pointer to H state (input/output, 32 bytes)
    /// - `block_ptr`: Pointer to message block (input, 64 bytes)
    pub(crate) unsafe fn sha256_compress_block(h_ptr: *mut u32, block_ptr: *const u8);

    /// SHA-256 hash function (arbitrary-length message)
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `msg_ptr` points to valid `msg_len` bytes
    /// - `digest_ptr` points to valid 32-byte buffer
    /// - No data races
    ///
    /// # Parameters
    ///
    /// - `msg_ptr`: Pointer to message (input, arbitrary length)
    /// - `msg_len`: Length of message in bytes
    /// - `digest_ptr`: Pointer to digest output (output, 32 bytes)
    pub(crate) unsafe fn sha256_hash(msg_ptr: *const u8, msg_len: usize, digest_ptr: *mut u8);

    /// HMAC-SHA256 (RFC 2104)
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `key_ptr` points to valid `key_len` bytes
    /// - `msg_ptr` points to valid `msg_len` bytes
    /// - `mac_ptr` points to valid 32-byte buffer
    /// - No data races
    ///
    /// # Parameters
    ///
    /// - `key_ptr`: Pointer to key (input, arbitrary length)
    /// - `key_len`: Length of key in bytes
    /// - `msg_ptr`: Pointer to message (input, arbitrary length)
    /// - `msg_len`: Length of message in bytes
    /// - `mac_ptr`: Pointer to MAC output (output, 32 bytes)
    pub(crate) unsafe fn hmac_sha256(
        key_ptr: *const u8,
        key_len: usize,
        msg_ptr: *const u8,
        msg_len: usize,
        mac_ptr: *mut u8,
    );

    /// HKDF-SHA256 (RFC 5869)
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `salt_ptr` points to valid `salt_len` bytes
    /// - `ikm_ptr` points to valid `ikm_len` bytes
    /// - `info_ptr` points to valid `info_len` bytes
    /// - `okm_ptr` points to valid `okm_len` bytes
    /// - No data races
    ///
    /// # Parameters
    ///
    /// - `salt_ptr`: Pointer to salt (input, arbitrary length)
    /// - `salt_len`: Length of salt in bytes
    /// - `ikm_ptr`: Pointer to input keying material (input, arbitrary length)
    /// - `ikm_len`: Length of IKM in bytes
    /// - `info_ptr`: Pointer to info/context (input, arbitrary length)
    /// - `info_len`: Length of info in bytes
    /// - `okm_ptr`: Pointer to output keying material (output, okm_len bytes)
    /// - `okm_len`: Length of OKM in bytes
    pub(crate) unsafe fn hkdf_sha256(
        salt_ptr: *const u8,
        salt_len: usize,
        ikm_ptr: *const u8,
        ikm_len: usize,
        info_ptr: *const u8,
        info_len: usize,
        okm_ptr: *mut u8,
        okm_len: usize,
    );
}
