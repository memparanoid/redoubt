// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Master key storage
#[cfg(any(test, feature = "test-utils"))]
use core::sync::atomic::Ordering;

use redoubt_alloc::RedoubtVec;
use redoubt_buffer::BufferError;
use redoubt_hkdf::hkdf;
use redoubt_zero::ZeroizingGuard;

pub mod buffer;
pub mod consts;
pub mod storage;

#[cfg(any(test, feature = "test-utils"))]
use crate::utils::{CIPHERBOX_UID, this_process};

use consts::{CIPHERBOX_KEY_INFO_LEN, CIPHERBOX_KEY_INFO_PREFIX, MASTER_KEY_LEN};

/// A caller asking for more of the master key than there is.
#[derive(Debug, thiserror::Error)]
#[error(
    "a master key of {} bytes cannot be truncated to {asked}",
    MASTER_KEY_LEN
)]
pub struct TruncationTooWide {
    /// The width that was asked for.
    pub asked: usize,
}

/// The HKDF info a box derives its key under. The pid is in it because a
/// forked child holds the parent's master key and counts uids from the same
/// value.
pub(crate) fn cipherbox_key_info(pid: u32, uid: usize) -> [u8; CIPHERBOX_KEY_INFO_LEN] {
    let mut info = [0_u8; CIPHERBOX_KEY_INFO_LEN];
    let (prefix, rest) = info.split_at_mut(CIPHERBOX_KEY_INFO_PREFIX.len());
    let (pid_bytes, uid_bytes) = rest.split_at_mut(4);

    prefix.copy_from_slice(CIPHERBOX_KEY_INFO_PREFIX);
    pid_bytes.copy_from_slice(&pid.to_le_bytes());
    uid_bytes.copy_from_slice(&(uid as u64).to_le_bytes());

    info
}

pub(crate) fn derive_cipherbox_key(
    key_size: usize,
    info: &[u8; CIPHERBOX_KEY_INFO_LEN],
) -> Result<ZeroizingGuard<RedoubtVec<u8>>, BufferError> {
    let mut key = ZeroizingGuard::<RedoubtVec<u8>>::from_default();

    key.default_init_to_size(key_size);

    storage::open(&mut |master_key| {
        if key_size > MASTER_KEY_LEN {
            return Err(BufferError::callback_error(TruncationTooWide {
                asked: key_size,
            }));
        }

        hkdf(&[], master_key, info, key.as_mut_slice())
            .expect("Infallible: key_size is at most MASTER_KEY_LEN, far below 255 digests");

        Ok(())
    })?;

    Ok(key)
}

/// The key the next `CipherBox` made in this process will encrypt with, for a
/// test that watches for it before the box exists.
#[cfg(any(test, feature = "test-utils"))]
pub fn derive_next_cipherbox_key(
    key_size: usize,
) -> Result<ZeroizingGuard<RedoubtVec<u8>>, BufferError> {
    let info = cipherbox_key_info(this_process(), CIPHERBOX_UID.load(Ordering::Relaxed));

    derive_cipherbox_key(key_size, &info)
}

#[cfg(test)]
pub fn leak_master_key(truncate_at: usize) -> Result<ZeroizingGuard<RedoubtVec<u8>>, BufferError> {
    let mut master_key = ZeroizingGuard::<RedoubtVec<u8>>::from_default();

    master_key.default_init_to_size(truncate_at);

    storage::open(&mut |mk| {
        // NOTE: Validation is inside the closure (not before vec allocation) for test coverage.
        // The `?` operator needs to be covered, and having it only inside the closure ensures
        // it can be tested. In practice, truncate_at is always 16 or 32 bytes (never fails).
        if truncate_at > MASTER_KEY_LEN {
            return Err(BufferError::callback_error(TruncationTooWide {
                asked: truncate_at,
            }));
        }

        // Not `copy_from_slice`, which is `core::ptr::copy_nonoverlapping`
        // underneath. A length the compiler cannot see is a call into the C
        // library's `memcpy`, and glibc's moves the bytes through vector
        // registers that nothing afterwards writes over — so the whole key
        // stays in one of them until the process ends. This copy erases the
        // registers it used.
        //
        // SAFETY: `mk` is at least `truncate_at` long, checked above against
        // `MASTER_KEY_LEN`, and `master_key` was created with exactly that
        // length. The two are different allocations, so they cannot overlap.
        unsafe {
            redoubt_mem::copy_nonoverlapping(mk.as_ptr(), master_key.as_mut_ptr(), truncate_at);
        }

        Ok(())
    })?;

    Ok(master_key)
}
