// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Buffer creation logic
use alloc::boxed::Box;

use redoubt_buffer::{Buffer, BufferError, PortableBuffer};
use redoubt_rand::{EntropySource, SystemEntropySource};

#[cfg(all(unix, not(target_os = "wasi")))]
use redoubt_buffer::{PageBuffer, ProtectionStrategy};

use super::consts::MASTER_KEY_LEN;

#[cfg(any(target_os = "wasi", not(unix)))]
pub fn create_buffer() -> Box<dyn Buffer> {
    Box::new(PortableBuffer::create(MASTER_KEY_LEN))
}

#[cfg(all(unix, not(target_os = "wasi")))]
pub fn create_buffer() -> Box<dyn Buffer> {
    // SECURITY: Always use MemProtected for defense in depth.
    // prctl(PR_SET_DUMPABLE) is reversible, so we always add mprotect() layer.
    match PageBuffer::new(ProtectionStrategy::MemProtected, MASTER_KEY_LEN) {
        Ok(buffer) => Box::new(buffer),
        Err(e) => {
            #[cfg(not(feature = "no_std"))]
            {
                eprintln!("\x1b[33m⚠️  SECURITY: Failed to create protected memory page: {:?}\x1b[0m", e);
                eprintln!("\x1b[33m   Falling back to heap (no mlock/mprotect/madvise).\x1b[0m");
            }
            Box::new(PortableBuffer::create(MASTER_KEY_LEN))
        }
    }
}

pub fn create_initialized_buffer() -> Box<dyn Buffer> {
    // Check OS-level protections (Linux only)
    #[cfg(all(target_os = "linux", not(feature = "no_std")))]
    {
        let status = redoubt_guard::guard_status();

        if !status.prctl_succeeded && !status.rlimit_succeeded {
            eprintln!("\x1b[33m⚠️  SECURITY: OS-level core dump protection failed\x1b[0m");
            eprintln!("\x1b[33m   Both prctl(PR_SET_DUMPABLE) and setrlimit(RLIMIT_CORE) failed.\x1b[0m");
        } else if !status.prctl_succeeded {
            eprintln!("\x1b[33m⚠️  SECURITY: prctl(PR_SET_DUMPABLE) failed\x1b[0m");
            eprintln!("\x1b[33m   Process can be attached via ptrace.\x1b[0m");
        } else if !status.rlimit_succeeded {
            eprintln!("\x1b[33m⚠️  INFO: setrlimit(RLIMIT_CORE) failed (prctl active).\x1b[0m");
        }
    }

    let mut buffer = create_buffer();

    buffer
        .open_mut(&mut |bytes| {
            SystemEntropySource {}
                .fill_bytes(bytes)
                .map_err(BufferError::callback_error)?;
            Ok(())
        })
        .expect("CRITICAL: EntropySource not available");

    buffer
}
