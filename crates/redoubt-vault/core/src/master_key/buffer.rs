// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Buffer creation logic
use alloc::boxed::Box;

use redoubt_buffer::{Buffer, BufferError, PortableBuffer};
use redoubt_rand::generate_random_key;

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
                eprintln!(
                    "\x1b[33m⚠️  SECURITY: Failed to create protected memory page: {:?}\x1b[0m",
                    e
                );
                eprintln!("\x1b[33m   Falling back to heap (no mlock/mprotect/madvise).\x1b[0m");
            }
            #[cfg(feature = "no_std")]
            {
                let _ = e;
            }
            Box::new(PortableBuffer::create(MASTER_KEY_LEN))
        }
    }
}

pub fn create_initialized_buffer() -> Box<dyn Buffer> {
    let status = redoubt_guard::guard_status();
    create_initialized_buffer_with(status)
}

pub fn create_initialized_buffer_with(status: redoubt_guard::GuardStatus) -> Box<dyn Buffer> {
    #[cfg(not(all(target_os = "linux", not(feature = "no_std"))))]
    let _ = status;

    // Forensic analysis warning (applies to all platforms when __internal__forensics feature is active)
    #[cfg(all(feature = "__internal__forensics", not(feature = "no_std")))]
    {
        eprintln!(
            "\x1b[31m⚠️  WARNING: Forensic analysis mode enabled - memory protections DISABLED\x1b[0m"
        );
        eprintln!(
            "\x1b[31m   prctl(PR_SET_DUMPABLE) and setrlimit(RLIMIT_CORE) are NOT applied.\x1b[0m"
        );
        eprintln!("\x1b[31m   Process CAN be debugged and core dumps ARE enabled.\x1b[0m");
    }

    // Check OS-level protections (Linux only)
    #[cfg(all(target_os = "linux", not(feature = "no_std")))]
    {
        if !status.prctl_succeeded {
            eprintln!("\x1b[33m⚠️  SECURITY: prctl(PR_SET_DUMPABLE) failed\x1b[0m");
            eprintln!("\x1b[33m   Process can be attached via ptrace.\x1b[0m");
        }

        if !status.rlimit_succeeded {
            eprintln!("\x1b[33m⚠️  SECURITY: setrlimit(RLIMIT_CORE) failed\x1b[0m");
            eprintln!("\x1b[33m   Core dumps may be generated.\x1b[0m");
        }
    }

    let mut buffer = create_buffer();

    buffer
        .open_mut(&mut |bytes| {
            generate_random_key(b"redoubt.master_key.v1", bytes)
                .map_err(BufferError::callback_error)?;
            Ok(())
        })
        .expect("CRITICAL: Key generation failed");

    buffer
}
