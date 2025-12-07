// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! memguard - Process-level memory protection via prctl
//!
//! Provides a one-time initialization of `PR_SET_DUMPABLE` to prevent
//! core dumps and ptrace attachment. Uses a spin lock to ensure only
//! one thread performs the initialization.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
mod tests;

use core::sync::atomic::{AtomicU8, Ordering};

/// Initialization state: not yet attempted
const STATE_UNINIT: u8 = 0;
/// Initialization state: in progress by another thread
const STATE_IN_PROGRESS: u8 = 1;
/// Initialization state: completed
const STATE_DONE: u8 = 2;

static INIT_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static PRCTL_SUCCEEDED: AtomicU8 = AtomicU8::new(0);

/// Returns whether process-level memory protection is active.
///
/// On first call, attempts `prctl(PR_SET_DUMPABLE, 0)` to prevent
/// core dumps and ptrace attachment. Subsequent calls return the
/// cached result immediately.
///
/// Thread-safe: if multiple threads call simultaneously, only one
/// performs the syscall while others spin-wait.
///
/// Returns `false` if:
/// - prctl failed (e.g., blocked by seccomp)
/// - Running on a non-Linux platform
#[inline]
pub fn is_guarded() -> bool {
    // Fast path: already initialized
    if INIT_STATE.load(Ordering::Acquire) == STATE_DONE {
        return PRCTL_SUCCEEDED.load(Ordering::Relaxed) != 0;
    }

    init_slow();
    is_guarded()
}

#[cold]
#[inline(never)]
fn init_slow() {
    // Try to become the initializer
    match INIT_STATE.compare_exchange(
        STATE_UNINIT,
        STATE_IN_PROGRESS,
        Ordering::Acquire,
        Ordering::Relaxed,
    ) {
        Ok(_) => {
            // We won, perform prctl
            let succeeded = prctl_set_not_dumpable();
            PRCTL_SUCCEEDED.store(succeeded as u8, Ordering::Relaxed);
            // Delay STATE_DONE to allow other threads to enter init_slow()
            // and hit the spin loop for coverage. Without this, initialization
            // completes too fast and threads skip init_slow() entirely.
            #[cfg(test)]
            std::thread::sleep(std::time::Duration::from_millis(100));
            INIT_STATE.store(STATE_DONE, Ordering::Release);
        }
        Err(_) => {
            // Another thread is initializing or already done, spin until done
            while INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
                core::hint::spin_loop();
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn prctl_set_not_dumpable() -> bool {
    // PR_SET_DUMPABLE = 4, 0 = not dumpable
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn prctl_set_not_dumpable() -> bool {
    // prctl is Linux-only
    false
}
