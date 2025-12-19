// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! redoubt_guard - Process-level memory protection via prctl and setrlimit
//!
//! Provides a one-time initialization of `PR_SET_DUMPABLE` and `RLIMIT_CORE`
//! to prevent core dumps and ptrace attachment. Uses a spin lock to ensure
//! only one thread performs the initialization.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
mod tests;

use core::sync::atomic::{AtomicU8, Ordering};

/// Guard status returned by `guard_status()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardStatus {
    /// Whether `prctl(PR_SET_DUMPABLE, 0)` succeeded.
    ///
    /// Critical for anti-debugging (blocks ptrace) and core dump prevention.
    /// Reversible by other code calling `prctl(PR_SET_DUMPABLE, 1)`.
    pub prctl_succeeded: bool,

    /// Whether `setrlimit(RLIMIT_CORE, 0)` succeeded.
    ///
    /// Redundant core dump prevention (limits size to 0 bytes).
    /// Does NOT block ptrace. More difficult to revert than prctl.
    pub rlimit_succeeded: bool,
}

/// Initialization state: not yet attempted
const STATE_UNINIT: u8 = 0;
/// Initialization state: in progress by another thread
const STATE_IN_PROGRESS: u8 = 1;
/// Initialization state: completed
const STATE_DONE: u8 = 2;

static INIT_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static PRCTL_SUCCEEDED: AtomicU8 = AtomicU8::new(0);
static RLIMIT_SUCCEEDED: AtomicU8 = AtomicU8::new(0);

/// Returns the status of process-level memory protections.
///
/// **Side effect on first call:** Attempts to initialize both:
/// - `prctl(PR_SET_DUMPABLE, 0)` - prevents core dumps and ptrace attachment
/// - `setrlimit(RLIMIT_CORE, 0)` - limits core dump size to 0 bytes
///
/// Subsequent calls return the cached result immediately without side effects.
///
/// Thread-safe: if multiple threads call simultaneously, only one thread
/// performs the initialization syscalls while others spin-wait.
///
/// # Example
///
/// ```
/// use redoubt_guard::guard_status;
///
/// let status = guard_status();
/// if status.prctl_succeeded {
///     println!("prctl protection active");
/// }
/// if status.rlimit_succeeded {
///     println!("rlimit protection active");
/// }
/// if status.is_protected() {
///     println!("At least one protection is active");
/// }
/// ```
#[inline]
pub fn guard_status() -> GuardStatus {
    // Fast path: already initialized
    if INIT_STATE.load(Ordering::Acquire) == STATE_DONE {
        return GuardStatus {
            prctl_succeeded: PRCTL_SUCCEEDED.load(Ordering::Relaxed) != 0,
            rlimit_succeeded: RLIMIT_SUCCEEDED.load(Ordering::Relaxed) != 0,
        };
    }

    init_slow();
    guard_status()
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
            // We won, perform both protections
            let prctl_ok = prctl_set_not_dumpable();
            let rlimit_ok = setrlimit_core_zero();

            PRCTL_SUCCEEDED.store(prctl_ok as u8, Ordering::Relaxed);
            RLIMIT_SUCCEEDED.store(rlimit_ok as u8, Ordering::Relaxed);

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

#[cfg(target_os = "linux")]
fn setrlimit_core_zero() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn setrlimit_core_zero() -> bool {
    // setrlimit RLIMIT_CORE is Linux-specific
    false
}
