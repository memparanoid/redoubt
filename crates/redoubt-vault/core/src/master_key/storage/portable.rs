// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Portable (no_std) storage implementation
//!
//! Uses a spinlock for lazy initialization of the underlying buffer.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use redoubt_buffer::{Buffer, BufferError};

use super::super::buffer::create_initialized_buffer;

/// Initialization state: not yet attempted
const STATE_UNINIT: u8 = 0;
/// Initialization state: in progress by another thread
const STATE_IN_PROGRESS: u8 = 1;
/// Initialization state: completed
const STATE_DONE: u8 = 2;

struct BufferCell(UnsafeCell<Option<Box<dyn Buffer>>>);

unsafe impl Sync for BufferCell {}

static INIT_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static BUFFER: BufferCell = BufferCell(UnsafeCell::new(None));
static LOCKED: AtomicBool = AtomicBool::new(false);

#[cold]
#[inline(never)]
fn init_slow() {
    match INIT_STATE.compare_exchange(
        STATE_UNINIT,
        STATE_IN_PROGRESS,
        Ordering::Acquire,
        Ordering::Relaxed,
    ) {
        Ok(_) => {
            unsafe {
                *BUFFER.0.get() = Some(create_initialized_buffer());
            }

            // Ensure the write to BUFFER is visible before STATE_DONE
            core::sync::atomic::fence(Ordering::Release);

            // Delay STATE_DONE to allow other threads to enter init_slow()
            // and hit the spin loop for coverage. Without this, initialization
            // completes too fast and threads skip init_slow() entirely.
            #[cfg(test)]
            std::thread::sleep(std::time::Duration::from_millis(100));

            INIT_STATE.store(STATE_DONE, Ordering::Release);
        }
        Err(_) => {
            // Another thread is initializing, spin until done
            while INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
                core::hint::spin_loop();
            }
        }
    }
}

fn acquire() {
    while LOCKED.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Delay lock release during tests to force thread contention and ensure
    // the spin loop above gets coverage. Without this, lock acquisition is
    // so fast that threads never actually spin.
    #[cfg(test)]
    std::thread::sleep(std::time::Duration::from_micros(10));
}

fn release() {
    LOCKED.store(false, Ordering::Release);
}

pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), BufferError>) -> Result<(), BufferError> {
    if INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
        init_slow();
    }

    acquire();

    let result = unsafe {
        (*BUFFER.0.get())
            .as_mut()
            .expect("Infallible: BUFFER is already initialized")
            .open(f)
    };

    release();

    result
}

/// Resets the master key storage (GDB testing only)
///
/// # Safety
///
/// This function is only available with the `gdb` feature.
/// It reinitializes the master key buffer, discarding the previous key material.
/// This should only be used for memory leak detection in controlled testing environments.
///
/// # Panics
///
/// Panics if the buffer has not been initialized yet.
#[cfg(feature = "__internal__forensics")]
pub fn reset() {
    assert_eq!(
        INIT_STATE.load(Ordering::Acquire),
        STATE_DONE,
        "BUFFER must be initialized before reset"
    );

    acquire();

    unsafe {
        *BUFFER.0.get() = Some(create_initialized_buffer());
    }

    release();
}
