// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Portable (no_std) storage implementation
//!
//! Uses a spinlock for lazy initialization of the underlying buffer.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU8, Ordering};

use membuffer::Buffer;

/// Initialization state: not yet attempted
const STATE_UNINIT: u8 = 0;
/// Initialization state: in progress by another thread
const STATE_IN_PROGRESS: u8 = 1;
/// Initialization state: completed
const STATE_DONE: u8 = 2;

static INIT_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static mut BUFFER: Option<Box<dyn Buffer>> = None;

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
            // We won, initialize the buffer
            // TODO: Create actual buffer
            unsafe {
                BUFFER = None; // placeholder
            }
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

pub fn open<F, R>(f: F) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    if INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
        init_slow();
    }

    // TODO: Actually open buffer and call f
    todo!()
}

pub fn open_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut [u8]) -> R,
{
    if INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
        init_slow();
    }

    // TODO: Actually open buffer mutably and call f
    todo!()
}
