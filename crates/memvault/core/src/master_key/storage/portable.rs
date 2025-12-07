// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Portable (no_std) storage implementation
//!
//! Uses a spinlock for lazy initialization of the underlying buffer.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

use membuffer::{Buffer, BufferError as MemBufferError};

use crate::BufferError;

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

pub fn open(f: &mut dyn FnMut(&[u8]) -> Result<(), MemBufferError>) -> Result<(), BufferError> {
    if INIT_STATE.load(Ordering::Acquire) != STATE_DONE {
        init_slow();
    }

    unsafe {
        (*BUFFER.0.get())
            .as_mut()
            .expect("buffer not initialized")
            .open(f)?;
    }

    Ok(())
}
