// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The stretch of stack an operation left behind, and where a copy of it goes.
//!
//! # What the window is
//!
//! Everything between the lowest address this thread's stack can reach and
//! wherever the stack pointer was when the capture ran. The operation's frames
//! are in there and nothing of anybody else's is: the frames still live are
//! above the stack pointer, and below the floor is the overflow that would
//! have killed the process instead of returning.
//!
//! Neither end is a number anybody chose. The floor comes from the thread's
//! own attributes and the top comes from the stack pointer, so there is no
//! depth to guess at and nothing to plant.
//!
//! # Why the copy exists at all
//!
//! The frames are still readable where they are — a released frame is ordinary
//! `rw-p` memory and the sweep walks it. What they are not is durable. Any
//! call made afterwards writes exactly there, and a secret a few dozen bytes
//! wide goes under it whole, leaving a photograph that reports a clean process
//! and reports it just as cleanly for an operation that wiped nothing.
//!
//! So the window is copied out at the moment it is made, and what happens to
//! the stack afterwards stops being a question.
//!
//! # Why statics and not arguments
//!
//! The same reason the register capture writes into a room of its own: an
//! argument costs a register to pass and another to work its address out, and
//! at the moment of a capture nothing may run. A static is reached relative to
//! the instruction pointer on `x86_64`, and through the two scratch registers
//! the linker already owns on `aarch64` — neither is a value anybody was
//! holding.
//!
//! # One measurement at a time
//!
//! There is one of each, so a second capture writes over the first. That is
//! already true of the register room, and it is what is wanted when the
//! reading is the difference between two photographs. It is also why these
//! tests take a process each: `nextest`, not `cargo test`.

use core::mem::MaybeUninit;
use core::ptr::null_mut;

use crate::errors::Reason;

/// Where the copy of the window goes.
///
/// A leaked allocation, so nothing frees it while the sweep is reading and
/// nothing has to be told when it is done with. Filled by [`open`], because
/// allocating at the capture would be a call between the operation and the
/// copy.
///
/// Null until then, and a capture that finds it null copies nothing. That is
/// the one branch in the capture, and it is there because the alternative to a
/// null check is a store through a null pointer in the middle of somebody's
/// test.
///
/// On the heap and not in `.bss`, unlike the register room, because how much
/// it has to hold is a property of the thread and is not known until one is
/// running.
pub static mut COPY: *mut u8 = null_mut();

/// The lowest address this thread's stack can reach.
///
/// Not a number anybody chose: it comes from the thread's own attributes.
///
/// Nothing the operation does can write below it. A write past the floor is
/// the overflow that would have killed the process instead of returning, so a
/// measurement that happened at all is a measurement of something wholly above
/// this address.
pub static mut FLOOR: usize = 0;

/// Where the stack pointer was when the capture ran.
///
/// Written by the capture, along with the registers. Everything the operation
/// left is below it and above [`FLOOR`], so the two together are the window —
/// measured rather than chosen, and known only after the fact.
///
/// What it is for afterwards is reading the copy back: [`COPY`] holds
/// `SP - FLOOR` bytes and zeroes past that.
pub static mut SP: usize = 0;

/// Reserve the window's room and find its floor.
///
/// Runs before the operation, and its own frames are inside the window it is
/// about to describe — which is harmless, because the operation writes over
/// them on its way down. It is also what stops the enclosing function from
/// being a leaf: a leaf may use the 128 bytes below the stack pointer without
/// adjusting it, and those bytes are the top of the window.
///
/// # Errors
///
/// [`Reason::NoFloor`] when this is the process's first thread, or when the
/// thread will not say where its stack is.
pub fn open() -> Result<(), Reason> {
    let (floor, wide) = reach()?;

    let copy = vec![0_u8; wide].leak();

    // SAFETY: one thread writes these, before any capture reads them, and a
    // second measurement in the same process is the overwrite this crate
    // already documents.
    unsafe {
        FLOOR = floor;
        COPY = copy.as_mut_ptr();
        SP = 0;
    }

    Ok(())
}

/// The floor, and how far it is from the top of the stack.
///
/// # The first thread is refused
///
/// Its stack is grown on demand, so the pages a few kilobytes below the stack
/// pointer are not there to read and a copy of the window faults. Every other
/// thread's stack is one mapping, made whole when the thread was made, and can
/// be read from end to end.
///
/// That is not a restriction in practice — libtest runs each test on a thread
/// it spawned — and it is the reason the floor is asked of the thread rather
/// than of `getrlimit`, whose answer is about the process and is wrong here by
/// megabytes.
///
/// # The guard page
///
/// The guard is added to the floor whether or not the attributes counted it in
/// the size. Counted, this steps over a page that faults on the first byte
/// read; not counted, it gives up one page at the very bottom of a stack the
/// operation never came near. There is no reading of the attributes under
/// which adding it is wrong, and one under which leaving it out is fatal.
fn reach() -> Result<(usize, usize), Reason> {
    // SAFETY: both are reads of the caller's own identity and cannot fail.
    if unsafe { libc::gettid() } == unsafe { libc::getpid() } {
        return Err(Reason::NoFloor);
    }

    let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();

    // SAFETY: the attributes are written by the call and read only where it
    // answered zero.
    if unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) } != 0 {
        return Err(Reason::NoFloor);
    }

    // SAFETY: initialized by the call above.
    let mut attr = unsafe { attr.assume_init() };

    let mut at: *mut libc::c_void = null_mut();
    let mut size = 0_usize;
    let mut guard = 0_usize;

    // SAFETY: three pointers to locals of this frame, live until it returns.
    let told = unsafe {
        libc::pthread_attr_getstack(&raw const attr, &raw mut at, &raw mut size)
            | libc::pthread_attr_getguardsize(&raw const attr, &raw mut guard)
    };

    // SAFETY: initialized above, and nothing reads it after this.
    unsafe { libc::pthread_attr_destroy(&raw mut attr) };

    if told != 0 || guard >= size {
        return Err(Reason::NoFloor);
    }

    Ok((at as usize + guard, size - guard))
}
