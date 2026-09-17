// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Where the window starts, how wide it is, and that the copy is the window.
//!
//! # Why these are not out in `tests/`
//!
//! [`reach`] is private, and it is the half that decides both ends. A file
//! outside the crate could reach the three statics and `open`, and would then
//! be asserting the answer without being able to ask the thing that worked it
//! out.
//!
//! # A process each
//!
//! There is one window in a process, so a second `open` replaces the first and
//! a second capture writes over it. `nextest`, not `cargo test`.

use core::slice;

use crate::capture;
use crate::errors::Reason;
use crate::window::{COPY, FLOOR, SP, open};

/// Thirty-two bytes to leave in a frame and look for in the copy.
const MARK: [u8; 32] = [
    0x7A, 0x13, 0xE5, 0x6B, 0xC0, 0x28, 0x9F, 0x44, 0xD1, 0x36, 0xAE, 0x52, 0x08, 0xFB, 0x71, 0x2C,
    0x95, 0x4D, 0xB3, 0x60, 0xEC, 0x17, 0x8A, 0x3E, 0xD7, 0x22, 0x69, 0xF5, 0x40, 0xBC, 0x01, 0x98,
];

/// The mark, written into a frame that is released on the way out, and the
/// address it was written at.
///
/// Never inlined: an inlined body would leave the mark in the caller's frame,
/// which is still live when the capture runs and so is not in the window at
/// all.
#[inline(never)]
fn a_frame_left_full() -> usize {
    let mut room = MARK;

    core::hint::black_box(&mut room).as_ptr() as usize
}

/// How many frames down [`a_deep_frame_left_full`] goes before it leaves the
/// mark.
///
/// A kilobyte of `waste` each, so the mark ends up a quarter of a megabyte from
/// where the capture runs — far enough that a window reaching only the last
/// call's frame cannot have it.
const DEEP: usize = 256;

/// The mark, left at the far end of a chain of frames that are all released
/// before the capture, and the address it was written at.
#[inline(never)]
fn a_deep_frame_left_full(left: usize) -> usize {
    let mut waste = [0_u8; 1024];

    core::hint::black_box(&mut waste);

    if left == 0 {
        return a_frame_left_full();
    }

    a_deep_frame_left_full(left - 1)
}

/// How wide the frame [`a_frame_with_one_byte_set`] leaves behind is.
///
/// Every offset of it is asked about separately, so this is a count of captures
/// and each is microseconds.
const WIDE: usize = 256;

/// A released frame of [`WIDE`] zeroes with a one at `at`, and the address it
/// was written at.
///
/// The zeroes are the half that matters: a copy that doubled a byte or carried
/// the frame over by one has somewhere to show it, which a frame full of marks
/// does not.
#[inline(never)]
fn a_frame_with_one_byte_set(at: usize) -> usize {
    let mut room = [0_u8; WIDE];

    room[at] = 1;

    core::hint::black_box(&mut room).as_ptr() as usize
}

/// The mapping `/proc/self/maps` puts an address in, as `(low, high)`.
///
/// The kernel rather than the thread's attributes, which is what `reach` asks
/// and so cannot be the oracle for what it answered.
fn mapped(at: usize) -> (usize, usize) {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("this process's own mappings");

    for line in maps.lines() {
        let bounds = line.split_whitespace().next().expect("a line with bounds");
        let (low, high) = bounds.split_once('-').expect("two bounds");

        let low = usize::from_str_radix(low, 16).expect("a hexadecimal bound");
        let high = usize::from_str_radix(high, 16).expect("a hexadecimal bound");

        if (low..high).contains(&at) {
            return (low, high);
        }
    }

    panic!("no mapping holds {at:#x}");
}

// ============================================================================
// open
// ============================================================================

/// The floor is inside the mapping this thread's stack is in.
///
/// Asked of the kernel, because the thread's attributes are what `reach` reads:
/// a floor worked out from them and checked against them would be the
/// arithmetic agreeing with itself. A floor outside the mapping is a copy that
/// reads somebody else's memory or faults on the first byte, and neither
/// announces itself as a wrong floor.
#[test]
fn test_open_finds_a_floor_inside_the_stack_this_thread_runs_on() -> Result<(), Reason> {
    let here = 0_u64;
    let (low, high) = mapped(core::hint::black_box(&here) as *const u64 as usize);

    open()?;

    // SAFETY: written by `open` just above, on the thread reading it.
    let floor = unsafe { FLOOR };

    assert!(
        (low..high).contains(&floor),
        "the floor {floor:#x} is not in the stack mapping {low:#x}-{high:#x}",
    );

    Ok(())
}

/// A window nobody has captured into reports no stack pointer.
///
/// `SP` is the width the copy is read back by, and a window that has not been
/// captured into has no bytes to read: a number left there from the last
/// measurement would hand out this window's room to the last one's length.
#[test]
fn test_open_leaves_no_stack_pointer_behind_it() -> Result<(), Reason> {
    open()?;

    // SAFETY: written by `open` just above, on the thread reading it.
    assert_eq!(unsafe { SP }, 0, "a stack pointer nobody captured");

    Ok(())
}

/// The stack pointer a capture wrote is gone by the next window.
///
/// Asserted with the one the capture wrote read first, because otherwise a
/// capture that stopped writing `SP` at all leaves it zero from end to end and
/// this passes having watched nothing happen.
#[test]
fn test_open_clears_the_stack_pointer_the_last_capture_wrote() -> Result<(), Reason> {
    open()?;

    capture!();

    // SAFETY: written by the capture just above, on the thread reading it.
    let stood = unsafe { SP };

    assert_ne!(stood, 0, "the capture wrote no stack pointer to clear");

    open()?;

    // SAFETY: written by `open` just above, on the thread reading it.
    assert_eq!(unsafe { SP }, 0, "a stack pointer from before this window");

    Ok(())
}

/// A second window is a second room, and the first is not written into again.
///
/// There is one of each static, so the only thing that makes two measurements
/// in a process independent is that the second `open` hands out somewhere else
/// to put the copy. A caller comparing two photographs takes two.
#[test]
fn test_open_reserves_a_new_room_for_every_window() -> Result<(), Reason> {
    open()?;

    // SAFETY: written by `open` just above, on the thread reading it.
    let first = unsafe { COPY };

    open()?;

    // SAFETY: the same.
    let second = unsafe { COPY };

    assert!(!first.is_null(), "the first window reserved nothing");
    assert_ne!(first, second, "both windows share one room");

    Ok(())
}

/// The capture writes down the stack pointer it ran at.
///
/// The width the copy is read back by, and the only number of the three that
/// `open` does not work out. A stale one — from the last measurement, or from
/// before the operation — reads this window's bytes to the last one's length,
/// and the bytes are there either way.
///
/// The oracle is a local of this frame: the capture ran here, so the stack
/// pointer it wrote down is below that local and within this frame's depth of
/// it.
#[test]
fn test_the_capture_writes_down_the_stack_pointer_it_ran_at() -> Result<(), Reason> {
    open()?;

    capture!();

    let here = 0_u64;
    let at = core::hint::black_box(&here) as *const u64 as usize;

    // SAFETY: written by the capture above, on the thread reading it.
    let stood = unsafe { SP };

    assert!(stood <= at, "the capture ran above this frame's own local");
    assert!(
        at - stood < 4096,
        "the stack pointer {stood:#x} is {} bytes under a local of the frame the \
         capture ran in, which is another frame's",
        at - stood,
    );

    Ok(())
}

/// The copy is the window, byte for byte, at the address each byte came from.
///
/// The pair in the crate's own `tests/` says the copy happens by finding the
/// secret afterwards; this says *where*, which is what tells a broken copy from
/// a broken sweep the day that pair disagrees. The sweep finds a mark wherever
/// it is, so an offset out by any amount fails here and nowhere else.
#[test]
fn test_open_reserves_a_room_the_capture_fills_from_the_floor_up() -> Result<(), Reason> {
    open()?;

    let at = a_frame_left_full();

    capture!();

    // SAFETY: `FLOOR` and `COPY` were written by `open` and `SP` by the capture
    // above, all three on the thread reading them.
    let (floor, stood, copy) = unsafe { (FLOOR, SP, COPY) };

    assert!(
        (floor..stood).contains(&at),
        "the frame at {at:#x} is not in the window {floor:#x}-{stood:#x}",
    );

    // SAFETY: the room is as wide as the window, and `at` is inside it with
    // `MARK` bytes to spare — the frame that held them was released below the
    // stack pointer the capture wrote down.
    let there = unsafe { slice::from_raw_parts(copy.add(at - floor), MARK.len()) };

    assert_eq!(there, &MARK[..], "the copy is not the window it stands for");

    Ok(())
}

/// The mark is at one offset of the copy, and it is the one its address names.
///
/// What the test above cannot say on its own: an equality at a single offset
/// holds just as well for a copy taken from the wrong place, as long as the
/// mark landed there by some other route. Reading the whole room and counting
/// leaves one explanation — a copy that begins at the floor.
///
/// It is also the falsification the test above wants and cannot perform. A
/// destination in the capture moved by any amount `k` puts the one occurrence
/// at `at - floor - k`, and this is the only test that would say so.
#[test]
fn test_the_mark_is_at_one_offset_of_the_copy_and_it_is_the_address_it_came_from()
-> Result<(), Reason> {
    open()?;

    let at = a_frame_left_full();

    capture!();

    // SAFETY: `FLOOR` and `COPY` were written by `open` and `SP` by the capture
    // above, all three on the thread reading them.
    let (floor, stood, copy) = unsafe { (FLOOR, SP, COPY) };

    // SAFETY: the room is as wide as the window, which is what the capture just
    // copied into it.
    let room = unsafe { slice::from_raw_parts(copy, stood - floor) };

    let found = room
        .windows(MARK.len())
        .enumerate()
        .filter(|(_, window)| *window == &MARK[..])
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();

    assert_eq!(
        found,
        [at - floor],
        "the mark left at {at:#x} is not at the one offset its address names",
    );

    Ok(())
}

/// The window reaches the far end of the stack, not just the last call.
///
/// The test above leaves its mark one frame from where the capture runs, which
/// a window that copied only the last few hundred bytes would carry just as
/// well. This one leaves it a quarter of a megabyte away, so what it asks is
/// how far the copy goes rather than whether it happened.
#[test]
fn test_the_copy_reaches_a_frame_released_a_long_way_from_the_capture() -> Result<(), Reason> {
    open()?;

    let at = a_deep_frame_left_full(DEEP);

    capture!();

    // SAFETY: `FLOOR` and `COPY` were written by `open` and `SP` by the capture
    // above, all three on the thread reading them.
    let (floor, stood, copy) = unsafe { (FLOOR, SP, COPY) };

    assert!(
        stood - at > DEEP * 1024,
        "the mark came to rest {} bytes from the capture, which is not a long way",
        stood - at,
    );

    // SAFETY: the room is as wide as the window, and `at` is inside it with
    // `MARK` bytes to spare — the frames that held them were all released
    // before the capture wrote down where it stood.
    let there = unsafe { slice::from_raw_parts(copy.add(at - floor), MARK.len()) };

    assert_eq!(there, &MARK[..], "the copy stops short of the mark");

    Ok(())
}

/// Every byte of a released frame is in the copy, at its own offset and at no
/// other.
///
/// The marks above say one stretch of thirty-two bytes arrived where its
/// address named. This asks the same of every offset there is, one at a time,
/// with the rest of the frame zero — which is what tells a copy that dropped a
/// byte from one that doubled one, and either from one that carried the whole
/// frame over by a byte. Each of the three reads as a one in a place the offset
/// did not name, and nothing coarser than a byte at a time distinguishes them.
///
/// One `open` for the lot: the room is written over by each capture and it is
/// read before the next, and a window per offset would leak a stack's worth of
/// allocation two hundred and fifty-six times.
#[test]
fn test_every_byte_of_a_released_frame_is_in_the_copy_at_its_own_offset() -> Result<(), Reason> {
    open()?;

    for offset in 0..WIDE {
        let at = a_frame_with_one_byte_set(offset);

        capture!();

        // SAFETY: `FLOOR` and `COPY` were written by `open` above and `SP` by
        // the capture, all three on the thread reading them.
        let (floor, copy) = unsafe { (FLOOR, COPY) };

        // SAFETY: the room is as wide as the window, and the frame is inside it
        // with `WIDE` bytes to spare — it was released before the capture wrote
        // down where it stood.
        let frame = unsafe { slice::from_raw_parts(copy.add(at - floor), WIDE) };

        let set = frame
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte != 0)
            .map(|(where_it_is, _)| where_it_is)
            .collect::<Vec<_>>();

        assert_eq!(
            set,
            [offset],
            "the frame left with byte {offset} set came back with these set",
        );
    }

    Ok(())
}

// ============================================================================
// reach
// ============================================================================

#[test]
#[ignore = "Uncovered: all three refusals are. It takes no argument, libtest \
            runs every test on a thread it spawned so the first-thread check \
            never fires, and neither `pthread_getattr_np` nor the two reads \
            under it fails for a live thread. Shell preserved in case a caller \
            arrives that is not libtest."]
fn test_reach_reports_no_floor_where_the_thread_will_not_say() {
    // Intentionally empty.
}
