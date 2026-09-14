// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Everything an analysis needs, reserved before there is an analysis.
//!
//! # Why it is all in one place
//!
//! Two things want the same thing for different reasons.
//!
//! The child may not allocate. `fork` takes one thread and the whole address
//! space, locks included: a lock another thread held at that instant is held
//! in the child by nobody, forever. glibc covers its own allocator across a
//! fork and nothing covers anything else, so the rule is that the child asks
//! for no memory at all. It cannot ask if everything is already there.
//!
//! And the analysis has to be able to skip itself. What the instrument keeps
//! between one photograph and the next is bytes, and bytes are what is being
//! counted. Anything scattered across six allocations can only be skipped by
//! knowing where all six are. One block is one stretch.
//!
//! # How it is recognised
//!
//! [`MAGIC`] sits at the front and every block is [`BLOCK`] bytes. That is the
//! whole protocol: find the phrase, skip that many bytes. Nothing is
//! registered anywhere, which is what makes it work for a block some earlier
//! snapshot is still holding, and for one that was freed and left in the heap
//! with the phrase intact.
//!
//! It is a check as much as a search. A child is copy-on-write from its
//! parent, so a block is at the same address in the photograph as in the
//! process reading it.
//!
//! # Nothing here is squared
//!
//! An earlier shape of this counted every extent of the secret separately —
//! how many places held `secret[7..19]`, and so on for all of them. That is
//! `of * of` counters, which is thirty kilobytes for a key and eighty-seven
//! megabytes for an RSA-4096, and it answers a question nobody asks. What is
//! kept instead is one counter per *width*, which is linear, and a single
//! score. The block is the same size for a thirty-two byte secret and an
//! eight kilobyte one.
//!
//! # What is not covered, and why it does not matter
//!
//! Everything the instrument does the same way twice — parsing
//! `/proc/self/maps` into strings it throws away, the stack it walks, the
//! pages the allocator hands back — happens identically before both
//! photographs and cancels in the difference between them. What does not
//! cancel is what is *kept*: the first result, alive when the second
//! photograph is taken. That is what this covers, and it is the only thing
//! that accumulates.

use std::ptr;
use std::slice;

/// What marks memory as the instrument's own.
///
/// Twenty-two bytes no program has a reason to hold, which is the whole
/// requirement: a phrase that turns up by chance is a stretch of somebody's
/// memory silently dropped from the sweep.
pub(crate) const MAGIC: [u8; 22] = *b"__REDOUBT__FORENSICS__";

/// The phrase and the padding that keeps everything after it eight-aligned.
const HEAD: usize = 32;

/// How much of a mapping is read at a time. Some of them are gigabytes, so
/// this is a number of turns around the loop and not a limit on anything.
pub(crate) const WINDOW: usize = 1 << 18;

/// How much of a report is formatted before it is written out.
pub(crate) const REPORT: usize = 1 << 18;

/// The longest needle any of this takes. An RSA-4096 in its file form is
/// about three and a half kilobytes, so this is that with room over.
pub(crate) const MOST: usize = 8192;

/// How many stretches of the instrument's own memory one sweep can skip: one
/// per block ever allocated and not yet overwritten.
pub(crate) const SKIPS: usize = 256;

/// How many mappings one sweep can be over.
pub(crate) const MAPPINGS: usize = 4096;

/// How much stack the analysis runs on.
///
/// Its own, and inside the block on purpose. Reserved here it costs nothing at
/// the moment of the photograph, and marked by the phrase at the front of the
/// block it is skipped by the sweep — so the frames the instrument pushes are
/// never memory anybody is counting.
pub(crate) const STACK: usize = 1 << 18;

/// Which byte may follow which, as one bit each.
const NEXT: usize = 256 * 32;
/// Which bytes are in the needle at all, as one bit each.
const SEEN: usize = 32;
/// One counter per width a run can have.
const WIDTHS: usize = MOST * 8;
/// The last bytes swept, kept so that a run can be read back when it closes.
///
/// As long as the longest needle: a stretch of the secret is never wider than
/// the secret, so a run wider than this holds nothing past its last `MOST`
/// bytes that could be one.
const TAIL: usize = MOST;
/// One `u16` per byte of the needle, scratch for verifying a run against it.
const LENS: usize = MOST * 2;
/// What comes back through the pipe.
const RESULT: usize = 64;

const EXCL: usize = 8 + SKIPS * 16;
const MAPS: usize = 8 + MAPPINGS * 16;

const AT_WINDOW: usize = HEAD;
const AT_REPORT: usize = AT_WINDOW + WINDOW;
const AT_SECRET: usize = AT_REPORT + REPORT;
const AT_NEXT: usize = AT_SECRET + MOST;
const AT_SEEN: usize = AT_NEXT + NEXT;
const AT_WIDTHS: usize = AT_SEEN + SEEN;
const AT_TAIL: usize = AT_WIDTHS + WIDTHS;
const AT_LENS: usize = AT_TAIL + TAIL;
const AT_RESULT: usize = AT_LENS + LENS;
const AT_EXCL: usize = AT_RESULT + RESULT;
const AT_MAPS: usize = AT_EXCL + EXCL;
const AT_STACK: usize = AT_MAPS + MAPS;

/// How long every block is, which is how far a sweep skips from a phrase.
pub(crate) const BLOCK: usize = AT_STACK + STACK;

/// Where the result sits among the counters that come back.
pub(crate) const FOUND: usize = 0;
/// The score.
pub(crate) const SCORE: usize = 1;
/// How many bytes were swept, which is what the score is measured against.
pub(crate) const SWEPT: usize = 2;
/// The widest run there was.
pub(crate) const WIDEST: usize = 3;
/// How many runs were closed at all.
pub(crate) const RUNS: usize = 4;
/// Whether the child got as far as answering.
///
/// Every other number is zero until something writes to it, and zero is also
/// what "the secret is nowhere" looks like. This is the one that tells those
/// two apart, so that a photograph that could not be taken is not read as a
/// clean one.
pub(crate) const OK: usize = 5;
/// How many times the needle was there exactly, for a plain count.
pub(crate) const COUNT: usize = 6;
/// How much of the result comes back through the pipe, in `u64`.
pub(crate) const SHIPPED: usize = RESULT / 8;

/// One mapping, or one stretch of it that is being skipped.
pub(crate) type Span = (u64, u64);

/// One block: the scratch a sweep needs and the numbers it fills.
///
/// Reserved and zeroed on the near side of the fork. The child writes into it
/// and copy-on-write hands the child its own pages, so what this process keeps
/// is the zeros it started with — except the result, which is read back
/// through a pipe on purpose.
pub(crate) struct ForensicState {
    /// One allocation, held as `u64` so that it is eight-aligned and every
    /// view carved out of it is too.
    block: Vec<u64>,
    /// How much of `secret` is the needle.
    pub(crate) of: usize,
    /// Whether the child turns the needle around before looking for it, which
    /// is what a caller holding a secret backwards is asking for.
    pub(crate) backwards: bool,
}

/// The block, taken apart. One call, because it is one allocation and the
/// borrow checker will not hand the pieces out twice.
pub(crate) struct Parts<'a> {
    /// One window of the photograph at a time.
    pub(crate) held: &'a mut [u8],
    /// Where a report is formatted before it is written out.
    ///
    /// Reserved and not yet used: a sweep that wants to say more than a score
    /// writes it from here with `write(2)`, which is the one way to say more
    /// without asking for memory or leaving it in anybody's process.
    #[allow(dead_code)]
    pub(crate) report: &'a mut [u8],
    /// The needle. It arrives backwards and is turned around in the child.
    pub(crate) secret: &'a mut [u8],
    /// One bit per pair: whether `y` ever follows `x` in the needle.
    pub(crate) next: &'a mut [u8],
    /// One bit per byte value: whether it is in the needle at all.
    pub(crate) seen: &'a mut [u8],
    /// How many runs were closed at each width.
    pub(crate) widths: &'a mut [u64],
    /// The last `MOST` bytes swept, as a ring. A run is read back out of it
    /// when it closes, wherever it began and whichever window that was in.
    pub(crate) tail: &'a mut [u8],
    /// Scratch for verifying a run against the needle, one counter per byte
    /// of it.
    pub(crate) lens: &'a mut [u16],
    /// What goes back through the pipe.
    pub(crate) result: &'a mut [u64],
    /// The instrument's own blocks, found by their phrase, to be skipped.
    pub(crate) skips: Spans<'a>,
    /// The mappings to sweep, read before the fork.
    pub(crate) maps: Spans<'a>,
}

/// A count, and that many spans after it, in one run of `u64`.
pub(crate) struct Spans<'a> {
    at: &'a mut [u64],
}

impl Spans<'_> {
    /// How many there are.
    pub(crate) fn len(&self) -> usize {
        self.at[0] as usize
    }

    /// Whether there are none.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Back to none.
    ///
    /// One block serves every photograph a caller takes, so what the last one
    /// found has to go before the next one starts counting.
    pub(crate) fn clear(&mut self) {
        self.at[0] = 0;
    }

    /// One more, or `false` if there is no room.
    ///
    /// A sweep that has run out of room to skip would count the instrument as
    /// if it were somebody else's memory, so the caller is told rather than
    /// quietly handed a short list.
    pub(crate) fn push(&mut self, span: Span) -> bool {
        let at = self.at[0] as usize;

        if at >= (self.at.len() - 1) / 2 {
            return false;
        }

        self.at[1 + at * 2] = span.0;
        self.at[2 + at * 2] = span.1;
        self.at[0] = at as u64 + 1;

        true
    }

    /// The one at that place.
    pub(crate) fn get(&self, at: usize) -> Span {
        (self.at[1 + at * 2], self.at[2 + at * 2])
    }

    /// All of them, in the order they were pushed.
    pub(crate) fn iter(&self) -> impl Iterator<Item = Span> + '_ {
        (0..self.len()).map(|at| self.get(at))
    }
}

#[cfg(test)]
impl<'a> Spans<'a> {
    /// One over a caller's own words, holding none to begin with.
    ///
    /// Here rather than in the tests because what it knows is the shape of the
    /// run — a count in the first word and the spans after it — and that is
    /// this file's to know. A test that built the run itself would be a second
    /// place the shape is written down, and the two would part company the day
    /// it changed.
    ///
    /// For a test that wants to say what is in one. Everywhere else they are
    /// filled by a photograph, which is not a thing an assertion about
    /// [`inside`](crate::analysis::memory::inside) wants to arrange.
    pub(crate) fn over(at: &'a mut [u64]) -> Self {
        at[0] = 0;

        Self { at }
    }
}

impl Default for ForensicState {
    fn default() -> Self {
        let mut state = Self {
            block: vec![0; BLOCK / 8],
            of: 0,
            backwards: false,
        };

        // SAFETY: the block is `BLOCK` bytes and `MAGIC` is far shorter than
        // `HEAD`, which is the room set aside for it at the front.
        let head = unsafe {
            slice::from_raw_parts_mut(state.block.as_mut_ptr().cast::<u8>(), MAGIC.len())
        };

        head.copy_from_slice(&MAGIC);

        state
    }
}

impl ForensicState {
    /// The needle, copied where the child can reach it without asking for
    /// memory.
    ///
    /// It goes in exactly as the caller holds it, which is backwards. Turning
    /// it around is the child's to do, on the far side of the photograph:
    /// written forwards here it would be a copy of the secret in this process,
    /// put there by the thing that is looking for copies of the secret in this
    /// process.
    pub(crate) fn hold(&mut self, needle: &[u8], backwards: bool) -> bool {
        if needle.is_empty() || needle.len() > MOST {
            return false;
        }

        self.of = needle.len();
        self.backwards = backwards;
        self.parts().secret[..needle.len()].copy_from_slice(needle);

        true
    }

    /// The result, as the bytes that go over the pipe.
    pub(crate) fn shipped(&mut self) -> &mut [u8] {
        // SAFETY: the result is `u64` and any bit pattern is a valid `u8`, so
        // a byte view of it is aligned and every byte of it initialised.
        unsafe {
            slice::from_raw_parts_mut(self.block.as_mut_ptr().cast::<u8>().add(AT_RESULT), RESULT)
        }
    }

    /// The block, taken apart.
    pub(crate) fn parts(&mut self) -> Parts<'_> {
        let base = self.block.as_mut_ptr().cast::<u8>();

        // SAFETY: the block is a `Vec<u64>`, so it is eight-aligned, and every
        // offset below is a multiple of eight — which is what makes the `u64`
        // views aligned. Any bit pattern is a valid `u8`, every byte of the
        // block is initialised, the pieces are laid out end to end so no two
        // of them overlap, and all of them are inside the `BLOCK` bytes that
        // were reserved.
        unsafe {
            Parts {
                held: slice::from_raw_parts_mut(base.add(AT_WINDOW), WINDOW),
                report: slice::from_raw_parts_mut(base.add(AT_REPORT), REPORT),
                secret: slice::from_raw_parts_mut(base.add(AT_SECRET), MOST),
                next: slice::from_raw_parts_mut(base.add(AT_NEXT), NEXT),
                seen: slice::from_raw_parts_mut(base.add(AT_SEEN), SEEN),
                widths: slice::from_raw_parts_mut(base.add(AT_WIDTHS).cast(), MOST),
                tail: slice::from_raw_parts_mut(base.add(AT_TAIL), TAIL),
                lens: slice::from_raw_parts_mut(base.add(AT_LENS).cast(), MOST),
                result: slice::from_raw_parts_mut(base.add(AT_RESULT).cast(), SHIPPED),
                skips: Spans {
                    at: slice::from_raw_parts_mut(base.add(AT_EXCL).cast(), 1 + SKIPS * 2),
                },
                maps: Spans {
                    at: slice::from_raw_parts_mut(base.add(AT_MAPS).cast(), 1 + MAPPINGS * 2),
                },
            }
        }
    }

    /// One number out of the result.
    /// The high end of the stack the analysis runs on, aligned as the ABI
    /// wants it at a call.
    ///
    /// A stack is a region and a register that points into it, and nothing
    /// says the register has to point at the one the kernel handed out. This
    /// is the far end of a quarter megabyte of the block, because stacks grow
    /// down — and being in the block is what keeps the instrument's own frames
    /// out of everybody's count.
    pub(crate) fn stack_top(&mut self) -> *mut u8 {
        // SAFETY: the offset is the end of a region inside the block, which is
        // `BLOCK` bytes long — one past the end, which is where a stack that
        // grows down begins.
        let end = unsafe { self.block.as_mut_ptr().cast::<u8>().add(AT_STACK + STACK) };

        (end as usize & !15) as *mut u8
    }

    /// One number out of the result.
    pub(crate) fn read(&mut self, at: usize) -> u64 {
        self.parts().result[at]
    }
}

impl Drop for ForensicState {
    /// Zeroed on the way out, and volatile so that it happens.
    ///
    /// A block that is merely freed keeps its phrase, and a phrase in the heap
    /// is a stretch every later sweep skips — for as long as the process
    /// lives, over memory that has nothing to do with this crate. Nothing
    /// reads these bytes afterwards, which is exactly the shape of write an
    /// optimiser is entitled to delete, so it is the one kind it may not.
    fn drop(&mut self) {
        let at = self.block.as_mut_ptr();

        for i in 0..self.block.len() {
            // SAFETY: `i` is inside the block, which is live until this
            // returns, and the pointer is aligned for `u64` by construction.
            unsafe { ptr::write_volatile(at.add(i), 0) };
        }
    }
}
