// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! A photograph of this process's memory, and who is allowed to look at it.
//!
//! # Three processes, and why
//!
//! An instrument that allocates while it measures is measuring itself. Reading
//! one's own memory means holding a window of it, and that window is a second
//! copy of whatever was in it — including the thing being looked for, in the
//! very memory being looked through.
//!
//! One fork is not enough for that, only for half of it. A parent that forks a
//! child and then reads the child gets a photograph the reading cannot
//! disturb — but the *reading* happens in the parent, and everything it
//! touches is still there when the next photograph is taken. Two measurements
//! either side of an operation are only worth comparing if the first one did
//! not write over what the second one reads.
//!
//! So there are three:
//!
//! ```text
//! P ── fork ──▶ A ── fork ──▶ A'   traces itself, stops, and is the photograph
//! │             │
//! │             └── reads A', counts, writes the answer down the pipe, _exit
//! └── reads the answer. Nothing else of this ever reaches P.
//! ```
//!
//! `A` is `A'`'s parent and its tracer, which is what makes it allowed to
//! read it where `ptrace_scope` is anything but zero. `A` gets filthy —
//! megabytes of somebody else's memory pass through it — and then it is gone.
//! What arrives in `P` is a handful of numbers.
//!
//! # The child asks for nothing
//!
//! `fork` takes one thread and the whole address space, locks and all, so a
//! lock another thread held at that instant is held in the child by nobody.
//! The analyst therefore allocates nothing: everything it writes into was
//! reserved by `P` before the fork and is reached through the same addresses,
//! because that is what inheriting an address space means.
//!
//! It does not open `/proc/<pid>/mem` either. `process_vm_readv` takes the pid
//! and needs no path, so there is no string to build.

use std::ptr;

use crate::state::{BLOCK, ForensicState, MAGIC, OK, Parts, Span, Spans};

/// A stopped child holding a photograph of its parent's memory.
///
/// It is killed and reaped in a `Drop` rather than at the end of whatever made
/// it: a panic between the two would otherwise leave a stopped process behind
/// for as long as the test runner lives.
pub(crate) struct Subject {
    pid: libc::pid_t,
}

impl Subject {
    /// This process, photographed.
    ///
    /// The child asks to be traced before it stops, which is what makes its
    /// parent its tracer and its memory readable — a plain parent is not
    /// enough where `ptrace_scope` is anything but zero.
    ///
    /// Nothing between the fork and the stop allocates or runs a destructor.
    /// Only the calling thread survives into the child, so anything another
    /// thread was holding at that moment is held by nobody there.
    pub(crate) fn photograph() -> Option<Self> {
        // SAFETY: `fork` is called with nothing else of this library's in
        // flight. The child path below touches only async-signal-safe calls
        // and leaves through `_exit`, which runs no destructor and flushes
        // nothing the parent also owns.
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            return None;
        }

        if pid == 0 {
            // SAFETY: the child, which is about to stop and then leave. None
            // of the three returns to Rust.
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut::<libc::c_void>(), 0);
                libc::raise(libc::SIGSTOP);
                libc::_exit(0);
            }
        }

        let mut status = 0;

        // SAFETY: the pid is this process's own child, and the status is a
        // local this call writes into.
        if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
            return None;
        }

        // A child that was reaped rather than stopped has no memory left to
        // read, and reading nothing would answer the same as finding nothing.
        if !libc::WIFSTOPPED(status) {
            return None;
        }

        Some(Self { pid })
    }

    /// As much of the photograph at that address as fits, and nothing on
    /// refusal.
    ///
    /// No path and no open file: the pid is the whole address.
    pub(crate) fn read_at(&self, at: u64, into: &mut [u8]) -> usize {
        let local = libc::iovec {
            iov_base: into.as_mut_ptr().cast(),
            iov_len: into.len(),
        };

        let remote = libc::iovec {
            iov_base: at as usize as *mut libc::c_void,
            iov_len: into.len(),
        };

        // SAFETY: both vectors describe one buffer each. The local one is the
        // slice that was handed in, live and writable for its whole length;
        // the remote one is read in another address space and never
        // dereferenced here. The pid is this process's own traced child.
        let got = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };

        usize::try_from(got).unwrap_or(0)
    }
}

impl Drop for Subject {
    fn drop(&mut self) {
        // SAFETY: the pid is this process's own child, stopped and not yet
        // reaped, so it cannot have been reused for anything else.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, ptr::null_mut(), 0);
        }
    }
}

/// `7f8e1c000000-7f8e1c021000 rw-p 00000000 00:00 0`, as far as the flags.
///
/// Bytes and not a `str`, because the caller of this has already forked and
/// may not allocate: there is no line to have been read into a `String`, only
/// a stretch of the buffer the whole file was read into at once.
pub(crate) fn region(line: &[u8]) -> Option<Span> {
    let dash = line.iter().position(|byte| *byte == b'-')?;
    let space = line.iter().position(|byte| *byte == b' ')?;

    if dash > space {
        return None;
    }

    // Writable, and not merely readable. What is left behind is left behind
    // by writing, so a mapping nothing can write to holds only what a compiler
    // put there. Reading those as well is seconds per sweep for a binary of
    // any size, and finds nothing a caller is asking about.
    if line.get(space + 1..space + 3)? != b"rw" {
        return None;
    }

    Some((hex(&line[..dash])?, hex(&line[dash + 1..space])?))
}

/// A run of hexadecimal, read where it lies.
fn hex(of: &[u8]) -> Option<u64> {
    if of.is_empty() || of.len() > 16 {
        return None;
    }

    let mut at = 0_u64;

    for byte in of {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };

        at = at * 16 + u64::from(digit);
    }

    Some(at)
}

/// `/proc/<pid>/maps`, written into a buffer rather than built.
fn named(pid: libc::pid_t, into: &mut [u8; 32]) -> bool {
    let mut digits = [0_u8; 10];
    let mut count = 0;
    let mut left = pid.unsigned_abs();

    loop {
        digits[count] = b'0' + (left % 10) as u8;
        count += 1;
        left /= 10;

        if left == 0 {
            break;
        }
    }

    let mut at = 0;

    for byte in b"/proc/" {
        into[at] = *byte;
        at += 1;
    }

    while count > 0 {
        count -= 1;
        into[at] = digits[count];
        at += 1;
    }

    for byte in b"/maps\0" {
        into[at] = *byte;
        at += 1;
    }

    true
}

/// Every writable mapping of the photograph, read without asking for memory.
///
/// The whole file into a buffer that was reserved long before any of this, and
/// parsed where it lies. A `BufReader` and a `String` per line would be easier
/// and are the two things this may not do: allocate, and take a kilobyte of
/// somebody's stack doing it.
///
/// The photograph's mappings and not this process's. They were the same list
/// at the instant of the fork and stop being one as soon as anybody allocates,
/// which is about to happen a great deal.
pub(crate) fn mappings(pid: libc::pid_t, text: &mut [u8], maps: &mut Spans<'_>) -> bool {
    maps.clear();

    let mut path = [0_u8; 32];

    if !named(pid, &mut path) {
        return false;
    }

    // SAFETY: the path is a buffer this function just wrote and terminated.
    let file = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };

    if file < 0 {
        return false;
    }

    let mut filled = 0;

    while filled < text.len() {
        // SAFETY: the pointer and length are the part of a live slice that has
        // not been filled yet.
        let got = unsafe {
            libc::read(file, text[filled..].as_mut_ptr().cast(), text.len() - filled)
        };

        if got <= 0 {
            break;
        }

        filled += got as usize;
    }

    // SAFETY: a descriptor this function just opened.
    unsafe { libc::close(file) };

    for line in text[..filled].split(|byte| *byte == b'\n') {
        let Some(span) = region(line) else {
            continue;
        };

        if !maps.push(span) {
            return false;
        }
    }

    !maps.is_empty()
}

/// Every block of the instrument that is in the photograph.
///
/// One pass looking for nothing but the phrase, so that the pass that counts
/// can leave those stretches alone. The blocks are the same size, so the
/// phrase is the whole address: find it, and the next [`BLOCK`] bytes are not
/// anybody's memory but this crate's.
pub(crate) fn instrument(
    subject: &Subject,
    held: &mut [u8],
    maps: &Spans<'_>,
    skips: &mut Spans<'_>,
) -> bool {
    skips.clear();

    let seam = MAGIC.len() - 1;

    for (from, to) in maps.iter() {
        let mut at = from;

        while at < to {
            let want = (to - at).min(held.len() as u64) as usize;
            let got = subject.read_at(at, &mut held[..want]);

            if got < MAGIC.len() {
                break;
            }

            for (i, window) in held[..got].windows(MAGIC.len()).enumerate() {
                if window == MAGIC {
                    let one = at + i as u64;

                    if !skips.push((one, one + BLOCK as u64)) {
                        return false;
                    }
                }
            }

            if got <= seam {
                break;
            }

            at += (got - seam) as u64;
        }
    }

    true
}

/// Every byte of the photograph that is not the instrument's own, in address
/// order, and how many of them there were.
///
/// `on` is handed a window, the address it starts at, and whether the ground
/// breaks after it — the end of a mapping, a stretch being skipped, or a read
/// that was refused. An empty window with the break set is a break and nothing
/// else, which is what a caller carrying a run across windows needs in order
/// to know when not to.
///
/// `seam` is how much consecutive windows share. A caller matching something
/// `n` bytes wide wants `n - 1`, or it will miss every one that straddles two
/// windows. A caller carrying its own state across the boundary wants `0`, and
/// then the windows go end to end and nothing is read twice.
pub(crate) fn sweep(
    subject: &Subject,
    held: &mut [u8],
    maps: &Spans<'_>,
    skips: &Spans<'_>,
    seam: usize,
    mut on: impl FnMut(&[u8], u64, bool),
) -> u64 {
    let mut swept = 0;

    for (from, to) in maps.iter() {
        let mut at = from;

        while at < to {
            // Inside one of ours: step over the whole of it, and whatever was
            // being carried ends here.
            if let Some(past) = inside(skips, at) {
                at = past.min(to).max(at + 1);
                on(&[], at, true);
                continue;
            }

            let stop = next_skip(skips, at).min(to);
            let want = (stop - at).min(held.len() as u64) as usize;

            if want == 0 {
                break;
            }

            let got = subject.read_at(at, &mut held[..want]);

            // A mapping that went away between the listing and the read, or
            // one the kernel will not hand over. Either way the ground breaks.
            if got == 0 {
                on(&[], at, true);
                break;
            }

            swept += got as u64;

            let ends = at + got as u64 >= stop;

            on(&held[..got], at, ends);

            if ends {
                at = stop;
                continue;
            }

            if got <= seam {
                break;
            }

            at += (got - seam) as u64;
        }

        on(&[], at, true);
    }

    swept
}

/// Where the stretch containing that address ends, if one does.
fn inside(skips: &Spans<'_>, at: u64) -> Option<u64> {
    skips
        .iter()
        .find(|(from, to)| at >= *from && at < *to)
        .map(|(_, to)| to)
}

/// Where the next stretch after that address begins, or nowhere.
fn next_skip(skips: &Spans<'_>, at: u64) -> u64 {
    skips
        .iter()
        .map(|(from, _)| from)
        .filter(|from| *from > at)
        .min()
        .unwrap_or(u64::MAX)
}

/// Run the analysis in a child, and bring back only what it answers.
///
/// The child is where every byte of the subject's memory goes, and the child
/// does not come back. What crosses the pipe is the handful of numbers in the
/// result, which is the whole reason there are two forks rather than one.
pub(crate) fn analyse(
    state: &mut ForensicState,
    work: fn(&mut ForensicState, &Subject) -> bool,
) -> bool {
    let mut ends = [0 as libc::c_int; 2];

    // SAFETY: the argument is a local array of the two descriptors this fills.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } < 0 {
        return false;
    }

    let (reading, writing) = (ends[0], ends[1]);

    // SAFETY: nothing of this library's is in flight. The child path allocates
    // nothing — everything it writes to was reserved above — and leaves
    // through `_exit`, which runs no destructor and flushes nothing.
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        // SAFETY: both are descriptors this function just opened.
        unsafe {
            libc::close(reading);
            libc::close(writing);
        }

        return false;
    }

    if pid == 0 {
        // SAFETY: the analyst. It closes the end it will not use, works, sends
        // what it found, and leaves without returning to Rust.
        unsafe { libc::close(reading) };

        if let Some(subject) = Subject::photograph() {
            // Read on this side of the fork, where taking a kilobyte of stack
            // would cost nothing — this stack is one nobody is measuring.
            let known = {
                let Parts { report, mut maps, .. } = state.parts();

                mappings(subject.pid, report, &mut maps)
            };

            if known && work(state, &subject) {
                state.parts().result[OK] = 1;
            }

            // Reaped here and not at the end of the scope, because there is no
            // end of the scope: `_exit` runs no destructor.
            drop(subject);
        }

        send(writing, state.shipped());

        // SAFETY: the child, which does not return.
        unsafe { libc::_exit(0) };
    }

    // SAFETY: a descriptor this function just opened, and the end this process
    // will not write to.
    unsafe { libc::close(writing) };

    let heard = recv(reading, state.shipped());

    // SAFETY: the other end, now that it has been read to the finish.
    unsafe { libc::close(reading) };

    let mut status = 0;

    // SAFETY: the pid is this process's own child and the status is a local.
    unsafe { libc::waitpid(pid, &mut status, 0) };

    heard && state.read(OK) == 1
}

/// All of it, however many turns that takes.
fn send(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut sent = 0;

    while sent < bytes.len() {
        // SAFETY: the pointer and length describe the part of a live slice
        // that has not been written yet.
        let put = unsafe {
            libc::write(fd, bytes[sent..].as_ptr().cast(), bytes.len() - sent)
        };

        if put <= 0 {
            return false;
        }

        sent += put as usize;
    }

    true
}

/// The same, the other way.
fn recv(fd: libc::c_int, bytes: &mut [u8]) -> bool {
    let mut heard = 0;

    while heard < bytes.len() {
        let want = bytes.len() - heard;

        // SAFETY: the pointer and length describe the part of a live slice
        // that has not been filled yet.
        let got = unsafe { libc::read(fd, bytes[heard..].as_mut_ptr().cast(), want) };

        if got <= 0 {
            return false;
        }

        heard += got as usize;
    }

    true
}

/// How many times `needle` is in `held`, read forwards or backwards.
///
/// Backwards is a comparison and never a second copy of the needle: the bytes
/// are walked in reverse where they already are.
pub(crate) fn within(held: &[u8], needle: &[u8], reversed: bool) -> usize {
    if needle.is_empty() || held.len() < needle.len() {
        return 0;
    }

    held.windows(needle.len())
        .filter(|at| {
            if reversed {
                at.iter().eq(needle.iter().rev())
            } else {
                at.iter().eq(needle.iter())
            }
        })
        .count()
}

/// What the analysis needs, on its way to a different stack.
#[repr(C)]
pub(crate) struct Errand {
    state: *mut ForensicState,
    work: fn(&mut ForensicState, &Subject) -> bool,
    done: bool,
}

/// The analysis, entered from the far side of the switch.
///
/// `extern "C"` not for the calling convention but for what it does to a
/// panic: one that reaches this boundary aborts instead of unwinding.
/// Unwinding is the thing that must not happen here — the frames below this
/// one are on a stack the unwinder has never heard of, and it would walk off
/// the end of the world looking for a caller.
extern "C" fn errand(at: *mut Errand) {
    // SAFETY: the pointer is the live `Errand` the switch was handed, sitting
    // in the frame of whoever called it, and nothing else refers to it.
    let at = unsafe { &mut *at };

    // SAFETY: the state outlives the errand by construction — it is borrowed
    // for the whole of `elsewhere`, which does not return until this does.
    let state = unsafe { &mut *at.state };

    at.done = analyse(state, at.work);
}

/// Run the analysis with the stack pointer moved somewhere nobody is looking.
///
/// # The last hundred bytes
///
/// Everything else was moved to before the operation, and what was left was
/// the handful of frames between the caller and the `fork`. A hundred bytes of
/// stack is three copies of a thirty-two byte secret, so a handful of frames
/// is not small enough to stop caring about.
///
/// A stack is a region and a register pointing into it, and nothing says the
/// register has to point at the region the kernel handed out. So this points
/// it at the block instead — reserved long ago, and skipped by the sweep
/// because the phrase is at the front of it. From the switch onwards, every
/// frame the instrument pushes lands somewhere that is neither the caller's
/// stack nor anybody's evidence.
///
/// Inlined, so that reaching the switch is not itself a call. What is written
/// below the caller's frame is then nothing at all.
#[inline(always)]
pub(crate) fn elsewhere(
    state: &mut ForensicState,
    work: fn(&mut ForensicState, &Subject) -> bool,
) -> bool {
    let top = state.stack_top();
    let mut at = Errand { state: std::ptr::from_mut(state), work, done: false };
    let to = std::ptr::from_mut(&mut at);

    // SAFETY: `top` is sixteen-aligned and the far end of a quarter megabyte
    // inside the block, which is live for the whole of this call and is not
    // otherwise in use. The stack pointer is put back from a callee-saved
    // register the called function is obliged to preserve, so the caller's
    // stack is exactly as it was. `errand` is `extern "C"`, so nothing
    // unwinds out of it.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov rdi, {to}",
            "mov r12, rsp",
            "mov rsp, {top}",
            "call {run}",
            "mov rsp, r12",
            to = in(reg) to,
            top = in(reg) top,
            run = in(reg) errand as extern "C" fn(*mut Errand),
            out("r12") _,
            clobber_abi("sysv64"),
        );

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "mov x0, {to}",
            "mov x19, sp",
            "mov sp, {top}",
            "blr {run}",
            "mov sp, x19",
            to = in(reg) to,
            top = in(reg) top,
            run = in(reg) errand as extern "C" fn(*mut Errand),
            out("x19") _,
            clobber_abi("C"),
        );

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        errand(to);
    }

    at.done
}
