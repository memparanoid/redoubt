// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Every register, copied into a static so that a sweep of memory can read
//! them.
//!
//! # The one place looking harder does not reach
//!
//! A register is in no mapping. Nothing that reads memory has ever been able
//! to see one, which is why a `memcpy` of a secret can leave it sitting in
//! `zmm16` and every instrument in this crate will answer that the process is
//! clean — truthfully, and uselessly.
//!
//! The way out is not to look harder. It is to make the registers stop being
//! registers: copy them out, and they are memory like anything else, found by
//! the same sweep that finds everything else, weighed by the same score.
//!
//! Nothing here clears anything. The registers are read and left exactly as
//! they were; what changes is that a copy of them now exists somewhere a
//! photograph can reach.
//!
//! # Nothing runs at the moment of the capture
//!
//! Every instruction between a secret moving and the capture is a chance for
//! the register holding it to be gone, so the capture is one `call` and there
//! is nothing else to run:
//!
//! - **No argument.** The destination is [`spilled`], a static in `.bss`
//!   reached RIP-relative. A buffer passed in cost `rdi` and whatever the
//!   caller used to work out the address, and the `rdi` slot held our own
//!   pointer instead of the caller's.
//! - **No feature check.** Asking what the machine supports is a branch and an
//!   atomic load, and both need a register. It is asked once, by
//!   [`pick_spiller`], and the answer is a slot the assembly jumps through.
//!
//! [`pick_spiller`] is called by [`crate::Forensics::watching`], so a caller
//! of this crate has nothing to remember. It is idempotent and public for
//! anyone using the capture without the rest.
//!
//! # What it cannot capture
//!
//! Only this thread's. Another thread's registers are that thread's, and no
//! instruction here can reach them — and two threads capturing at once write
//! over each other, because there is one room.
//!
//! The room holds one capture. A second overwrites the first, which is what is
//! wanted when the reading is a difference between photographs, and is worth
//! knowing before writing a loop.
//!
//! # Why `.bss` and not the stack, and not the heap either
//!
//! The stack is out: what writes over a frame next is whatever is called next,
//! and what is called next is exactly what this is trying to catch.
//!
//! The heap is out for two reasons. A block is wherever the allocator put it,
//! so writing to it means carrying its address in a register — which is the
//! argument we just removed. And reaching it means having called `malloc`,
//! whose own wide copies land in the same high vector registers a capture is
//! there to read: the instrument would be planting the thing it measures.
//!
//! `.bss` has neither problem. Its address is known at link time, and it is
//! there from the first instruction of the process. It is an ordinary `rw-p`
//! mapping, swept like any other.
//!
//! # Two architectures, one shape
//!
//! `x86_64` reaches the room RIP-relative and touches no register at all
//! before the first store, so every value in a capture is the caller's own.
//!
//! `aarch64` cannot: a store there has no PC-relative form, so the room's
//! address has to be built into `x0` first, and the branch through the
//! dispatch slot needs `x16`. Both are put back, and `x0` reads back true —
//! but `x16` and `x17` hold the trampoline's own working and not the
//! caller's. They are that architecture's `rdi`: transit, never a resting
//! place, and nothing leaves a secret in one.
//!
//! Each has one place a secret can rest. On `x86_64` it is `zmm16-31`, which
//! no form of `vzeroall` reaches and compiled code never touches. On
//! `aarch64` it is the far end of `z0-z31`: their low 128 bits are `v0-v31`
//! and everything writes those, but past 128 bits only SVE reaches, and a
//! compiler emits none unless it was asked to. Both are captured, and neither
//! by the narrow form — which is what [`pick_spiller`] is for.

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
unsafe extern "C" {
    /// Every register into [`spilled`], in the widest form [`pick_spiller`]
    /// found.
    ///
    /// This is the one to call. It is a jump through a slot, so the call site
    /// is a single call instruction: no argument to compute, no branch, and —
    /// on `x86_64` — no register touched before the first store.
    ///
    /// Raw and public because placement is the whole thing. A caller that
    /// needs this to be the very next instruction after a copy calls it
    /// itself, in the same `unsafe` block, with nothing in between.
    ///
    /// # Safety
    ///
    /// Safe to call at any time. It writes only into the room, and the form it
    /// reaches is one this machine supports.
    ///
    /// Nothing that ships calls this: `freeze!` writes the general registers
    /// itself and reaches [`redoubt_spill_vectors`] for the rest. What reads
    /// the whole form is `src/tests/spiller.rs`, which is where the register
    /// lists live.
    #[cfg(test)]
    pub safe fn redoubt_spill();

    /// The vector half alone, for a caller that wrote the general registers
    /// itself.
    ///
    /// The same jump through a slot, reaching the same form at its second
    /// entry. What it is for is the order: a `call` puts eight bytes below the
    /// stack pointer on `x86_64`, and eight bytes below the stack pointer is
    /// the shallowest of what an operation left. A caller that has copied that
    /// region somewhere else already can afford them; one that has not,
    /// cannot.
    ///
    /// # Safety
    ///
    /// Safe to call at any time. It writes only into the room, and the form it
    /// reaches is one this machine supports.
    pub safe fn redoubt_spill_vectors();

    /// Which form [`redoubt_spill`] jumps to. [`pick_spiller`] writes it.
    ///
    /// Declared as an atomic because that is what it is: one word, written
    /// from Rust and read by the processor's instruction fetch. Its initial
    /// value is the narrowest form, so it is callable before anything picks.
    safe static redoubt_spill_which: core::sync::atomic::AtomicPtr<()>;

    /// Which form [`redoubt_spill_vectors`] jumps to.
    ///
    /// Two slots and not one, because a jump cannot be told which half of a
    /// form to start at. [`use_spiller`] writes both from the one choice, so
    /// the two can only name entries of the same form.
    safe static redoubt_spill_vectors_which: core::sync::atomic::AtomicPtr<()>;

    /// Where a capture lands.
    ///
    /// Declared here for the one caller that needs the address rather than the
    /// contents: a capture written out at its call site, which reaches the
    /// slots itself instead of calling anything. Nothing reads it through this
    /// name — the reader is the sweep, which needs no symbol.
    pub safe static redoubt_spill_room: [u8; SPILL];
}

/// How wide the room is.
///
/// Sixteen general slots of eight bytes and thirty-two vector slots of
/// sixty-four, which is `zmm`'s width.
#[cfg(target_arch = "x86_64")]
pub const SPILL: usize = 2176;

/// How wide the room is.
///
/// Thirty-one general slots and the stack pointer, then thirty-two vector
/// slots of 256 bytes, which is the widest vector this architecture defines.
#[cfg(target_arch = "aarch64")]
pub const SPILL: usize = 8448;

/// Point the dispatch at something that is not a form.
///
/// Beside the slot because the slot is what it writes, and for the reading
/// below: a dispatch pointing somewhere this crate cannot name is the shape of
/// one nobody wrote, and the reading has to say so rather than answer with the
/// nearest form.
///
/// What is in the slot afterwards is the caller's to put back, and nothing may
/// capture in between — the jump would land here.
#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
pub(crate) fn use_no_form() {
    redoubt_spill_which.store(
        pick_spiller as *mut (),
        core::sync::atomic::Ordering::Relaxed,
    );
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe extern "C" {
    /// The general registers and the whole of `zmm0-31`.
    ///
    /// `zmm16-31` are the reason this exists. No form of `vzeroall` reaches
    /// them and ordinary compiled code never touches them, so what a wide
    /// `memcpy` leaves in one stays there — invisible to every other form of
    /// capture in this crate.
    ///
    /// # Safety
    ///
    /// Needs AVX-512F. Call [`redoubt_spill`] instead unless the point is to
    /// force this form.
    pub fn redoubt_spill_avx512();

    /// The same with `ymm0-15`, needing only AVX.
    ///
    /// # Safety
    ///
    /// Needs AVX.
    pub fn redoubt_spill_avx();

    /// The same with `xmm0-15`, needing nothing past SSE2.
    ///
    /// # Safety
    ///
    /// Always available on `x86_64`. Reaches 384 bytes of the room and leaves
    /// the rest as it was.
    pub fn redoubt_spill_sse();

    /// The vector half of [`redoubt_spill_avx512`].
    ///
    /// # Safety
    ///
    /// Needs AVX-512F.
    pub fn redoubt_spill_vectors_avx512();

    /// The vector half of [`redoubt_spill_avx`].
    ///
    /// # Safety
    ///
    /// Needs AVX.
    pub fn redoubt_spill_vectors_avx();

    /// The vector half of [`redoubt_spill_sse`].
    ///
    /// # Safety
    ///
    /// Always available on `x86_64`.
    pub fn redoubt_spill_vectors_sse();
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" {
    /// The general registers, the stack pointer, and the whole of `z0-z31`.
    ///
    /// The far end of a `z` is the reason this exists. `v0-v31` are its low
    /// 128 bits and ordinary compiled code writes those constantly, but past
    /// 128 bits nothing but SVE reaches — and a compiler emits none unless it
    /// was asked to. So on a machine whose vector length is wider than that,
    /// whatever a wide copy left up there stays until the process ends, and
    /// the NEON form cannot see any of it.
    ///
    /// # Safety
    ///
    /// Needs SVE. Call [`redoubt_spill`] instead unless the point is to force
    /// this form.
    pub fn redoubt_spill_sve();

    /// The general registers, the stack pointer, and `v0-v31`.
    ///
    /// NEON is on every `aarch64`, so nothing has to be checked to reach it.
    ///
    /// # Safety
    ///
    /// Safe to call at any time.
    pub safe fn redoubt_spill_neon();

    /// The vector half of [`redoubt_spill_sve`].
    ///
    /// # Safety
    ///
    /// Needs SVE.
    pub fn redoubt_spill_vectors_sve();

    /// The vector half of [`redoubt_spill_neon`].
    ///
    /// # Safety
    ///
    /// Safe to call at any time.
    pub safe fn redoubt_spill_vectors_neon();
}

/// Point [`redoubt_spill`] at the widest form this machine supports.
///
/// Every form is in the binary already. This only decides which one the jump
/// lands on, and it is called by [`crate::Forensics::watching`] long before
/// any capture — because the question cannot be asked at the capture itself.
/// Idempotent: it writes the same answer every time.
///
/// Until this runs, [`redoubt_spill`] reaches the narrowest form — SSE on
/// `x86_64`, NEON on `aarch64`. Correct either way, and a quarter of what a
/// modern machine has.
/// Which registers a capture reaches.
///
/// Named rather than counted in bytes, because a caller comparing a width
/// against a constant is a caller that has to know how wide a slot is — and
/// what it wanted to know was whether this machine has the registers a wide
/// copy of a key passes through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Form {
    /// `xmm0-15`, on every `x86_64` there is.
    #[cfg(target_arch = "x86_64")]
    Sse,
    /// `ymm0-15`.
    #[cfg(target_arch = "x86_64")]
    Avx,
    /// `zmm0-31`, the half of which nothing else in a process writes.
    #[cfg(target_arch = "x86_64")]
    Avx512,
    /// `v0-31`, on every `aarch64`.
    #[cfg(target_arch = "aarch64")]
    Neon,
    /// `z0-31`, whose far end is where `aarch64` keeps what NEON cannot see.
    #[cfg(target_arch = "aarch64")]
    Sve,
}

pub fn pick_spiller() {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    use_spiller(pick_spiller_from(
        std::arch::is_x86_feature_detected!("avx512f"),
        std::arch::is_x86_feature_detected!("avx"),
    ));

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    use_spiller(pick_spiller_from(std::arch::is_aarch64_feature_detected!(
        "sve"
    )));
}

/// Which capture a machine with those registers wants.
///
/// The machine's answers arrive rather than being asked for here, because what
/// this decides is decided by them alone — and a machine is one set of answers
/// for the life of a process, so asked here there would be one arm of this
/// anybody could ever reach.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[must_use]
pub(crate) fn pick_spiller_from(wide: bool, some: bool) -> Form {
    if wide {
        Form::Avx512
    } else if some {
        Form::Avx
    } else {
        Form::Sse
    }
}

/// The same, where the choice is one question wide.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[must_use]
pub(crate) fn pick_spiller_from(wide: bool) -> Form {
    if wide { Form::Sve } else { Form::Neon }
}

/// Point both entries at that form.
///
/// The one place a form becomes an address. A jump is what a capture does
/// first and it uses no register to get there, so what it lands on has to be
/// settled long beforehand and written down once.
///
/// Both slots are written here and from the one answer, so that the two can
/// only ever name entries of the same form.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
pub(crate) fn use_spiller(form: Form) {
    let (whole, vectors): (unsafe extern "C" fn(), unsafe extern "C" fn()) = match form {
        #[cfg(target_arch = "x86_64")]
        Form::Avx512 => (redoubt_spill_avx512, redoubt_spill_vectors_avx512),
        #[cfg(target_arch = "x86_64")]
        Form::Avx => (redoubt_spill_avx, redoubt_spill_vectors_avx),
        #[cfg(target_arch = "x86_64")]
        Form::Sse => (redoubt_spill_sse, redoubt_spill_vectors_sse),
        #[cfg(target_arch = "aarch64")]
        Form::Sve => (redoubt_spill_sve, redoubt_spill_vectors_sve),
        #[cfg(target_arch = "aarch64")]
        Form::Neon => (redoubt_spill_neon, redoubt_spill_vectors_neon),
    };

    redoubt_spill_which.store(whole as *mut (), core::sync::atomic::Ordering::Relaxed);

    redoubt_spill_vectors_which.store(vectors as *mut (), core::sync::atomic::Ordering::Relaxed);
}

/// Which capture the dispatch is pointing at.
///
/// The widest registers a machine has are the ones a `memcpy` of a key is
/// likeliest to pass through, and whether this machine has them at all is a
/// property of the machine and not of the code — so a run that reports `neon`
/// has said nothing about `sve`, and a reader with no way to tell the two
/// apart would read the silence as coverage.
///
/// Asked of the pointer the dispatch actually jumps through, so it cannot
/// disagree with what runs.
#[cfg(test)]
pub(crate) fn picked() -> Option<Form> {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    {
        let at = redoubt_spill_which.load(core::sync::atomic::Ordering::Relaxed);

        #[cfg(target_arch = "x86_64")]
        let every = [
            (redoubt_spill_avx512 as unsafe extern "C" fn(), Form::Avx512),
            (redoubt_spill_avx, Form::Avx),
            (redoubt_spill_sse, Form::Sse),
        ];

        #[cfg(target_arch = "aarch64")]
        let every = [
            (redoubt_spill_sve as unsafe extern "C" fn(), Form::Sve),
            (redoubt_spill_neon, Form::Neon),
        ];

        for (one, form) in every {
            if core::ptr::eq(at, one as *mut ()) {
                return Some(form);
            }
        }

        None
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    )))]
    None
}
