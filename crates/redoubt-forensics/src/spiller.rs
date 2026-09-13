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

/// How much one capture is: the general registers, then one slot per vector
/// register wide enough for the widest one the architecture has.
///
/// The two differ only in how much of the front the general registers take —
/// sixteen of them on `x86_64`, thirty-one and the stack pointer on
/// `aarch64`. [`spilled`] says where each one lands.
#[cfg(target_arch = "x86_64")]
pub const SPILL: usize = 128 + 32 * 64;

/// How much one capture is. See the `x86_64` form above.
#[cfg(target_arch = "aarch64")]
pub const SPILL: usize = 256 + 32 * 256;

/// Where the vector slots begin.
#[cfg(target_arch = "x86_64")]
pub const VECTORS: usize = 128;

/// Where the vector slots begin.
#[cfg(target_arch = "aarch64")]
pub const VECTORS: usize = 256;

/// Nothing, on an architecture there is no capture for.
///
/// Zero and not a guess: [`spilled`] hands back an empty slice there, and a
/// caller reading a room of no bytes finds no registers, which is exactly
/// what happened.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const SPILL: usize = 0;

/// Nothing, on an architecture there is no capture for.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const VECTORS: usize = 0;

/// How far apart one vector slot is from the next.
///
/// As wide as the widest vector the architecture defines, whatever this
/// machine's happens to be — `zmm` at 64 bytes, an SVE `z` at 256 — so that
/// the layout does not move when the form does. [`spilled_width`] says how
/// much of each slot the last capture actually wrote.
#[cfg(target_arch = "x86_64")]
pub const SLOT: usize = 64;

/// How far apart one vector slot is from the next.
#[cfg(target_arch = "aarch64")]
pub const SLOT: usize = 256;

/// How far apart one vector slot is from the next.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const SLOT: usize = 0;

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
    pub safe fn redoubt_spill();

    /// Where the captures land. [`spilled`] reads it; nothing should write it.
    static redoubt_spill_room: [u8; SPILL];

    /// How many bytes of each vector slot the last capture wrote.
    ///
    /// [`spilled_width`] reads it; the assembly writes it.
    static redoubt_spill_width: usize;

    /// Which form [`redoubt_spill`] jumps to. [`pick_spiller`] writes it.
    ///
    /// Declared as an atomic because that is what it is: one word, written
    /// from Rust and read by the processor's instruction fetch. Its initial
    /// value is the narrowest form, so it is callable before anything picks.
    safe static redoubt_spill_which: core::sync::atomic::AtomicPtr<()>;
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
pub fn pick_spiller() {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        let pick: unsafe extern "C" fn() = if std::arch::is_x86_feature_detected!("avx512f") {
            redoubt_spill_avx512
        } else if std::arch::is_x86_feature_detected!("avx") {
            redoubt_spill_avx
        } else {
            redoubt_spill_sse
        };

        redoubt_spill_which.store(pick as *mut (), core::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        let pick: unsafe extern "C" fn() = if std::arch::is_aarch64_feature_detected!("sve") {
            redoubt_spill_sve
        } else {
            redoubt_spill_neon
        };

        redoubt_spill_which.store(pick as *mut (), core::sync::atomic::Ordering::Relaxed);
    }
}

/// Every register this thread has, into the room.
///
/// `inline(always)` and a bare call, so this costs exactly what
/// [`redoubt_spill`] costs and adds no frame of its own.
///
/// ```no_run
/// # use redoubt_forensics::{spill, spilled};
/// spill();
/// // ... take the photograph, and the room is still there ...
/// core::hint::black_box(spilled());
/// ```
#[inline(always)]
pub fn spill() {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    redoubt_spill();
}

/// The room, so that a photograph has something to find and a caller can keep
/// it observed.
///
/// All [`SPILL`] bytes, whichever form last wrote into it. Vector register
/// `n` is at `VECTORS + n * SLOT` on both architectures, at whatever width
/// was captured, the rest of its slot left as it was. The general registers
/// are the front, and there the two differ:
///
/// ```text
/// x86_64    0    rax rbx rcx rdx rsi rdi rbp rsp r8..r15
/// aarch64   0    x0..x30, then sp at 248
/// ```
///
/// A slot is as wide as the widest vector the architecture defines, and the
/// form that ran may have written less of it. [`spilled_width`] says how much
/// — without it, a register captured narrow reads the same as one captured
/// wide that happened to be empty past its sixteenth byte.
#[must_use]
pub fn spilled() -> &'static [u8] {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    {
        // SAFETY: the room is a static of exactly this size, written only by
        // the captures above, and `u8` has no invalid bit patterns. A capture
        // racing this is a torn read of bytes nobody interprets.
        unsafe { &*core::ptr::addr_of!(redoubt_spill_room) }
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    )))]
    {
        &[]
    }
}

/// How many bytes of each vector slot the last capture wrote.
///
/// Sixteen, thirty-two or sixty-four on `x86_64`, by which form ran; sixteen
/// from NEON, or this machine's vector length from SVE, on `aarch64`. Zero
/// until something has been captured.
///
/// Anything past this in a slot is whatever was there before, which on a room
/// nothing has overwritten is zero — and a register that is genuinely zero
/// reads the same way. That is the difference this answers.
#[must_use]
pub fn spilled_width() -> usize {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    {
        // SAFETY: a static word, written by the captures and read here. A
        // capture racing this hands back one of the two widths, both true.
        unsafe { core::ptr::read_volatile(&raw const redoubt_spill_width) }
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    )))]
    {
        0
    }
}
