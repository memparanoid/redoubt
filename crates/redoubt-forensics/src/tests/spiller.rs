// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What the capture writes down, held to it.
//!
//! # Why these are not out in `tests/`
//!
//! Everything they touch is this crate's own business: which slot a register
//! lands in, which form the machine got, how wide a slot is. None of it is
//! anybody's to call, and putting the tests in here is what lets it stay that
//! way — an integration test can only reach what is public, and that is a
//! reason to make things public that nobody asked for.
//!
//! # A process each
//!
//! The room the capture writes is one static, shared by every thread. Two of
//! these at once are two captures into the same bytes, and the second would be
//! read as the first. Under `cargo test` they skip themselves and say so.
//!
//! # The chain, and where this is one link of it
//!
//! A caller that reads "nothing survived in a register" is trusting three
//! things, and each is measured somewhere:
//!
//! 1. **A value that reaches a register is found.** That is
//!    `test_a_register_spilled_onto_a_dead_frame_is_found`, out in
//!    `tests/integration.rs`, and it is the one to read first — a secret goes
//!    through a pair of vector registers onto a frame that then dies, the
//!    whole of [`forensics!`](crate::forensics) runs over it, and it comes
//!    back found. End to end, through the same door a caller uses.
//! 2. **Every register reaches the room, at its own slot.** That is this file.
//!    Without it, step one is one path that happens to work and says nothing
//!    about the other twenty-nine.
//! 3. **The room is memory the sweep reads.** It is a static in the process,
//!    and the sweep reads the process.
//!
//! Which is why the tests here assert a mapping and not a presence. A capture
//! that wrote every register into one slot would satisfy step one and fail
//! everyone whose secret was in a different register.
//!
//! # Why there is no control for a stale room
//!
//! The obvious next test is: seed, capture, clear, capture again, and demand
//! the slot came back empty — a room that wrote once and never refreshed would
//! fail it. It is not here because nothing can produce that failure. Each form
//! is a straight run of unconditional stores: no branch, no flag, nothing that
//! asks whether a slot was written before. A test for a mode the code has no
//! way to be in is ceremony, and it costs a green that means nothing.
//!
//! Should a form ever grow a reason to skip a store — a cache, a dirty bit, a
//! fast path — that stops being true and the control is worth writing that
//! day.
//!
//! # And what none of this says
//!
//! That the capture runs at the right moment. What is asserted here is that it
//! writes down what it was called on; whether the thing that calls it does so
//! while a secret is still in a register is a question about
//! [`forensics!`](crate::forensics), not about this.
//!
//! Nor that anything is absent. These say the instrument looks, and looks in
//! the right place. Every absence the rest of the workspace reports is worth
//! what they are worth, and no more.

use crate::spiller::{Form, pick_spiller, pick_spiller_from, picked, use_no_form, use_spiller};

// ============================================================================
// The room, read from Rust
// ============================================================================

// The capture's own side of the boundary, declared here rather than beside the
// rest of the assembly it belongs to.
//
// Because nothing that ships reads it. The room is written on every
// measurement and it is the whole mechanism — but what reads it in earnest is
// the sweep, through `/proc/<pid>/mem`, finding the copy as memory like any
// other and needing no symbol and no constant to do it. Naming it from Rust is
// something only these tests want, so the naming lives with them.

/// How much one capture is: the general registers, then one slot per vector
/// register wide enough for the widest one the architecture has.
#[cfg(target_arch = "x86_64")]
const SPILL: usize = 128 + 32 * 64;

/// How much one capture is. See the `x86_64` form above.
#[cfg(target_arch = "aarch64")]
const SPILL: usize = 256 + 32 * 256;

/// Where the vector slots begin: past the general registers, of which there
/// are sixteen here and thirty-one and a stack pointer there.
#[cfg(target_arch = "x86_64")]
const VECTORS: usize = 128;

/// Where the vector slots begin.
#[cfg(target_arch = "aarch64")]
const VECTORS: usize = 256;

/// How far apart one vector slot is from the next.
///
/// As wide as the widest vector the architecture defines, whatever this
/// machine's happens to be — `zmm` at 64 bytes, an SVE `z` at 256 — so that
/// the layout does not move when the form does.
#[cfg(target_arch = "x86_64")]
const SLOT: usize = 64;

/// How far apart one vector slot is from the next.
#[cfg(target_arch = "aarch64")]
const SLOT: usize = 256;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe extern "C" {
    /// Where the captures land. Read here; nothing should ever write it.
    static redoubt_spill_room: [u8; SPILL];

    /// How many bytes of each vector slot the last capture wrote.
    static redoubt_spill_width: usize;
}

/// The room, as bytes.
///
/// A slot is as wide as the widest vector the architecture defines, and the
/// form that ran may have written less of it — so a register captured narrow
/// reads the same as one captured wide that happened to be empty past its
/// sixteenth byte. Every test here knows which form it called, so it knows
/// which of the two it is looking at.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn spilled() -> &'static [u8] {
    // SAFETY: the room is a static of exactly this size, written only by the
    // captures, and `u8` has no invalid bit patterns. Nothing else in this
    // process is capturing while a test reads.
    unsafe { &*core::ptr::addr_of!(redoubt_spill_room) }
}

/// How many bytes of each vector slot the last capture wrote.
///
/// Sixteen, thirty-two or sixty-four on `x86_64`, by which form ran; sixteen
/// from NEON, or this machine's vector length from SVE, on `aarch64`.
///
/// Anything past this in a slot is whatever was there before, which on a room
/// nothing has overwritten is zero — and a register that is genuinely zero
/// reads the same way. That is the difference this answers.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn spilled_width() -> usize {
    // SAFETY: a static word, written by the captures and read here.
    unsafe { core::ptr::read_volatile(&raw const redoubt_spill_width) }
}

/// Thirty-two distinct bytes, so a run that extends did not extend by luck.
const ALPHA: [u8; 32] = [
    0x9E, 0x41, 0x17, 0xC3, 0x5A, 0xF0, 0x2B, 0x88, 0x6D, 0xB4, 0x0A, 0xE7, 0x39, 0x52, 0xCE, 0x71,
    0x84, 0x1D, 0xA6, 0x3F, 0xD8, 0x60, 0x95, 0x2E, 0xBB, 0x07, 0x4C, 0xE1, 0x76, 0xAF, 0x13, 0xCA,
];

/// A test that needs a process to itself, or a word about why it did not run.
///
/// Silently passing would be worse than failing: the room is one static, and a
/// capture taken beside another is a reading of that one.
macro_rules! alone {
    () => {
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!("skipped: this test needs a process of its own. `cargo nextest run`.");

            return;
        }
    };
}

/// Whether the capture wrote the general slots at all.
///
/// The least any of these can be held to, and the most that can be asked
/// without choosing what the registers hold. A capture that writes nothing, or
/// writes somewhere nobody reads, is indistinguishable from a machine whose
/// registers are empty — and this tells the two apart, because the stack
/// pointer is one of them and a running process has a stack.
///
/// What is in a vector register after a copy is the compiler's to decide, so
/// there is no honest floor to put under that here. Seeding each register and
/// reading it back is the test that can, and it is not one of these.
fn filled_the_general_slots(room: &[u8]) -> bool {
    room[..VECTORS].iter().any(|byte| *byte != 0)
}

/// Thirty-two bytes moved, and every register captured by the very next
/// instruction.
///
/// No wrapper, no bounds check, no method call: the capture is called raw,
/// because anything at all between the copy and the capture is a chance for
/// the register to be gone. It takes no argument, so there is not even an
/// address to work out for it — the call is one instruction and the
/// destination is in the instructions that follow it.
#[inline(never)]
fn copy_then_capture(from: &[u8], into: &mut [u8]) {
    // SAFETY: `from` and `into` are different allocations and `into` is at
    // least as long. Nothing runs between the two, which is the point.
    unsafe {
        core::ptr::copy_nonoverlapping(from.as_ptr(), into.as_mut_ptr(), from.len());
        crate::spiller::redoubt_spill();
    }
}

// ============================================================================
// One register, put there on purpose
// ============================================================================

/// Sixteen bytes of a value nothing else in this process is holding.
///
/// Never `0x00` and never `0xFF`, which are what an untouched slot and an
/// erased one hold: a test seeded with either would pass on a capture that
/// wrote nothing. The rest is chosen for the assertion below rather than for
/// looks — it has to be a value the room does not already contain, so that
/// finding it anywhere but the one slot means the capture put it there.
/// As wide as the widest register any of these seeds, which is a `zmm`. A
/// narrower one takes the front of it and the assertion compares that much.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SEED: [u8; 64] = [
    0x6C, 0x93, 0x2A, 0xE7, 0x51, 0xB8, 0x0D, 0xF4, 0x37, 0xA1, 0x5E, 0xC2, 0x89, 0x14, 0xDB, 0x76,
    0x2F, 0xC5, 0x8A, 0x41, 0xE3, 0x19, 0xB6, 0x7D, 0x50, 0xAC, 0x3B, 0xD8, 0x64, 0x9F, 0x27, 0xE1,
    0x48, 0xBD, 0x16, 0x73, 0xCA, 0x2E, 0x95, 0x08, 0xDF, 0x61, 0xA4, 0x39, 0x7C, 0xD2, 0x85, 0x1B,
    0xF0, 0x56, 0xE9, 0x23, 0xB7, 0x4D, 0x0A, 0x98, 0x35, 0xC1, 0x6E, 0xFA, 0x82, 0x1F, 0xA7, 0x54,
];

/// One register set to [`SEED`], and the room read back around it.
///
/// The strong half is not that the slot holds the value — it is that nothing
/// else does. A capture that wrote every register into one slot, or wrote one
/// register into every slot, or wrote the right bytes into the neighbour's
/// place, holds the value somewhere and passes a test that only asks whether
/// it is there. So the mapping is what is asserted: this register, that slot,
/// and nowhere else.
///
/// # Why the seeding and the call are one block
///
/// Most of what is seeded here is caller-saved, which is exactly the licence
/// the compiler needs to put something else in it. A seed written in one
/// statement and a call made in the next is a seed the compiler may discard,
/// reload, or route through somewhere else entirely. Inside one `asm!` there
/// is nowhere for it to put anything.
///
/// That the call arrives with everything intact is the capture's own doing:
/// `redoubt_spill` is an indirect jump through a slot, using no register to
/// reach it, and each form writes every register down before it uses one.
///
/// # The SSE form by name
///
/// Called directly rather than through the slot, because which form the slot
/// holds is the machine's to decide and this asserts an exact layout. The
/// wider forms fill the same slots and more.
///
/// # What is not here
///
/// `rsp`, which cannot be given a value of anyone's choosing and still be a
/// stack, and `rbp`, which holds the frame pointer rather than anything of
/// anyone's. Neither is a place a secret comes to rest.
///
/// `rbx` is, and it is [below](test_the_capture_writes_down_rbx) rather than
/// here, because Rust refuses to let inline assembly name it.
///
/// # Nothing else is declared clobbered
///
/// A claim about the capture rather than an omission: each form only reads
/// registers and stores into its own room, so a call to one leaves every
/// register as it found it.
macro_rules! seeded_x86 {
    ($name:ident, $load:tt, $register:tt, $slot:expr, $wide:expr) => {
        // On the generated test rather than on the macro, so that both macros
        // exist on both architectures and the two lists at the end of this
        // file need no gate of their own. An item this strips is one whose
        // assembly is never read, which is what lets each list name registers
        // the other machine has never heard of.
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn $name() {
            alone!();

            // SAFETY: the one register written is declared, the seed is read
            // for the sixteen bytes it has, and the call is the last thing in
            // the block. The load is unaligned, so the seed needs no alignment
            // of its own.
            unsafe {
                core::arch::asm!(
                    concat!($load, " ", $register, ", [{seed}]"),
                    "call {spill}",
                    seed = in(reg) SEED.as_ptr(),
                    spill = sym crate::spiller::redoubt_spill_sse,
                    out($register) _,
                );
            }

            found_only_at($register, $slot, $wide);
        }
    };
}

/// The same, on the widest form this architecture has.
///
/// # Why this one and not only the narrow one
///
/// A slot is sixty-four bytes and the SSE form fills sixteen of them, so every
/// test above says nothing about the other forty-eight — nor about `zmm16-31`,
/// which have no slot the narrow form writes at all. Those are not an
/// afterthought: `vzeroall` reaches `ymm0-15` and stops, and compiled code
/// never writes the sixteen above them, which makes them the one place on this
/// architecture where a value is left alone indefinitely. Of everything a
/// capture could fail to write down, that is the worst.
///
/// The general registers are here too, because the wide form stores them with
/// instructions of its own and a test of the narrow form's stores says nothing
/// about them.
///
/// # A machine without it
///
/// Skips, and that is the whole of it rather than a gap: registers a machine
/// does not have are registers nothing on it has ever left anything in.
///
/// The seeding sits in an inner function so the feature can be turned on for
/// it alone. Turning it on for the test itself would let the compiler use
/// those instructions anywhere in it, including before the check that says the
/// machine has them.
macro_rules! seeded_wide_x86 {
    ($name:ident, $load:tt, $register:tt, $slot:expr, $wide:expr) => {
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn $name() {
            alone!();

            if !std::arch::is_x86_feature_detected!("avx512f") {
                eprintln!("skipped: no AVX-512 here, so there is no such register to fill.");

                return;
            }

            #[target_feature(enable = "avx512f")]
            unsafe fn put() {
                // SAFETY: the one register written is declared, the seed is
                // read for the sixty-four bytes it has, and the call is the
                // last thing in the block. The load is unaligned.
                unsafe {
                    core::arch::asm!(
                        concat!($load, " ", $register, ", [{seed}]"),
                        "call {spill}",
                        seed = in(reg) SEED.as_ptr(),
                        spill = sym crate::spiller::redoubt_spill_avx512,
                        out($register) _,
                    );
                }
            }

            // SAFETY: the feature it is compiled for was just detected.
            unsafe { put() };

            found_only_at($register, $slot, $wide);
        }
    };
}

/// The seed is in that register's slot, and in no other.
///
/// `wide` is how much of the seed the register could hold: eight bytes of it
/// for a general register, all sixteen for a vector one. Every other slot is
/// searched for that same prefix, because a slot holding it is a slot the
/// capture wrote this register into.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn found_only_at(register: &str, slot: usize, wide: usize) {
    let room = spilled();
    let want = &SEED[..wide];

    assert_eq!(
        &room[slot..slot + wide],
        want,
        "the capture did not write {register} down: its slot at {slot} holds \
         {:02x?}",
        &room[slot..slot + wide],
    );

    // Inclusive: the last window that fits begins at `room.len() - wide`, and
    // an exclusive range here would leave the end of the room unread — which
    // is where the last register's slot is.
    let elsewhere: Vec<usize> = (0..=room.len() - wide)
        .filter(|at| *at != slot && &room[*at..*at + wide] == want)
        .collect();

    assert!(
        elsewhere.is_empty(),
        "what was put in {register} is in its slot at {slot} and in {} other \
         places as well, so which register a slot holds is not what this says: \
         {elsewhere:?}",
        elsewhere.len(),
    );
}

/// The one the macro above cannot reach, reached another way.
///
/// `rbx` is where this matters most and where naming it is refused. It is
/// callee-saved and general, which is the pair of properties that makes a
/// register somewhere a secret stays: a value put there survives every call
/// made under it, and every function that wants the register for itself copies
/// that value onto a frame of its own on the way in.
///
/// Rust will not have it as an operand — LLVM keeps `rbx` for its own
/// bookkeeping — so it is saved, written, read back and put where it was, all
/// inside the one block. Nothing outside ever sees it changed, which is what
/// makes borrowing it legitimate rather than a violation dressed up.
///
/// The stack is used here, by the push and by the call both. That is already
/// true of the twenty-nine above, whose `call` says the same thing, and it is
/// why none of these blocks claims `nostack`.
///
/// # Why this one could not be left to its neighbours
///
/// Its place is eight bytes in, the second of the sixteen the capture writes.
/// A wrong offset on the second line names some other register's slot, and
/// that register writes its own slot afterwards — so the mistake is written
/// over before anything reads it, and every other test here passes. Fifteen
/// green neighbours say nothing at all about this line.
#[test]
#[cfg(target_arch = "x86_64")]
fn test_the_capture_writes_down_rbx() {
    alone!();

    // SAFETY: `rbx` is given back exactly as it was found before the block
    // ends, so nothing outside ever observes it changed; the push and the pop
    // are balanced, so the stack is given back too. The seed is read for the
    // eight bytes the register can hold.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov rbx, [{seed}]",
            "call {spill}",
            "pop rbx",
            seed = in(reg) SEED.as_ptr(),
            spill = sym crate::spiller::redoubt_spill_sse,
        );
    }

    found_only_at("rbx", 8, 8);
}

/// The same question on the other architecture, which asks it slightly
/// differently.
///
/// Three things are not as they are above. A vector register is `q5` where the
/// instruction names it and `v5` where the operand does, so both spellings are
/// passed. The call is `bl`, which writes the link register on its way, so
/// `lr` is declared clobbered — and is itself one of the registers that
/// therefore cannot be seeded, because what the capture writes down for it is
/// the address this block returns to.
///
/// # What is not here
///
/// `sp`, for the reason it is not there either. `x29`, which carries the frame
/// pointer, and `x18`, which belongs to the platform: Rust reserves both. And
/// `x30`, which the `bl` overwrites before the capture can read it — the one
/// register here excluded by the measurement rather than by the compiler.
macro_rules! seeded_arm {
    ($name:ident, $load:tt, $named:tt, $operand:tt, $slot:expr, $wide:expr) => {
        #[cfg(target_arch = "aarch64")]
        #[test]
        fn $name() {
            alone!();

            // SAFETY: the one register written is declared, as is the link
            // register the call writes; the seed is read for the sixteen bytes
            // it has, and the call is the last thing in the block.
            unsafe {
                core::arch::asm!(
                    concat!($load, " ", $named, ", [{seed}]"),
                    "bl {spill}",
                    seed = in(reg) SEED.as_ptr(),
                    spill = sym crate::spiller::redoubt_spill_neon,
                    out($operand) _,
                    out("lr") _,
                );
            }

            found_only_at($operand, $slot, $wide);
        }
    };
}

// ============================================================================
// Every register there is, on x86_64
// ============================================================================

seeded_x86!(test_the_capture_writes_down_rax, "mov", "rax", 0, 8);
seeded_x86!(test_the_capture_writes_down_rcx, "mov", "rcx", 16, 8);
seeded_x86!(test_the_capture_writes_down_rdx, "mov", "rdx", 24, 8);
seeded_x86!(test_the_capture_writes_down_rsi, "mov", "rsi", 32, 8);
seeded_x86!(test_the_capture_writes_down_rdi, "mov", "rdi", 40, 8);
seeded_x86!(test_the_capture_writes_down_r8, "mov", "r8", 64, 8);
seeded_x86!(test_the_capture_writes_down_r9, "mov", "r9", 72, 8);
seeded_x86!(test_the_capture_writes_down_r10, "mov", "r10", 80, 8);
seeded_x86!(test_the_capture_writes_down_r11, "mov", "r11", 88, 8);
seeded_x86!(test_the_capture_writes_down_r12, "mov", "r12", 96, 8);
seeded_x86!(test_the_capture_writes_down_r13, "mov", "r13", 104, 8);
seeded_x86!(test_the_capture_writes_down_r14, "mov", "r14", 112, 8);
seeded_x86!(test_the_capture_writes_down_r15, "mov", "r15", 120, 8);

seeded_x86!(test_the_capture_writes_down_xmm0, "movdqu", "xmm0", 128, 16);
seeded_x86!(test_the_capture_writes_down_xmm1, "movdqu", "xmm1", 192, 16);
seeded_x86!(test_the_capture_writes_down_xmm2, "movdqu", "xmm2", 256, 16);
seeded_x86!(test_the_capture_writes_down_xmm3, "movdqu", "xmm3", 320, 16);
seeded_x86!(test_the_capture_writes_down_xmm4, "movdqu", "xmm4", 384, 16);
seeded_x86!(test_the_capture_writes_down_xmm5, "movdqu", "xmm5", 448, 16);
seeded_x86!(test_the_capture_writes_down_xmm6, "movdqu", "xmm6", 512, 16);
seeded_x86!(test_the_capture_writes_down_xmm7, "movdqu", "xmm7", 576, 16);
seeded_x86!(test_the_capture_writes_down_xmm8, "movdqu", "xmm8", 640, 16);
seeded_x86!(test_the_capture_writes_down_xmm9, "movdqu", "xmm9", 704, 16);
seeded_x86!(
    test_the_capture_writes_down_xmm10,
    "movdqu",
    "xmm10",
    768,
    16
);
seeded_x86!(
    test_the_capture_writes_down_xmm11,
    "movdqu",
    "xmm11",
    832,
    16
);
seeded_x86!(
    test_the_capture_writes_down_xmm12,
    "movdqu",
    "xmm12",
    896,
    16
);
seeded_x86!(
    test_the_capture_writes_down_xmm13,
    "movdqu",
    "xmm13",
    960,
    16
);
seeded_x86!(
    test_the_capture_writes_down_xmm14,
    "movdqu",
    "xmm14",
    1024,
    16
);
seeded_x86!(
    test_the_capture_writes_down_xmm15,
    "movdqu",
    "xmm15",
    1088,
    16
);

// ============================================================================
// Every register there is, on x86_64 with AVX-512
// ============================================================================

seeded_wide_x86!(test_the_wide_capture_writes_down_rax, "mov", "rax", 0, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_rcx, "mov", "rcx", 16, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_rdx, "mov", "rdx", 24, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_rsi, "mov", "rsi", 32, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_rdi, "mov", "rdi", 40, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r8, "mov", "r8", 64, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r9, "mov", "r9", 72, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r10, "mov", "r10", 80, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r11, "mov", "r11", 88, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r12, "mov", "r12", 96, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r13, "mov", "r13", 104, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r14, "mov", "r14", 112, 8);
seeded_wide_x86!(test_the_wide_capture_writes_down_r15, "mov", "r15", 120, 8);

seeded_wide_x86!(
    test_the_capture_writes_down_zmm0,
    "vmovdqu64",
    "zmm0",
    128,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm1,
    "vmovdqu64",
    "zmm1",
    192,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm2,
    "vmovdqu64",
    "zmm2",
    256,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm3,
    "vmovdqu64",
    "zmm3",
    320,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm4,
    "vmovdqu64",
    "zmm4",
    384,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm5,
    "vmovdqu64",
    "zmm5",
    448,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm6,
    "vmovdqu64",
    "zmm6",
    512,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm7,
    "vmovdqu64",
    "zmm7",
    576,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm8,
    "vmovdqu64",
    "zmm8",
    640,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm9,
    "vmovdqu64",
    "zmm9",
    704,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm10,
    "vmovdqu64",
    "zmm10",
    768,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm11,
    "vmovdqu64",
    "zmm11",
    832,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm12,
    "vmovdqu64",
    "zmm12",
    896,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm13,
    "vmovdqu64",
    "zmm13",
    960,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm14,
    "vmovdqu64",
    "zmm14",
    1024,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm15,
    "vmovdqu64",
    "zmm15",
    1088,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm16,
    "vmovdqu64",
    "zmm16",
    1152,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm17,
    "vmovdqu64",
    "zmm17",
    1216,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm18,
    "vmovdqu64",
    "zmm18",
    1280,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm19,
    "vmovdqu64",
    "zmm19",
    1344,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm20,
    "vmovdqu64",
    "zmm20",
    1408,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm21,
    "vmovdqu64",
    "zmm21",
    1472,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm22,
    "vmovdqu64",
    "zmm22",
    1536,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm23,
    "vmovdqu64",
    "zmm23",
    1600,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm24,
    "vmovdqu64",
    "zmm24",
    1664,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm25,
    "vmovdqu64",
    "zmm25",
    1728,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm26,
    "vmovdqu64",
    "zmm26",
    1792,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm27,
    "vmovdqu64",
    "zmm27",
    1856,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm28,
    "vmovdqu64",
    "zmm28",
    1920,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm29,
    "vmovdqu64",
    "zmm29",
    1984,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm30,
    "vmovdqu64",
    "zmm30",
    2048,
    64
);
seeded_wide_x86!(
    test_the_capture_writes_down_zmm31,
    "vmovdqu64",
    "zmm31",
    2112,
    64
);

// ============================================================================
// Every register there is, on aarch64
// ============================================================================

seeded_arm!(test_the_capture_writes_down_x0, "ldr", "x0", "x0", 0, 8);
seeded_arm!(test_the_capture_writes_down_x1, "ldr", "x1", "x1", 8, 8);
seeded_arm!(test_the_capture_writes_down_x2, "ldr", "x2", "x2", 16, 8);
seeded_arm!(test_the_capture_writes_down_x3, "ldr", "x3", "x3", 24, 8);
seeded_arm!(test_the_capture_writes_down_x4, "ldr", "x4", "x4", 32, 8);
seeded_arm!(test_the_capture_writes_down_x5, "ldr", "x5", "x5", 40, 8);
seeded_arm!(test_the_capture_writes_down_x6, "ldr", "x6", "x6", 48, 8);
seeded_arm!(test_the_capture_writes_down_x7, "ldr", "x7", "x7", 56, 8);
seeded_arm!(test_the_capture_writes_down_x8, "ldr", "x8", "x8", 64, 8);
seeded_arm!(test_the_capture_writes_down_x9, "ldr", "x9", "x9", 72, 8);
seeded_arm!(test_the_capture_writes_down_x10, "ldr", "x10", "x10", 80, 8);
seeded_arm!(test_the_capture_writes_down_x11, "ldr", "x11", "x11", 88, 8);
seeded_arm!(test_the_capture_writes_down_x12, "ldr", "x12", "x12", 96, 8);
seeded_arm!(
    test_the_capture_writes_down_x13,
    "ldr",
    "x13",
    "x13",
    104,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x14,
    "ldr",
    "x14",
    "x14",
    112,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x15,
    "ldr",
    "x15",
    "x15",
    120,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x16,
    "ldr",
    "x16",
    "x16",
    128,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x17,
    "ldr",
    "x17",
    "x17",
    136,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x20,
    "ldr",
    "x20",
    "x20",
    160,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x21,
    "ldr",
    "x21",
    "x21",
    168,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x22,
    "ldr",
    "x22",
    "x22",
    176,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x23,
    "ldr",
    "x23",
    "x23",
    184,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x24,
    "ldr",
    "x24",
    "x24",
    192,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x25,
    "ldr",
    "x25",
    "x25",
    200,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x26,
    "ldr",
    "x26",
    "x26",
    208,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x27,
    "ldr",
    "x27",
    "x27",
    216,
    8
);
seeded_arm!(
    test_the_capture_writes_down_x28,
    "ldr",
    "x28",
    "x28",
    224,
    8
);

seeded_arm!(test_the_capture_writes_down_v0, "ldr", "q0", "v0", 256, 16);
seeded_arm!(test_the_capture_writes_down_v1, "ldr", "q1", "v1", 512, 16);
seeded_arm!(test_the_capture_writes_down_v2, "ldr", "q2", "v2", 768, 16);
seeded_arm!(test_the_capture_writes_down_v3, "ldr", "q3", "v3", 1024, 16);
seeded_arm!(test_the_capture_writes_down_v4, "ldr", "q4", "v4", 1280, 16);
seeded_arm!(test_the_capture_writes_down_v5, "ldr", "q5", "v5", 1536, 16);
seeded_arm!(test_the_capture_writes_down_v6, "ldr", "q6", "v6", 1792, 16);
seeded_arm!(test_the_capture_writes_down_v7, "ldr", "q7", "v7", 2048, 16);
seeded_arm!(test_the_capture_writes_down_v8, "ldr", "q8", "v8", 2304, 16);
seeded_arm!(test_the_capture_writes_down_v9, "ldr", "q9", "v9", 2560, 16);
seeded_arm!(
    test_the_capture_writes_down_v10,
    "ldr",
    "q10",
    "v10",
    2816,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v11,
    "ldr",
    "q11",
    "v11",
    3072,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v12,
    "ldr",
    "q12",
    "v12",
    3328,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v13,
    "ldr",
    "q13",
    "v13",
    3584,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v14,
    "ldr",
    "q14",
    "v14",
    3840,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v15,
    "ldr",
    "q15",
    "v15",
    4096,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v16,
    "ldr",
    "q16",
    "v16",
    4352,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v17,
    "ldr",
    "q17",
    "v17",
    4608,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v18,
    "ldr",
    "q18",
    "v18",
    4864,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v19,
    "ldr",
    "q19",
    "v19",
    5120,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v20,
    "ldr",
    "q20",
    "v20",
    5376,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v21,
    "ldr",
    "q21",
    "v21",
    5632,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v22,
    "ldr",
    "q22",
    "v22",
    5888,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v23,
    "ldr",
    "q23",
    "v23",
    6144,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v24,
    "ldr",
    "q24",
    "v24",
    6400,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v25,
    "ldr",
    "q25",
    "v25",
    6656,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v26,
    "ldr",
    "q26",
    "v26",
    6912,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v27,
    "ldr",
    "q27",
    "v27",
    7168,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v28,
    "ldr",
    "q28",
    "v28",
    7424,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v29,
    "ldr",
    "q29",
    "v29",
    7680,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v30,
    "ldr",
    "q30",
    "v30",
    7936,
    16
);
seeded_arm!(
    test_the_capture_writes_down_v31,
    "ldr",
    "q31",
    "v31",
    8192,
    16
);

/// The one the list above cannot reach, and the same one as on the other
/// architecture.
///
/// Each machine keeps one callee-saved general register for the compiler's own
/// bookkeeping and refuses to let inline assembly name it: `rbx` there, `x19`
/// here. That they are the same kind of register is not a coincidence — a
/// compiler wanting somewhere to keep a value across calls wants exactly what
/// a secret ends up in, and it is the one this test would least like to miss.
///
/// So, as there: saved, written, read back, and put where it was, all inside
/// the one block. Sixteen bytes come off the stack for eight, because the
/// stack pointer has to stay aligned to sixteen and giving back what was
/// borrowed matters more than the eight bytes.
#[cfg(target_arch = "aarch64")]
#[test]
fn test_the_capture_writes_down_x19() {
    alone!();

    // SAFETY: `x19` is given back exactly as it was found before the block
    // ends, so nothing outside ever observes it changed; the store and the
    // load are balanced and keep the stack aligned. The link register the
    // call writes is declared.
    unsafe {
        core::arch::asm!(
            "str x19, [sp, #-16]!",
            "ldr x19, [{seed}]",
            "bl {spill}",
            "ldr x19, [sp], #16",
            seed = in(reg) SEED.as_ptr(),
            spill = sym crate::spiller::redoubt_spill_neon,
            out("lr") _,
        );
    }

    found_only_at("x19", 152, 8);
}

// ============================================================================
// The capture, read out
// ============================================================================

/// Which slots the capture fills, and that the general ones are among them.
///
/// A capture that writes the general registers and leaves the vector ones
/// alone would look exactly like a machine whose vector registers are empty,
/// and the difference is the whole question. What is asserted is the half that
/// can be: which vector slots came back full is read out and not held to,
/// because a compiler that stopped using them would turn that into a failure
/// about nothing.
#[test]
fn test_the_capture_fills_the_general_slots() {
    alone!();

    pick_spiller();

    let mut into = vec![0_u8; ALPHA.len()];
    let source = core::hint::black_box(ALPHA.to_vec());

    copy_then_capture(&source, &mut into);

    let room = spilled();

    eprintln!();
    eprintln!("    general, in {}-byte words:", VECTORS / 16);

    for at in 0..VECTORS / 8 {
        let word = u64::from_le_bytes(room[at * 8..at * 8 + 8].try_into().unwrap());

        if word != 0 {
            eprintln!("      {at:<2}   {word:#018x}");
        }
    }

    eprintln!("    vector (one {SLOT}-byte slot each):");

    for at in 0..32 {
        let from = VECTORS + at * SLOT;
        let slot = &room[from..from + SLOT];
        let full = slot.iter().filter(|byte| **byte != 0).count();

        if full > 0 {
            eprintln!(
                "      {at:<2}   {full:>2} non-zero bytes   {:02x?}",
                &slot[..16]
            );
        }
    }

    eprintln!();

    assert!(
        filled_the_general_slots(room),
        "the capture left the general slots as it found them, so the vector \
         ones above are a reading of nothing",
    );

    core::hint::black_box((&into, &source));
}

/// Where the bytes go when the copy is wide, and how far into a register.
///
/// Each architecture has one place a secret can rest. On `x86_64` it is
/// `zmm16-31`: `vzeroall` reaches `ymm0-15` and no further, and compiled code
/// never touches the rest, so a `memcpy` dispatched to an AVX-512
/// implementation can leave a secret in one and nothing will ever write over
/// it. On `aarch64` it is not a register but a depth — `v0-v31` are the low
/// 128 bits of `z0-z31` and everything writes those, while past 128 bits only
/// SVE reaches and a compiler emits none unless asked.
///
/// So the offset matters as much as the register, and both are printed.
///
/// What is asserted is that the wide form ran and wrote: it is called by name
/// rather than through the slot, so a machine with the instructions but a form
/// that writes nowhere would otherwise read out "none" and pass.
#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn test_the_wide_capture_fills_the_general_slots() {
    alone!();

    #[cfg(target_arch = "x86_64")]
    const WIDE: &str = "zmm";

    #[cfg(target_arch = "aarch64")]
    const WIDE: &str = "z";

    #[cfg(target_arch = "x86_64")]
    {
        if !std::arch::is_x86_feature_detected!("avx512f") {
            eprintln!("    no AVX-512 on this machine, so there is no zmm16-31 to look at");

            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("sve") {
            eprintln!("    no SVE on this machine, so a z is a v and nothing more");

            return;
        }
    }

    let mut into = vec![0_u8; ALPHA.len()];
    let source = core::hint::black_box(ALPHA.to_vec());

    // SAFETY: `into` is as long as `source` and they are different
    // allocations; the capture takes no argument and writes only its own
    // room. Nothing runs between the two, and the form is called by name
    // rather than through the slot because the point is to force it.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            core::ptr::copy_nonoverlapping(source.as_ptr(), into.as_mut_ptr(), source.len());
            crate::spiller::redoubt_spill_avx512();
        }

        #[cfg(target_arch = "aarch64")]
        {
            core::ptr::copy_nonoverlapping(source.as_ptr(), into.as_mut_ptr(), source.len());
            crate::spiller::redoubt_spill_sve();
        }
    }

    let room = spilled();
    let wide = spilled_width();

    eprintln!();
    eprintln!("    {wide} bytes captured of each register; those holding some of the value:");

    let mut seen = false;

    for at in 0..32 {
        let from = VECTORS + at * SLOT;
        let slot = &room[from..from + wide.min(SLOT)];
        let full = slot.iter().filter(|byte| **byte != 0).count();

        let Some((widest, began)) = (1..=ALPHA.len()).rev().find_map(|take| {
            slot.windows(take)
                .position(|w| w == &ALPHA[..take])
                .map(|began| (take, began))
        }) else {
            continue;
        };

        seen = true;

        eprintln!(
            "      {WIDE}{at:<2}  {widest:>2} bytes of the value at offset {began:>3}, \
             {full:>3} non-zero",
        );
    }

    if !seen {
        eprintln!("      none");
    }

    eprintln!();

    assert!(
        filled_the_general_slots(room),
        "the wide form was called by name and wrote nothing anybody reads",
    );

    core::hint::black_box((&into, &source));
}

// ============================================================================
// pick_spiller
// ============================================================================

/// The form the machine gave, said out loud.
///
/// Which one it is decides what a run of this crate covered: the wide
/// registers are where a vectorised copy of a key passes, and a machine
/// without them never exercises the tests written for them. A run that
/// captured `neon` has said nothing about `sve`, and nothing else in the
/// output distinguishes "read and clean" from "never reached".
#[test]
fn test_the_capture_says_which_form_the_machine_gave() {
    pick_spiller();

    let form = picked();

    eprintln!("the capture is {form:?} on this machine.");

    assert!(
        form.is_some(),
        "the dispatch points at nothing this crate has a name for",
    );
}

// ============================================================================
// pick_spiller_from
// ============================================================================

/// The widest the machine has, of the three it may have.
///
/// Which one is what decides whether a run of this crate reached the registers
/// a vectorised copy of a key passes through. Asked of the answers rather than
/// of the machine, because a machine is one set of answers for the life of a
/// process: asked there, two of these three arms could never be read.
#[test]
#[cfg(target_arch = "x86_64")]
fn test_pick_spiller_from_takes_the_widest_the_machine_has() {
    assert_eq!(pick_spiller_from(true, true), Form::Avx512);
    assert_eq!(pick_spiller_from(true, false), Form::Avx512);
    assert_eq!(pick_spiller_from(false, true), Form::Avx);
    assert_eq!(pick_spiller_from(false, false), Form::Sse);
}

/// The same where the choice is one question wide.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_pick_spiller_from_takes_the_widest_the_machine_has() {
    assert_eq!(pick_spiller_from(true), Form::Sve);
    assert_eq!(pick_spiller_from(false), Form::Neon);
}

// ============================================================================
// use_spiller
// ============================================================================

/// Every form is reachable through the slot, and each is the one asked for.
///
/// The capture jumps through that slot using no register to get there, so a
/// form written into it wrongly is a capture that reads somebody else's
/// registers into the room — and the room is what every verdict is read from.
///
/// Put back the way it was found, because the slot is one word for the whole
/// process and the tests around this one capture through it.
#[test]
fn test_use_spiller_points_the_capture_at_the_form_it_was_given() {
    let before = picked();

    #[cfg(target_arch = "x86_64")]
    let every = [Form::Sse, Form::Avx, Form::Avx512];

    #[cfg(target_arch = "aarch64")]
    let every = [Form::Neon, Form::Sve];

    for form in every {
        use_spiller(form);

        assert_eq!(picked(), Some(form));
    }

    if let Some(form) = before {
        use_spiller(form);
    }
}

// ============================================================================
// picked
// ============================================================================

/// Nothing, where the dispatch points somewhere this crate cannot name.
///
/// The reading is what says which registers a run reached, so one that
/// answered with the nearest form would report coverage of a capture that
/// never happened.
#[test]
fn test_picked_returns_nothing_for_a_dispatch_it_cannot_name() {
    let before = picked();

    use_no_form();

    let named = picked();

    if let Some(form) = before {
        use_spiller(form);
    }

    assert_eq!(named, None);
}
