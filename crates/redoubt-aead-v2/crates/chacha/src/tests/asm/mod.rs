// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine leaves behind, asked of the two verifiers in `probes`.
//!
//! Their own tests live there; here they are used and not measured. What is
//! measured here is the routine, and only what it left: whether it enciphers
//! correctly is settled in `chacha20.rs`, `xchacha20.rs`, `hchacha20.rs` and
//! `backend.rs`, where both backends run the vectors and the oracle. An
//! assertion about an answer would make every test below two tests.
//!
//! Four cases per routine, the three negatives first and the real one last,
//! because the negatives are what make it mean anything. Two of them leave a
//! residue of their own; the third leaves the machine exactly as it arrived,
//! which is what says the reading is about the routine and not about the call
//! site having tidied up.
//!
//! The dirtying goes first. The selected routine and both verifiers then run
//! in one assembly block, so Rust cannot insert work before the measurement.
//! The register verdict is kept in a callee-saved register while the frame is
//! scanned; that move neither changes the stack pointer nor touches the frame.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

mod probes;

use rstest::rstest;

// The assembly, in the order the file declares it: the four entry points the
// backend calls, then the probe, which nothing in production calls.
unsafe extern "C" {
    fn redoubt_chacha_rounds(state: *mut u32);
    fn redoubt_hchacha_subkey(out: *mut u8, key: *const u8, nonce: *const u8);
    fn redoubt_chacha_xor(
        key: *const u8,
        nonce: *const u8,
        counter: u64,
        data: *mut u8,
        len: usize,
        nonce_len: usize,
    );
    fn redoubt_xchacha_xor(
        key: *const u8,
        nonce: *const u8,
        counter: u64,
        data: *mut u8,
        len: usize,
    );

    // The probe, last and apart: what asks first, then what is asked about.
    fn redoubt_chacha_registers_are_zeroized() -> u64;
    fn redoubt_chacha_frame_is_zeroized() -> u64;
    fn redoubt_chacha_dirty_registers();
    fn redoubt_chacha_dirty_frame(at: usize);
    fn redoubt_chacha_clean_frame();
}

/// Whether the two round-only routines spill at all, which the architectures
/// answer differently: x86-64 keeps four working words in registers and the
/// rest in a frame, aarch64 keeps all sixteen in w2-w17 and takes none.
const ROUNDS_TAKE_A_FRAME: bool = cfg!(target_arch = "x86_64");

/// Three stand-ins for the routine, with its arguments and none of its work.
///
/// The tail branch keeps the caller's stack pointer and return address. A
/// regular Rust wrapper could take another frame or change the registers on
/// return, making the residue belong to the wrapper instead of the helper.
///
/// The first two leave a residue of their own, which is what says the verifier
/// sees one across this call site. The third leaves none and does nothing at
/// all: it is the only one that measures the gap, because the other two dirty
/// the machine again from inside the call. What it answers is whether the
/// *caller's* dirtying survives to the verifier — without it, the real routine
/// reading clean could be the call site having cleaned rather than the routine.
///
/// Only the frame stand-in replaces the first argument with byte offset zero.
/// These functions never dereference their pointer arguments.
macro_rules! controls {
    ($registers:ident, $frame:ident, $untouched:ident, ($($argument:ident: $kind:ty),* $(,)?)) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($($argument: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($($argument: $kind),*) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "jmp {target}",
                target = sym redoubt_chacha_dirty_registers,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "b {target}",
                target = sym redoubt_chacha_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $frame($($argument: $kind),*) {
            #[cfg(target_arch = "x86_64")]
            core::arch::naked_asm!(
                "xor edi, edi",
                "jmp {target}",
                target = sym redoubt_chacha_dirty_frame,
            );

            #[cfg(target_arch = "aarch64")]
            core::arch::naked_asm!(
                "mov x0, xzr",
                "b {target}",
                target = sym redoubt_chacha_dirty_frame,
            );
        }
    };
}

/// Call the selected routine with its ABI arguments and immediately measure it.
///
/// The caller must uphold the routine's pointer and length preconditions.
/// Both verifiers preserve r12/x20, where the first verdict waits for the
/// second. Declaring that output makes Rust preserve its caller's value.
macro_rules! measure {
    ($routine:expr, $first:expr $(, ($x86:tt, $arm:tt, $argument:expr))* $(,)?) => {{
        let registers: u64;
        let frame: u64;

        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            register_probe = sym redoubt_chacha_registers_are_zeroized,
            frame_probe = sym redoubt_chacha_frame_is_zeroized,
            inlateout("r11") $routine => _,
            inlateout("rdi") $first => _,
            $(inlateout($x86) $argument => _,)*
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "blr x16",
            "bl {register_probe}",
            "mov x20, x0",
            "bl {frame_probe}",
            register_probe = sym redoubt_chacha_registers_are_zeroized,
            frame_probe = sym redoubt_chacha_frame_is_zeroized,
            inlateout("x16") $routine => _,
            inlateout("x0") $first => frame,
            $(inlateout($arm) $argument => _,)*
            lateout("x20") registers,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// Which residue the case deliberately leaves, or neither for the real call.
#[derive(Clone, Copy)]
enum Left {
    Registers,
    Frame,
    Everything,
    Nothing,
}

/// Each negative asks only about the residue it deliberately leaves.
fn assert_residue(registers: u64, frame: u64, left: Left, takes_frame: bool) {
    match left {
        Left::Everything => {
            // A call that did nothing at all. What the caller dirtied before it
            // has to still be there afterwards, or a clean reading below says
            // only that something between the calls tidied up.
            assert_ne!(
                registers, 0,
                "a call that ran nothing emptied the registers"
            );
            assert_ne!(frame, 0, "a call that ran nothing emptied the frame");
        }
        Left::Registers => {
            assert_ne!(
                registers, 0,
                "registers the replacement left full read as empty"
            );
        }
        Left::Frame => {
            assert_ne!(
                frame, 0,
                "the frame the replacement left full reads as empty"
            );
        }
        Left::Nothing => {
            // Assert zeroization!
            assert_eq!(registers, 0, "the registers after the real routine");

            if takes_frame {
                assert_eq!(frame, 0, "the frame after the real routine");
            } else {
                assert_ne!(frame, 0, "a routine that takes no frame emptied one");
            }
        }
    }
}

// === === === === === === === === === ===
// rounds
// === === === === === === === === === ===

type Rounds = unsafe extern "C" fn(*mut u32);

controls!(
    dirty_rounds_registers,
    dirty_rounds_frame,
    untouched_rounds,
    (_state: *mut u32)
);

#[rstest]
#[case::registers_left_full(dirty_rounds_registers as Rounds, Left::Registers)]
#[case::frame_left_full(dirty_rounds_frame as Rounds, Left::Frame)]
#[case::nothing_ran(untouched_rounds as Rounds, Left::Everything)]
#[case::real(redoubt_chacha_rounds as Rounds, Left::Nothing)]
fn test_rounds_leaves_the_residue_its_case_declares(#[case] routine: Rounds, #[case] left: Left) {
    // All cases use this indirect call site, including under release/LTO.
    // The controls exercise this caller; they do not certify other callers.
    let routine = core::hint::black_box(routine);
    let mut state = [0x5a5a_5a5au32; 16];

    // SAFETY: state is sixteen initialized writable words.
    let (registers, frame) = unsafe {
        redoubt_chacha_dirty_registers();
        redoubt_chacha_dirty_frame(0);
        measure!(routine, state.as_mut_ptr())
    };

    assert_residue(registers, frame, left, ROUNDS_TAKE_A_FRAME);
}

// === === === === === === === === === ===
// subkey
// === === === === === === === === === ===

type Subkey = unsafe extern "C" fn(*mut u8, *const u8, *const u8);

controls!(
    dirty_subkey_registers,
    dirty_subkey_frame,
    untouched_subkey,
    (_out: *mut u8, _key: *const u8, _nonce: *const u8)
);

#[rstest]
#[case::registers_left_full(dirty_subkey_registers as Subkey, Left::Registers)]
#[case::frame_left_full(dirty_subkey_frame as Subkey, Left::Frame)]
#[case::nothing_ran(untouched_subkey as Subkey, Left::Everything)]
#[case::real(redoubt_hchacha_subkey as Subkey, Left::Nothing)]
fn test_subkey_leaves_the_residue_its_case_declares(#[case] routine: Subkey, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let key: [u8; 32] = core::array::from_fn(|at| at as u8);
    let nonce = [0x17u8; 16];
    let mut out = [0u8; 32];

    // SAFETY: the three arrays are disjoint and have the exact sizes HChaCha
    // reads and writes.
    let (registers, frame) = unsafe {
        redoubt_chacha_dirty_registers();
        redoubt_chacha_dirty_frame(0);
        measure!(
            routine,
            out.as_mut_ptr(),
            ("rsi", "x1", key.as_ptr()),
            ("rdx", "x2", nonce.as_ptr()),
        )
    };

    assert_residue(registers, frame, left, ROUNDS_TAKE_A_FRAME);
}

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

type Xor = unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8, usize, usize);

controls!(
    dirty_xor_registers,
    dirty_xor_frame,
    untouched_xor,
    (
        _key: *const u8, _nonce: *const u8, _counter: u64,
        _data: *mut u8, _len: usize, _nonce_len: usize,
    )
);

#[rstest]
#[case::registers_left_full(dirty_xor_registers as Xor, Left::Registers)]
#[case::frame_left_full(dirty_xor_frame as Xor, Left::Frame)]
#[case::nothing_ran(untouched_xor as Xor, Left::Everything)]
#[case::real(redoubt_chacha_xor as Xor, Left::Nothing)]
fn test_xor_leaves_the_residue_its_case_declares(
    #[case] routine: Xor,
    #[case] left: Left,
    #[values(8, 12)] nonce_len: usize,
) {
    let routine = core::hint::black_box(routine);
    let key = [0x42u8; 32];
    let nonce = [0x17u8; 12];

    // Nothing at all, a partial block, exact blocks, and several of them: the
    // empty one takes no frame, and the partial tail is the one path that
    // leaves the stream loop from inside a block.
    for length in [0, 1, 63, 64, 65, 128, 129] {
        let mut data = std::vec![0xa5u8; length];

        // SAFETY: every pointer is to storage of the width the routine reads
        // or writes, the nonce is as long as the length beside it, and counter
        // seven exhausts nothing at these lengths.
        let (registers, frame) = unsafe {
            redoubt_chacha_dirty_registers();
            redoubt_chacha_dirty_frame(0);
            measure!(
                routine,
                key.as_ptr(),
                ("rsi", "x1", nonce.as_ptr()),
                ("rdx", "x2", 7u64),
                ("rcx", "x3", data.as_mut_ptr()),
                ("r8", "x4", length),
                ("r9", "x5", nonce_len),
            )
        };

        assert_residue(registers, frame, left, length != 0);
    }
}

// === === === === === === === === === ===
// xxor
// === === === === === === === === === ===

type Xxor = unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8, usize);

controls!(
    dirty_xxor_registers,
    dirty_xxor_frame,
    untouched_xxor,
    (
        _key: *const u8, _nonce: *const u8, _counter: u64,
        _data: *mut u8, _len: usize,
    )
);

#[rstest]
#[case::registers_left_full(dirty_xxor_registers as Xxor, Left::Registers)]
#[case::frame_left_full(dirty_xxor_frame as Xxor, Left::Frame)]
#[case::nothing_ran(untouched_xxor as Xxor, Left::Everything)]
#[case::real(redoubt_xchacha_xor as Xxor, Left::Nothing)]
fn test_xxor_leaves_the_residue_its_case_declares(#[case] routine: Xxor, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let key = [0x42u8; 32];
    let nonce = [0x17u8; 24];

    for length in [0, 1, 63, 64, 65, 128, 129] {
        let mut data = std::vec![0xa5u8; length];

        // SAFETY: the input arrays and exclusive output have the required
        // sizes, and these lengths cannot exhaust counter seven.
        let (registers, frame) = unsafe {
            redoubt_chacha_dirty_registers();
            redoubt_chacha_dirty_frame(0);
            measure!(
                routine,
                key.as_ptr(),
                ("rsi", "x1", nonce.as_ptr()),
                ("rdx", "x2", 7u64),
                ("rcx", "x3", data.as_mut_ptr()),
                ("r8", "x4", length),
            )
        };

        assert_residue(registers, frame, left, length != 0);
    }
}
