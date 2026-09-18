// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What each routine in the assembly leaves behind, and whether the two
//! verifiers that answer that can see anything at all.
//!
//! The verifiers come first and are the thing under test: swept over the whole
//! of what each claims to look at — every register in the budget one at a time,
//! every byte of every frame one at a time — with a positive for each. Then the
//! writers they are swept with, captured rather than asked, because an OR cannot
//! say which element carried it. Nothing in that half calls a routine.
//!
//! The routines come after, and there the verifiers are taken as read. What is
//! measured is the routine, and only what it left: whether it digests correctly
//! is settled in `shared`, `rfc.rs` and `wycheproof.rs`, where both backends run
//! every published answer. An assertion about an answer would make every one of
//! those tests two tests.
//!
//! Four cases per routine, the three negatives first and the real one last,
//! because the negatives are what make it mean anything. Two of them leave a
//! residue of their own; the third leaves the machine exactly as it arrived,
//! which is what says the reading is about the routine and not about the call
//! site having tidied up.
//!
//! The dirtying goes first. The selected routine and both verifiers then run in
//! one assembly block, so Rust cannot insert work before the measurement. The
//! register verdict is kept in a callee-saved register while the frame is
//! scanned; that move neither changes the stack pointer nor touches the frame.
//!
//! # Why the frame verifier is a different symbol in every test
//!
//! The routines do not share a frame, so there is no one window to read. Each
//! has its own verifier, built in the assembly from that routine's own size, and
//! a test names the one that goes with the routine it calls. The sizes are
//! written down here as well, because what the sweeps walk is the window itself
//! — and a frame that changed in the assembly and not here fails at the end of
//! its own sweep.
//!
//! These are not claims about kernel signal frames, swap, dumps, or the input
//! and output the caller owns.

use rstest::rstest;

use crate::consts::{BLOCK_SIZE, HASH_SIZE};

// The assembly, in the order the file declares it: the entry points the seam
// calls, the two the file keeps to itself with a name lent to them for a
// measurement, and then the probe, which nothing in production calls.
unsafe extern "C" {
    fn redoubt_sha256_compress_block(h: *mut u32, block: *const u8);
    fn redoubt_sha256_hash(msg: *const u8, msg_len: usize, digest: *mut u8);
    fn redoubt_hmac_sha256(
        key: *const u8,
        key_len: usize,
        msg: *const u8,
        msg_len: usize,
        mac: *mut u8,
    );
    fn redoubt_hkdf_sha256(
        salt: *const u8,
        salt_len: usize,
        ikm: *const u8,
        ikm_len: usize,
        info: *const u8,
        info_len: usize,
        okm: *mut u8,
        okm_len: usize,
    );

    fn redoubt_hkdf_probe_update_finalize(
        h: *mut u32,
        msg: *const u8,
        msg_len: usize,
        total_len: usize,
        digest: *mut u8,
    );
    fn redoubt_hkdf_probe_absorb(
        h: *mut u32,
        src: *const u8,
        len: usize,
        block: *mut u8,
        fill: *mut usize,
    );

    // The probe, last and apart: what asks first, then what is asked about.
    fn redoubt_hkdf_registers_are_zeroized() -> u64;
    fn redoubt_hkdf_dirty_registers();

    fn redoubt_hkdf_frame_is_zeroized_compress_block() -> u64;
    fn redoubt_hkdf_dirty_frame_compress_block(at: usize);
    fn redoubt_hkdf_clean_frame_compress_block();

    fn redoubt_hkdf_frame_is_zeroized_hash() -> u64;
    fn redoubt_hkdf_dirty_frame_hash(at: usize);
    fn redoubt_hkdf_clean_frame_hash();

    fn redoubt_hkdf_frame_is_zeroized_update_finalize() -> u64;
    fn redoubt_hkdf_dirty_frame_update_finalize(at: usize);
    fn redoubt_hkdf_clean_frame_update_finalize();

    fn redoubt_hkdf_frame_is_zeroized_hmac() -> u64;
    fn redoubt_hkdf_dirty_frame_hmac(at: usize);
    fn redoubt_hkdf_clean_frame_hmac();

    fn redoubt_hkdf_frame_is_zeroized_absorb() -> u64;
    fn redoubt_hkdf_dirty_frame_absorb(at: usize);
    fn redoubt_hkdf_clean_frame_absorb();

    fn redoubt_hkdf_frame_is_zeroized_hkdf() -> u64;
    fn redoubt_hkdf_dirty_frame_hkdf(at: usize);
    fn redoubt_hkdf_clean_frame_hkdf();
}

/// What the register writer leaves, and what the verifier therefore has to
/// report.
const POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// The one byte the frame writer leaves, at the offset it was asked for.
///
/// Distinct from the poison above so that a byte found in a frame cannot be a
/// register's worth of pattern that reached the stack some other way.
const LEFT_BYTE: u8 = 0x5c;

/// The general registers of the budget, in the order the list at the top of the
/// assembly names them.
///
/// Both files have to say it, and only one of them can be the assembly: what
/// this one buys is that a register missing from the wipe is named when the
/// capture below fails, rather than reported as an index.
const BUDGET: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

/// Each routine's frame, as the constant beside its `sub rsp` in the assembly
/// declares it.
const FRAME_COMPRESS_BLOCK: usize = 72;
const FRAME_HASH: usize = 200;
const FRAME_UPDATE_FINALIZE: usize = 200;
const FRAME_HMAC: usize = 328;
const FRAME_ABSORB: usize = 40;
const FRAME_HKDF: usize = 376;

/// Empty every general register of the budget, in one line each.
///
/// Written out rather than looped, because a loop needs a counter and the
/// counter is one of the registers being emptied.
macro_rules! empty_the_general_registers {
    () => {
        "xor rax, rax
         xor rcx, rcx
         xor rdx, rdx
         xor rsi, rsi
         xor rdi, rdi
         xor r8, r8
         xor r9, r9
         xor r10, r10
         xor r11, r11"
    };
}

/// Empty every vector register of the budget.
macro_rules! empty_the_vector_registers {
    () => {
        "pxor xmm0, xmm0
         pxor xmm1, xmm1
         pxor xmm2, xmm2
         pxor xmm3, xmm3
         pxor xmm4, xmm4
         pxor xmm5, xmm5
         pxor xmm6, xmm6
         pxor xmm7, xmm7
         pxor xmm8, xmm8
         pxor xmm9, xmm9
         pxor xmm10, xmm10
         pxor xmm11, xmm11
         pxor xmm12, xmm12
         pxor xmm13, xmm13"
    };
}

// === === === === === === === === === ===
// redoubt_hkdf_registers_are_zeroized
// === === === === === === === === === ===

/// One test per general register: fill that one and nothing else, and ask.
///
/// Every other test here reads a verdict the verifier gives. A verdict about a
/// register it never actually looks at would be a clean bill of health for a
/// register nobody checked, and there is no way to find that out except by
/// dirtying them one at a time.
///
/// The others are emptied first, which is what makes the answer about this one.
/// Left as the compiler happened to leave them, a verdict of "dirty" would be a
/// verdict about whichever of them held something, and every one of these tests
/// would pass without the register in its own name ever being looked at.
///
/// The poison is an immediate and not an operand. Handed over in a register, the
/// compiler is free to pick one of the caller-saved ones — `lateout` says they
/// are written late, not that they are unavailable before — and the emptying
/// above would wipe it on the way past.
macro_rules! test_dirty_register_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: the callee takes no argument and returns in the return
            // register, so the only registers that matter are the ones named
            // here, and every caller-saved one is declared clobbered.
            unsafe {
                core::arch::asm!(
                    empty_the_vector_registers!(),
                    empty_the_general_registers!(),
                    concat!("mov ", $register, ", {poison}"),
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
                    lateout("rax") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty ", $register, " does not reach the answer")
            );
        }
    };
}

/// One test per vector register: fill that one and nothing else, and ask.
///
/// A vector register is dirtied for the same reason a general one is, and asks
/// the same question of the same verifier. What differs is getting the pattern
/// in: a vector register cannot be loaded from an immediate, so it goes through
/// rax, and rax is emptied again before the call — so what the verifier finds
/// can only have come from the vector.
macro_rules! test_dirty_vector_is_seen {
    ($name:ident, $register:tt) => {
        #[test]
        fn $name() {
            let dirty: u64;

            // SAFETY: as for a general register. The pattern is carried through
            // rax, which is emptied again before the call.
            unsafe {
                core::arch::asm!(
                    empty_the_vector_registers!(),
                    empty_the_general_registers!(),
                    "mov rax, {poison}",
                    concat!("movq ", $register, ", rax"),
                    concat!("punpcklqdq ", $register, ", ", $register),
                    "xor rax, rax",
                    "call {verifier}",
                    poison = const POISON,
                    verifier = sym redoubt_hkdf_registers_are_zeroized,
                    lateout("rax") dirty,
                    clobber_abi("C"),
                );
            }

            assert_eq!(
                dirty, POISON,
                concat!("a dirty ", $register, " does not reach the answer")
            );
        }
    };
}

/// The other way round, and the reason the rest mean anything.
///
/// A verifier that answered "dirty" whatever it was handed would pass every
/// test below, so one of them has to hand it a machine that is actually clean.
#[test]
fn test_an_empty_register_file_reads_as_empty() {
    let dirty: u64;

    // SAFETY: the callee takes no argument and returns in the return register.
    // Every caller-saved register is emptied here before the call and declared
    // clobbered after it.
    unsafe {
        core::arch::asm!(
            empty_the_vector_registers!(),
            empty_the_general_registers!(),
            "call {verifier}",
            verifier = sym redoubt_hkdf_registers_are_zeroized,
            lateout("rax") dirty,
            clobber_abi("C"),
        );
    }

    assert_eq!(dirty, 0, "an empty register file reads as dirty");
}

test_dirty_register_is_seen!(test_rax_is_seen, "rax");
test_dirty_register_is_seen!(test_rcx_is_seen, "rcx");
test_dirty_register_is_seen!(test_rdx_is_seen, "rdx");
test_dirty_register_is_seen!(test_rsi_is_seen, "rsi");
test_dirty_register_is_seen!(test_rdi_is_seen, "rdi");
test_dirty_register_is_seen!(test_r8_is_seen, "r8");
test_dirty_register_is_seen!(test_r9_is_seen, "r9");
test_dirty_register_is_seen!(test_r10_is_seen, "r10");
test_dirty_register_is_seen!(test_r11_is_seen, "r11");

test_dirty_vector_is_seen!(test_xmm0_is_seen, "xmm0");
test_dirty_vector_is_seen!(test_xmm1_is_seen, "xmm1");
test_dirty_vector_is_seen!(test_xmm2_is_seen, "xmm2");
test_dirty_vector_is_seen!(test_xmm3_is_seen, "xmm3");
test_dirty_vector_is_seen!(test_xmm4_is_seen, "xmm4");
test_dirty_vector_is_seen!(test_xmm5_is_seen, "xmm5");
test_dirty_vector_is_seen!(test_xmm6_is_seen, "xmm6");
test_dirty_vector_is_seen!(test_xmm7_is_seen, "xmm7");
test_dirty_vector_is_seen!(test_xmm8_is_seen, "xmm8");
test_dirty_vector_is_seen!(test_xmm9_is_seen, "xmm9");
test_dirty_vector_is_seen!(test_xmm10_is_seen, "xmm10");
test_dirty_vector_is_seen!(test_xmm11_is_seen, "xmm11");
test_dirty_vector_is_seen!(test_xmm12_is_seen, "xmm12");
test_dirty_vector_is_seen!(test_xmm13_is_seen, "xmm13");

// === === === === === === === === === ===
// redoubt_hkdf_frame_is_zeroized_*
// === === === === === === === === === ===

/// One call per byte of a routine's window, and a positive beside it.
///
/// Every test of a routine reads a verdict this verifier gives, and a verdict
/// about a byte it never looks at would be a clean bill of health for memory
/// nobody inspected. A frame's worth of calls is cheap and it is the only way to
/// know it reads all of them — an off-by-one at either end, against whatever
/// sits next door, shows up here and nowhere else.
///
/// The pair is called with nothing in between, which is the other thing being
/// measured: if anything ran there, the frame the verifier reads would not be
/// the one the writer left.
///
/// A verifier that answered "dirty" whatever it was handed would pass every one
/// of those calls, so the positive hands it a frame that was written and then
/// emptied — which is what a routine does, without the work in between.
macro_rules! test_the_frame_verifier_reads_its_whole_window {
    ($sweep:ident, $positive:ident, $size:expr, $dirty:path, $clean:path, $verify:path) => {
        #[test]
        fn $sweep() {
            for at in 0..$size {
                // SAFETY: the target writes one byte inside the frame it
                // allocated, and the verifier reads the frame the call before
                // it released.
                let dirty = unsafe {
                    $dirty(at);
                    $verify()
                };

                assert_ne!(dirty, 0, "byte {at} of the frame reads as empty");
            }
        }

        #[test]
        fn $positive() {
            // SAFETY: the target fills the frame it allocated and empties it
            // again, and the verifier reads what it released.
            let dirty = unsafe {
                $clean();
                $verify()
            };

            // Assert zeroization!
            assert_eq!(dirty, 0, "a frame that was emptied reads as full");
        }
    };
}

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_compress_block_frame_is_seen,
    test_a_compress_block_frame_written_and_emptied_reads_as_empty,
    FRAME_COMPRESS_BLOCK,
    redoubt_hkdf_dirty_frame_compress_block,
    redoubt_hkdf_clean_frame_compress_block,
    redoubt_hkdf_frame_is_zeroized_compress_block
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hash_frame_is_seen,
    test_a_hash_frame_written_and_emptied_reads_as_empty,
    FRAME_HASH,
    redoubt_hkdf_dirty_frame_hash,
    redoubt_hkdf_clean_frame_hash,
    redoubt_hkdf_frame_is_zeroized_hash
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_update_finalize_frame_is_seen,
    test_an_update_finalize_frame_written_and_emptied_reads_as_empty,
    FRAME_UPDATE_FINALIZE,
    redoubt_hkdf_dirty_frame_update_finalize,
    redoubt_hkdf_clean_frame_update_finalize,
    redoubt_hkdf_frame_is_zeroized_update_finalize
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hmac_frame_is_seen,
    test_an_hmac_frame_written_and_emptied_reads_as_empty,
    FRAME_HMAC,
    redoubt_hkdf_dirty_frame_hmac,
    redoubt_hkdf_clean_frame_hmac,
    redoubt_hkdf_frame_is_zeroized_hmac
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_absorb_frame_is_seen,
    test_an_absorb_frame_written_and_emptied_reads_as_empty,
    FRAME_ABSORB,
    redoubt_hkdf_dirty_frame_absorb,
    redoubt_hkdf_clean_frame_absorb,
    redoubt_hkdf_frame_is_zeroized_absorb
);

test_the_frame_verifier_reads_its_whole_window!(
    test_a_byte_left_anywhere_in_the_hkdf_frame_is_seen,
    test_an_hkdf_frame_written_and_emptied_reads_as_empty,
    FRAME_HKDF,
    redoubt_hkdf_dirty_frame_hkdf,
    redoubt_hkdf_clean_frame_hkdf,
    redoubt_hkdf_frame_is_zeroized_hkdf
);

// === === === === === === === === === ===
// redoubt_hkdf_dirty_registers
// === === === === === === === === === ===

/// The writer must fill every general register in the budget, not merely some.
///
/// The sweep above establishes that the verifier sees any one register. This is
/// the other half of that instrument: the negatives further down read "something
/// is still full", and a writer short by one register would let them pass while
/// never dirtying the register the routine under test failed to wipe.
///
/// Capture the registers directly rather than asking the verifier, for the same
/// reason the frame writer is captured below: an OR cannot tell which of them
/// carried the answer. They are emptied first, so an equality here can only have
/// come from the writer.
#[test]
fn test_dirty_registers_fills_every_general_register_in_the_budget() {
    let mut actual = [0_u64; BUDGET.len()];

    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills, so the destination survives the call. `actual` is as long as the
    // budget, and the stores below cover it exactly once each.
    unsafe {
        core::arch::asm!(
            empty_the_general_registers!(),
            "call {writer}",
            "mov [r12], rax",
            "mov [r12 + 8], rcx",
            "mov [r12 + 16], rdx",
            "mov [r12 + 24], rsi",
            "mov [r12 + 32], rdi",
            "mov [r12 + 40], r8",
            "mov [r12 + 48], r9",
            "mov [r12 + 56], r10",
            "mov [r12 + 64], r11",
            writer = sym redoubt_hkdf_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value, POISON,
            "{} came back from the writer empty",
            BUDGET[at]
        );
    }
}

/// The writer must fill every vector register in the budget, and all of each.
///
/// Both words of every one of them are captured. A writer that filled only the
/// low half would leave the top of each for a routine to carry something out in,
/// and a verifier that gathers the whole register would still report the half
/// that was written — so the negatives would pass with half the budget never
/// dirtied.
#[test]
fn test_dirty_registers_fills_every_vector_register_in_the_budget() {
    let mut actual = [0_u64; 28];

    // SAFETY: the callee takes no argument, and r12 is outside the budget it
    // fills. `actual` is two words for each vector register, and the stores
    // below cover it exactly once each.
    unsafe {
        core::arch::asm!(
            empty_the_vector_registers!(),
            "call {writer}",
            "movdqu [r12], xmm0",
            "movdqu [r12 + 16], xmm1",
            "movdqu [r12 + 32], xmm2",
            "movdqu [r12 + 48], xmm3",
            "movdqu [r12 + 64], xmm4",
            "movdqu [r12 + 80], xmm5",
            "movdqu [r12 + 96], xmm6",
            "movdqu [r12 + 112], xmm7",
            "movdqu [r12 + 128], xmm8",
            "movdqu [r12 + 144], xmm9",
            "movdqu [r12 + 160], xmm10",
            "movdqu [r12 + 176], xmm11",
            "movdqu [r12 + 192], xmm12",
            "movdqu [r12 + 208], xmm13",
            writer = sym redoubt_hkdf_dirty_registers,
            inlateout("r12") actual.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }

    for (at, &value) in actual.iter().enumerate() {
        assert_eq!(
            value,
            POISON,
            "word {} of xmm{} came back from the writer empty",
            at % 2,
            at / 2
        );
    }
}

// === === === === === === === === === ===
// redoubt_hkdf_dirty_frame_*
// === === === === === === === === === ===

/// The writer must leave exactly one byte, even on a previously full frame.
///
/// Capture the bytes directly rather than asking the verifier: that answer
/// cannot distinguish the requested byte from residue somewhere else. Filling,
/// calling and capturing stay in one assembly block, with every stack access
/// inside a region reserved by this caller or by the writer itself.
macro_rules! test_the_frame_writer_leaves_one_byte {
    ($name:ident, $size:expr, $writer:path) => {
        #[test]
        fn $name() {
            for at in 0..$size {
                let mut actual = [0xff_u8; $size];

                // SAFETY: at is inside the writer's frame, and actual covers
                // every captured byte. r12 holds its pointer across the call;
                // the writer preserves it. The reservation keeps call alignment
                // and includes eight bytes below the frame plus the
                // return-address slot: the writer's frame is
                // [rsp + 8, rsp + 8 + size) after reserving again.
                unsafe {
                    core::arch::asm!(
                        "sub rsp, {window}",
                        "mov rax, {poison}",
                        "xor ecx, ecx",
                        "2:",
                        "mov [rsp + rcx + 8], rax",
                        "add rcx, 8",
                        "cmp rcx, {frame}",
                        "jb 2b",
                        "add rsp, {window}",
                        "call {writer}",
                        "sub rsp, {window}",
                        "xor ecx, ecx",
                        "3:",
                        "mov al, [rsp + rcx + 8]",
                        "mov [r12 + rcx], al",
                        "mov byte ptr [rsp + rcx + 8], 0",
                        "inc rcx",
                        "cmp rcx, {frame}",
                        "jb 3b",
                        "add rsp, {window}",
                        window = const $size + 16,
                        frame = const $size,
                        poison = const POISON,
                        writer = sym $writer,
                        inlateout("rdi") at => _,
                        inlateout("r12") actual.as_mut_ptr() => _,
                        clobber_abi("C"),
                    );
                }

                for (byte, &value) in actual.iter().enumerate() {
                    assert_eq!(
                        value,
                        if byte == at { LEFT_BYTE } else { 0 },
                        "requested byte {at}, captured byte {byte}",
                    );
                }
            }
        }
    };
}

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_compress_block_clears_every_byte_except_the_requested_one,
    FRAME_COMPRESS_BLOCK,
    redoubt_hkdf_dirty_frame_compress_block
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hash_clears_every_byte_except_the_requested_one,
    FRAME_HASH,
    redoubt_hkdf_dirty_frame_hash
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_update_finalize_clears_every_byte_except_the_requested_one,
    FRAME_UPDATE_FINALIZE,
    redoubt_hkdf_dirty_frame_update_finalize
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hmac_clears_every_byte_except_the_requested_one,
    FRAME_HMAC,
    redoubt_hkdf_dirty_frame_hmac
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_absorb_clears_every_byte_except_the_requested_one,
    FRAME_ABSORB,
    redoubt_hkdf_dirty_frame_absorb
);

test_the_frame_writer_leaves_one_byte!(
    test_dirty_frame_hkdf_clears_every_byte_except_the_requested_one,
    FRAME_HKDF,
    redoubt_hkdf_dirty_frame_hkdf
);

// === === === === === === === === === ===
// What the routines leave
// === === === === === === === === === ===

/// The state SHA-256 starts from, for the routines that are handed one.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A message that runs the block loop and still leaves a remainder for the
/// padding, so the frame the verifier reads is one the routine filled rather
/// than one it barely touched.
const MESSAGE: [u8; 150] = [0x5a; 150];

/// A key past a block, so the frame has the key hashed down in it as well as
/// padded.
const KEY: [u8; 100] = [0x0b; 100];

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
    (
        $registers:ident, $frame:ident, $untouched:ident,
        $dirty_frame:path,
        ($($argument:ident: $kind:ty),* $(,)?)
    ) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $untouched($($argument: $kind),*) {
            core::arch::naked_asm!("ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $registers($($argument: $kind),*) {
            core::arch::naked_asm!(
                "jmp {target}",
                target = sym redoubt_hkdf_dirty_registers,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn $frame($($argument: $kind),*) {
            core::arch::naked_asm!(
                "xor edi, edi",
                "jmp {target}",
                target = sym $dirty_frame,
            );
        }
    };
}

/// Call the selected routine with its ABI arguments and immediately measure it.
///
/// The caller must uphold the routine's pointer and length preconditions. Both
/// verifiers preserve r12, where the first verdict waits for the second.
/// Declaring that output makes Rust preserve its caller's value.
macro_rules! measure {
    ($routine:expr, $frame_probe:path, $first:expr $(, ($register:tt, $argument:expr))* $(,)?) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            register_probe = sym redoubt_hkdf_registers_are_zeroized,
            frame_probe = sym $frame_probe,
            inlateout("r11") $routine => _,
            inlateout("rdi") $first => _,
            $(inlateout($register) $argument => _,)*
            lateout("r12") registers,
            lateout("rax") frame,
            clobber_abi("C"),
        );

        (registers, frame)
    }};
}

/// Call a routine whose last two arguments the ABI puts on the stack, and
/// immediately measure it.
///
/// The reservation holding those two is made before the call and released after
/// both verifiers, so all three run with the stack pointer the routine was
/// entered from — which is what the frame verifier measures from. Releasing it
/// in between would move the window off the frame.
///
/// The two words arrive in registers the assembly has no claim on, and are put
/// where the ABI says to look for them from inside the block: handed over any
/// other way, Rust would be free to spill them into the same stack the
/// measurement is about.
///
/// The frame is dirtied from inside the block as well, and after the
/// reservation. Dirtied before it, from Rust, the window the writer filled would
/// sit above the one the routine and the verifier work from, and a clean reading
/// would only mean the verifier was looking somewhere the writer never reached.
/// The first argument waits on the stack while that runs, because the writer
/// takes an offset in the register it arrived in. The offset itself arrives in
/// r13, which is outside the budget and outside what the writer touches.
macro_rules! measure_with_stack_arguments {
    (
        $routine:expr, $frame_probe:path, $frame_writer:path, $at:expr, $first:expr,
        $(($register:tt, $argument:expr),)*
        stack: ($seventh:expr, $eighth:expr) $(,)?
    ) => {{
        let registers: u64;
        let frame: u64;

        core::arch::asm!(
            "sub rsp, 32",
            "mov [rsp + 16], rdi",
            "mov rdi, r13",
            "call {frame_writer}",
            "mov rdi, [rsp + 16]",
            "mov [rsp], r14",
            "mov [rsp + 8], r15",
            "call r11",
            "call {register_probe}",
            "mov r12, rax",
            "call {frame_probe}",
            "add rsp, 32",
            register_probe = sym redoubt_hkdf_registers_are_zeroized,
            frame_probe = sym $frame_probe,
            frame_writer = sym $frame_writer,
            inlateout("r11") $routine => _,
            inlateout("rdi") $first => _,
            $(inlateout($register) $argument => _,)*
            inlateout("r13") $at => _,
            inlateout("r14") $seventh => _,
            inlateout("r15") $eighth => _,
            lateout("r12") registers,
            lateout("rax") frame,
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
fn assert_residue(registers: u64, frame: u64, left: Left) {
    match left {
        Left::Everything => {
            // A call that did nothing at all. What the caller dirtied before it
            // has to still be there afterwards, or a clean reading below says
            // only that something between the calls tidied up.
            assert_ne!(registers, 0, "a call that ran nothing emptied the registers");
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
            assert_eq!(frame, 0, "the frame after the real routine");
        }
    }
}

// === === === === === === === === === ===
// sha256_compress_block
// === === === === === === === === === ===

type CompressBlock = unsafe extern "C" fn(*mut u32, *const u8);

controls!(
    dirty_compress_registers,
    dirty_compress_frame,
    untouched_compress,
    redoubt_hkdf_dirty_frame_compress_block,
    (_h: *mut u32, _block: *const u8)
);

#[rstest]
#[case::registers_left_full(dirty_compress_registers as CompressBlock, Left::Registers)]
#[case::frame_left_full(dirty_compress_frame as CompressBlock, Left::Frame)]
#[case::nothing_ran(untouched_compress as CompressBlock, Left::Everything)]
#[case::real(redoubt_sha256_compress_block as CompressBlock, Left::Nothing)]
fn test_compress_block_leaves_the_residue_its_case_declares(
    #[case] routine: CompressBlock,
    #[case] left: Left,
) {
    // All cases use this indirect call site, including under release/LTO.
    // The controls exercise this caller; they do not certify other callers.
    let routine = core::hint::black_box(routine);
    let mut h = H0;
    let block = [0x42_u8; BLOCK_SIZE];

    // SAFETY: the state is eight writable words and the block is `BLOCK_SIZE`
    // readable bytes, which is what the routine reads and writes.
    let (registers, frame) = unsafe {
        redoubt_hkdf_dirty_registers();
        redoubt_hkdf_dirty_frame_compress_block(0);
        measure!(
            routine,
            redoubt_hkdf_frame_is_zeroized_compress_block,
            h.as_mut_ptr(),
            ("rsi", block.as_ptr()),
        )
    };

    assert_residue(registers, frame, left);
}

// === === === === === === === === === ===
// sha256_hash
// === === === === === === === === === ===

type Hash = unsafe extern "C" fn(*const u8, usize, *mut u8);

controls!(
    dirty_hash_registers,
    dirty_hash_frame,
    untouched_hash,
    redoubt_hkdf_dirty_frame_hash,
    (_msg: *const u8, _msg_len: usize, _digest: *mut u8)
);

#[rstest]
#[case::registers_left_full(dirty_hash_registers as Hash, Left::Registers)]
#[case::frame_left_full(dirty_hash_frame as Hash, Left::Frame)]
#[case::nothing_ran(untouched_hash as Hash, Left::Everything)]
#[case::real(redoubt_sha256_hash as Hash, Left::Nothing)]
fn test_hash_leaves_the_residue_its_case_declares(#[case] routine: Hash, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let mut digest = [0_u8; HASH_SIZE];

    // Nothing at all, inside a block, the two lengths that decide whether the
    // padding needs a second one, a whole block, and past it.
    for length in [0, 1, 55, 56, 64, 65, MESSAGE.len()] {
        // SAFETY: the message is as long as the length beside it and the
        // destination is `HASH_SIZE` writable bytes.
        let (registers, frame) = unsafe {
            redoubt_hkdf_dirty_registers();
            redoubt_hkdf_dirty_frame_hash(0);
            measure!(
                routine,
                redoubt_hkdf_frame_is_zeroized_hash,
                MESSAGE.as_ptr(),
                ("rsi", length),
                ("rdx", digest.as_mut_ptr()),
            )
        };

        assert_residue(registers, frame, left);
    }
}

// === === === === === === === === === ===
// sha256_update_finalize
// === === === === === === === === === ===

type UpdateFinalize = unsafe extern "C" fn(*mut u32, *const u8, usize, usize, *mut u8);

controls!(
    dirty_update_registers,
    dirty_update_frame,
    untouched_update,
    redoubt_hkdf_dirty_frame_update_finalize,
    (
        _h: *mut u32,
        _msg: *const u8,
        _msg_len: usize,
        _total_len: usize,
        _digest: *mut u8,
    )
);

#[rstest]
#[case::registers_left_full(dirty_update_registers as UpdateFinalize, Left::Registers)]
#[case::frame_left_full(dirty_update_frame as UpdateFinalize, Left::Frame)]
#[case::nothing_ran(untouched_update as UpdateFinalize, Left::Everything)]
#[case::real(redoubt_hkdf_probe_update_finalize as UpdateFinalize, Left::Nothing)]
fn test_update_finalize_leaves_the_residue_its_case_declares(
    #[case] routine: UpdateFinalize,
    #[case] left: Left,
) {
    let routine = core::hint::black_box(routine);
    let mut h = H0;
    let mut digest = [0_u8; HASH_SIZE];

    // SAFETY: the state is eight writable words, the message is as long as the
    // length beside it, and the destination is `HASH_SIZE` writable bytes. The
    // total is the message, because nothing was folded in before this call.
    let (registers, frame) = unsafe {
        redoubt_hkdf_dirty_registers();
        redoubt_hkdf_dirty_frame_update_finalize(0);
        measure!(
            routine,
            redoubt_hkdf_frame_is_zeroized_update_finalize,
            h.as_mut_ptr(),
            ("rsi", MESSAGE.as_ptr()),
            ("rdx", MESSAGE.len()),
            ("rcx", MESSAGE.len()),
            ("r8", digest.as_mut_ptr()),
        )
    };

    assert_residue(registers, frame, left);
}

// === === === === === === === === === ===
// sha256_absorb
// === === === === === === === === === ===

type Absorb = unsafe extern "C" fn(*mut u32, *const u8, usize, *mut u8, *mut usize);

controls!(
    dirty_absorb_registers,
    dirty_absorb_frame,
    untouched_absorb,
    redoubt_hkdf_dirty_frame_absorb,
    (
        _h: *mut u32,
        _src: *const u8,
        _len: usize,
        _block: *mut u8,
        _fill: *mut usize,
    )
);

#[rstest]
#[case::registers_left_full(dirty_absorb_registers as Absorb, Left::Registers)]
#[case::frame_left_full(dirty_absorb_frame as Absorb, Left::Frame)]
#[case::nothing_ran(untouched_absorb as Absorb, Left::Everything)]
#[case::real(redoubt_hkdf_probe_absorb as Absorb, Left::Nothing)]
fn test_absorb_leaves_the_residue_its_case_declares(#[case] routine: Absorb, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let mut h = H0;
    let mut block = [0_u8; BLOCK_SIZE];

    // Nothing to add, less than a block, exactly one, and more: the run that
    // fills the buffer is the one that reaches the compression from inside.
    for length in [0, 1, BLOCK_SIZE, MESSAGE.len()] {
        let mut fill = 0_usize;

        // SAFETY: the state is eight writable words, the source is as long as
        // the length beside it, the buffer is `BLOCK_SIZE` writable bytes, and
        // the counter is one writable word holding how much of it is used.
        let (registers, frame) = unsafe {
            redoubt_hkdf_dirty_registers();
            redoubt_hkdf_dirty_frame_absorb(0);
            measure!(
                routine,
                redoubt_hkdf_frame_is_zeroized_absorb,
                h.as_mut_ptr(),
                ("rsi", MESSAGE.as_ptr()),
                ("rdx", length),
                ("rcx", block.as_mut_ptr()),
                ("r8", &raw mut fill),
            )
        };

        assert_residue(registers, frame, left);
    }
}

// === === === === === === === === === ===
// hmac_sha256
// === === === === === === === === === ===

type Hmac = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8);

controls!(
    dirty_hmac_registers,
    dirty_hmac_frame,
    untouched_hmac,
    redoubt_hkdf_dirty_frame_hmac,
    (
        _key: *const u8,
        _key_len: usize,
        _msg: *const u8,
        _msg_len: usize,
        _mac: *mut u8,
    )
);

#[rstest]
#[case::registers_left_full(dirty_hmac_registers as Hmac, Left::Registers)]
#[case::frame_left_full(dirty_hmac_frame as Hmac, Left::Frame)]
#[case::nothing_ran(untouched_hmac as Hmac, Left::Everything)]
#[case::real(redoubt_hmac_sha256 as Hmac, Left::Nothing)]
fn test_hmac_leaves_the_residue_its_case_declares(#[case] routine: Hmac, #[case] left: Left) {
    let routine = core::hint::black_box(routine);
    let mut mac = [0_u8; HASH_SIZE];

    // A key inside a block and one past it: the long one is hashed down first,
    // which is the path that puts a digest of the key in the frame.
    for key_len in [BLOCK_SIZE, KEY.len()] {
        // SAFETY: each pointer is as long as the length beside it and the
        // destination is `HASH_SIZE` writable bytes.
        let (registers, frame) = unsafe {
            redoubt_hkdf_dirty_registers();
            redoubt_hkdf_dirty_frame_hmac(0);
            measure!(
                routine,
                redoubt_hkdf_frame_is_zeroized_hmac,
                KEY.as_ptr(),
                ("rsi", key_len),
                ("rdx", MESSAGE.as_ptr()),
                ("rcx", MESSAGE.len()),
                ("r8", mac.as_mut_ptr()),
            )
        };

        assert_residue(registers, frame, left);
    }
}

// === === === === === === === === === ===
// hkdf_sha256
// === === === === === === === === === ===

type Hkdf =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *mut u8, usize);

/// The stand-ins for the routine whose last two arguments arrive on the stack.
///
/// They are written out rather than made by `controls!`. That macro takes the
/// argument list and hands it to a tail branch, and a signature with words on
/// the stack is one the tail branch keeps correct but the macro's own
/// declaration cannot spell without repeating all of them.
#[unsafe(naked)]
unsafe extern "C" fn untouched_hkdf(
    _salt: *const u8,
    _salt_len: usize,
    _ikm: *const u8,
    _ikm_len: usize,
    _info: *const u8,
    _info_len: usize,
    _okm: *mut u8,
    _okm_len: usize,
) {
    core::arch::naked_asm!("ret");
}

#[unsafe(naked)]
unsafe extern "C" fn dirty_hkdf_registers(
    _salt: *const u8,
    _salt_len: usize,
    _ikm: *const u8,
    _ikm_len: usize,
    _info: *const u8,
    _info_len: usize,
    _okm: *mut u8,
    _okm_len: usize,
) {
    core::arch::naked_asm!(
        "jmp {target}",
        target = sym redoubt_hkdf_dirty_registers,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn dirty_hkdf_frame(
    _salt: *const u8,
    _salt_len: usize,
    _ikm: *const u8,
    _ikm_len: usize,
    _info: *const u8,
    _info_len: usize,
    _okm: *mut u8,
    _okm_len: usize,
) {
    core::arch::naked_asm!(
        "xor edi, edi",
        "jmp {target}",
        target = sym redoubt_hkdf_dirty_frame_hkdf,
    );
}

#[rstest]
#[case::registers_left_full(dirty_hkdf_registers as Hkdf, Left::Registers)]
#[case::frame_left_full(dirty_hkdf_frame as Hkdf, Left::Frame)]
#[case::nothing_ran(untouched_hkdf as Hkdf, Left::Everything)]
#[case::real(redoubt_hkdf_sha256 as Hkdf, Left::Nothing)]
fn test_hkdf_leaves_the_residue_its_case_declares(#[case] routine: Hkdf, #[case] left: Left) {
    let routine = core::hint::black_box(routine);

    // Inside one block of output, exactly one, and past it: more than one block
    // is the only path that puts a previous T in the frame.
    for wanted in [1, HASH_SIZE, 100] {
        let mut okm = [0_u8; 100];

        // SAFETY: each pointer is as long as the length beside it, the
        // destination has room for the length asked for, and that length is
        // inside what the counter has blocks for.
        let (registers, frame) = unsafe {
            redoubt_hkdf_dirty_registers();
            measure_with_stack_arguments!(
                routine,
                redoubt_hkdf_frame_is_zeroized_hkdf,
                redoubt_hkdf_dirty_frame_hkdf,
                0_usize,
                KEY.as_ptr(),
                ("rsi", KEY.len()),
                ("rdx", MESSAGE.as_ptr()),
                ("rcx", MESSAGE.len()),
                ("r8", KEY.as_ptr()),
                ("r9", KEY.len()),
                stack: (okm.as_mut_ptr(), wanted),
            )
        };

        assert_residue(registers, frame, left);
    }
}

// === === === === === === === === === ===
// What the measurement reads
// === === === === === === === === === ===
//
// The window each measurement dirties has to be the window its verifier reads.
//
// The sweep over `dirty_frame` calls the writer and the verifier one after the
// other with nothing between them, so it cannot see a call site that moved the
// stack pointer between the two. These go through the measurement instead, and
// against the stand-in that does nothing at all — so what the verifier reports
// is the byte the writer left, at every offset it could be left at.
//
// A reservation a measurement forgot to account for shows up at whichever end
// the window slid off, and nowhere else. The byte at offset zero survives a
// slide in either direction, and offset zero is the only one the cases above ask
// about.
//
// One per routine, because each measurement is its own call site and they do
// not all reserve the same thing.
//
// The answer is asserted exactly and not merely as "something was found". The
// verifier ORs the window a word at a time, so one byte left in it comes back as
// that byte and nothing else — and a window that slid reads bytes nobody wrote,
// which come back as whatever was there. "Something was found" would take that
// for the byte.

/// What the verifier answers when the only thing left in the window is the byte
/// the writer put at `at`.
///
/// The gather is a word at a time, so the byte lands wherever it sits inside its
/// own word, and every other word contributes nothing.
fn only_the_byte_at(at: usize) -> u64 {
    u64::from(LEFT_BYTE) << (8 * (at % 8))
}

/// No offset expects an empty window.
///
/// Every sweep below asserts what this returns, and cannot check it: the only
/// other thing that knows where the byte lands is the verifier, which is what
/// those sweeps are asking about. So what is asked here is the one property that
/// would make the sweeps lie rather than fail — an expected answer of zero turns
/// "the verifier found the byte" into "the verifier found nothing", and that
/// reads as a pass at exactly the offset the byte went missing.
///
/// A shift wide enough to push the byte out of the word is how it would happen,
/// and the widest frame is where there is most room to get the modulus wrong.
#[test]
fn test_no_offset_expects_an_empty_window() {
    for at in 0..FRAME_HKDF {
        assert_ne!(only_the_byte_at(at), 0, "offset {at}");
    }
}

#[test]
fn test_the_measurement_of_compress_block_reads_the_window_the_writer_filled() {
    let mut h = H0;
    let block = [0x42_u8; BLOCK_SIZE];

    for at in 0..FRAME_COMPRESS_BLOCK {
        // SAFETY: at is inside the writer's frame, and the stand-in never
        // dereferences what it is handed.
        let (_, frame) = unsafe {
            redoubt_hkdf_dirty_frame_compress_block(at);
            measure!(
                untouched_compress as CompressBlock,
                redoubt_hkdf_frame_is_zeroized_compress_block,
                h.as_mut_ptr(),
                ("rsi", block.as_ptr()),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_hash_reads_the_window_the_writer_filled() {
    let mut digest = [0_u8; HASH_SIZE];

    for at in 0..FRAME_HASH {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_hkdf_dirty_frame_hash(at);
            measure!(
                untouched_hash as Hash,
                redoubt_hkdf_frame_is_zeroized_hash,
                MESSAGE.as_ptr(),
                ("rsi", MESSAGE.len()),
                ("rdx", digest.as_mut_ptr()),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_update_finalize_reads_the_window_the_writer_filled() {
    let mut h = H0;
    let mut digest = [0_u8; HASH_SIZE];

    for at in 0..FRAME_UPDATE_FINALIZE {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_hkdf_dirty_frame_update_finalize(at);
            measure!(
                untouched_update as UpdateFinalize,
                redoubt_hkdf_frame_is_zeroized_update_finalize,
                h.as_mut_ptr(),
                ("rsi", MESSAGE.as_ptr()),
                ("rdx", MESSAGE.len()),
                ("rcx", MESSAGE.len()),
                ("r8", digest.as_mut_ptr()),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_absorb_reads_the_window_the_writer_filled() {
    let mut h = H0;
    let mut block = [0_u8; BLOCK_SIZE];
    let mut fill = 0_usize;

    for at in 0..FRAME_ABSORB {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_hkdf_dirty_frame_absorb(at);
            measure!(
                untouched_absorb as Absorb,
                redoubt_hkdf_frame_is_zeroized_absorb,
                h.as_mut_ptr(),
                ("rsi", MESSAGE.as_ptr()),
                ("rdx", MESSAGE.len()),
                ("rcx", block.as_mut_ptr()),
                ("r8", &raw mut fill),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_hmac_reads_the_window_the_writer_filled() {
    let mut mac = [0_u8; HASH_SIZE];

    for at in 0..FRAME_HMAC {
        // SAFETY: as above.
        let (_, frame) = unsafe {
            redoubt_hkdf_dirty_frame_hmac(at);
            measure!(
                untouched_hmac as Hmac,
                redoubt_hkdf_frame_is_zeroized_hmac,
                KEY.as_ptr(),
                ("rsi", KEY.len()),
                ("rdx", MESSAGE.as_ptr()),
                ("rcx", MESSAGE.len()),
                ("r8", mac.as_mut_ptr()),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}

#[test]
fn test_the_measurement_of_hkdf_reads_the_window_the_writer_filled() {
    let mut okm = [0_u8; 100];

    for at in 0..FRAME_HKDF {
        // SAFETY: as above. This measurement dirties from inside its own
        // reservation, so the offset goes in rather than the writer being
        // called first.
        let (_, frame) = unsafe {
            measure_with_stack_arguments!(
                untouched_hkdf as Hkdf,
                redoubt_hkdf_frame_is_zeroized_hkdf,
                redoubt_hkdf_dirty_frame_hkdf,
                at,
                KEY.as_ptr(),
                ("rsi", KEY.len()),
                ("rdx", MESSAGE.as_ptr()),
                ("rcx", MESSAGE.len()),
                ("r8", KEY.as_ptr()),
                ("r9", KEY.len()),
                stack: (okm.as_mut_ptr(), okm.len()),
            )
        };

        assert_eq!(
            frame,
            only_the_byte_at(at),
            "byte {at} of the frame does not reach the answer"
        );
    }
}
