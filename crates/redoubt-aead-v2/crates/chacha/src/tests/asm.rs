// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Observe the machine immediately after the assembly returns, before Rust
//! can reuse its registers or stack. These tests are not claims about kernel
//! signal frames, swap, dumps, or caller-owned input and output.

use rstest::rstest;

use super::support::{oracle, vectors};

unsafe extern "C" {
    fn redoubt_chacha_probe(call: *const usize, snapshot: *mut u64);
    fn redoubt_chacha_untouched();
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
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    include_str!("support/probe_x86_64.S"),
    probe = sym redoubt_chacha_probe,
    untouched = sym redoubt_chacha_untouched,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    include_str!("support/probe_aarch64.S"),
    probe = sym redoubt_chacha_probe,
    untouched = sym redoubt_chacha_untouched,
);

#[cfg(target_arch = "x86_64")]
const CALLER_WORDS: usize = 9;
#[cfg(target_arch = "aarch64")]
const CALLER_WORDS: usize = 18;
#[cfg(target_arch = "x86_64")]
const PRESERVED_WORDS: usize = 6;
#[cfg(target_arch = "aarch64")]
const PRESERVED_WORDS: usize = 11;
#[cfg(target_arch = "x86_64")]
const GUARD_AT: usize = 15;
#[cfg(target_arch = "aarch64")]
const GUARD_AT: usize = 31;
#[cfg(target_arch = "x86_64")]
const FRAME_AT: usize = 18;
#[cfg(target_arch = "aarch64")]
const FRAME_AT: usize = 35;
#[cfg(target_arch = "x86_64")]
const SNAPSHOT_WORDS: usize = 38;
#[cfg(target_arch = "aarch64")]
const SNAPSHOT_WORDS: usize = 47;

const POISON: u64 = 0xa5a5a5a5a5a5a5a5;

// === === === === === === === === === ===
// Test helpers
// === === === === === === === === === ===

/// Call an assembly entry point and inspect its registers and released frame.
///
/// SAFETY: call[0] must name one of the declared entry points and call[1..]
/// must satisfy that function's pointer, length and counter preconditions.
unsafe fn observe(call: [usize; 7], allocated_frame: bool) {
    let mut snapshot = [u64::MAX; SNAPSHOT_WORDS];

    // SAFETY: the caller supplies valid arguments. The probe reads exactly
    // seven words and writes the architecture's documented snapshot size.
    unsafe { redoubt_chacha_probe(call.as_ptr(), snapshot.as_mut_ptr()) };

    assert_eq!(
        &snapshot[..CALLER_WORDS],
        &[0; CALLER_WORDS],
        "caller-saved registers"
    );

    for (at, &value) in snapshot[CALLER_WORDS..CALLER_WORDS + PRESERVED_WORDS]
        .iter()
        .enumerate()
    {
        assert_eq!(value, 19 + at as u64, "callee-saved register {at}");
    }

    #[cfg(target_arch = "aarch64")]
    assert_eq!(snapshot[29], snapshot[30], "platform register x18");

    assert!(
        snapshot[GUARD_AT..FRAME_AT]
            .iter()
            .all(|&word| word == POISON),
        "frame underrun"
    );
    let expected = if allocated_frame { 0 } else { POISON };
    assert!(
        snapshot[FRAME_AT..].iter().all(|&word| word == expected),
        "released stack frame: {:?}",
        &snapshot[FRAME_AT..]
    );
}

// === === === === === === === === === ===
// redoubt_chacha_probe
// === === === === === === === === === ===

#[test]
fn test_probe_reports_the_registers_a_call_left_alone() {
    let mut snapshot = [0u64; SNAPSHOT_WORDS];

    // SAFETY: the target takes no arguments and returns at once, so every
    // slot below is a value it never reads.
    unsafe {
        redoubt_chacha_probe(
            [
                redoubt_chacha_untouched as *const () as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
            ]
            .as_ptr(),
            snapshot.as_mut_ptr(),
        );
    }

    // What every other test here asserts is that a register came back empty.
    // That is worth nothing unless an empty one can be told from a full one,
    // and this is where that is established: nothing cleared these, so none of
    // them may read as cleared.
    assert!(
        snapshot[..CALLER_WORDS].iter().all(|&word| word != 0),
        "a register nothing touched reads as empty: {:?}",
        &snapshot[..CALLER_WORDS]
    );

    assert!(
        snapshot[GUARD_AT..].iter().all(|&word| word == POISON),
        "a frame nothing touched reads as emptied"
    );
}

// === === === === === === === === === ===
// rounds
// === === === === === === === === === ===

#[test]
fn test_rounds_zeroizes_its_registers_and_frame() {
    let mut state = vectors::INITIAL;

    // SAFETY: state is sixteen initialized writable words.
    unsafe {
        observe(
            [
                redoubt_chacha_rounds as *const () as usize,
                state.as_mut_ptr() as usize,
                // Poison and not zero in the slots this one never reads: a
                // register that arrives empty proves nothing by leaving empty.
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
            ],
            cfg!(target_arch = "x86_64"),
        );
    }

    assert_eq!(state, vectors::PERMUTED);
}

// === === === === === === === === === ===
// subkey
// === === === === === === === === === ===

#[test]
fn test_subkey_zeroizes_its_registers_and_frame() {
    let key: [u8; 32] = core::array::from_fn(|at| at as u8);
    let nonce: [u8; 16] = vectors::hex(vectors::HNONCE);
    let mut out = [0xa5; 32];

    // SAFETY: disjoint arrays have the exact sizes required by HChaCha.
    unsafe {
        observe(
            [
                redoubt_hchacha_subkey as *const () as usize,
                out.as_mut_ptr() as usize,
                key.as_ptr() as usize,
                nonce.as_ptr() as usize,
                POISON as usize,
                POISON as usize,
                POISON as usize,
            ],
            cfg!(target_arch = "x86_64"),
        );
    }

    assert_eq!(out, vectors::hex::<32>(vectors::SUBKEY));
}

// === === === === === === === === === ===
// xor
// === === === === === === === === === ===

#[rstest]
#[case::ietf(12)]
#[case::bernstein(8)]
fn test_xor_zeroizes_its_registers_and_frame(#[case] nonce_len: usize) {
    let key = [0x42; 32];
    let nonce = [0x17; 12];

    for length in [0, 1, 2, 3, 4, 63, 64, 65, 127, 128, 129, 256, 257] {
        let mut data = std::vec![0xa5; length];
        let counter = if nonce_len == 8 {
            u64::from(u32::MAX)
        } else {
            7
        };
        let expected = oracle::xor(&key, &nonce[..nonce_len], counter, &data);

        // SAFETY: all slices are disjoint and long enough, the nonce layout
        // is valid, and none of these messages exhausts its counter.
        unsafe {
            observe(
                [
                    redoubt_chacha_xor as *const () as usize,
                    key.as_ptr() as usize,
                    nonce.as_ptr() as usize,
                    counter as usize,
                    data.as_mut_ptr() as usize,
                    length,
                    nonce_len,
                ],
                length != 0,
            );
        }

        assert_eq!(data, expected, "{length} bytes in");
    }
}

// === === === === === === === === === ===
// xxor
// === === === === === === === === === ===

#[test]
fn test_xxor_zeroizes_its_registers_and_frame() {
    let key = [0x42; 32];
    let nonce = [0x17; 24];

    for length in [0, 1, 2, 3, 4, 63, 64, 65, 127, 128, 129, 256, 257] {
        let mut data = std::vec![0xa5; length];
        let expected = oracle::xxor(&key, &nonce, 7, &data);

        // SAFETY: the input arrays and exclusive output have the required
        // sizes, and these lengths cannot exhaust counter seven.
        unsafe {
            observe(
                [
                    redoubt_xchacha_xor as *const () as usize,
                    key.as_ptr() as usize,
                    nonce.as_ptr() as usize,
                    7,
                    data.as_mut_ptr() as usize,
                    length,
                    POISON as usize,
                ],
                length != 0,
            );
        }

        assert_eq!(data, expected, "{length} bytes in");
    }
}
