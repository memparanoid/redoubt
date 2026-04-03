// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! aarch64 assembly implementations for ChaCha20 and Poly1305.
//!
//! All operations are performed in registers to avoid stack copies.
//! Registers are zeroized before returning.

use core::arch::asm;

/// Perform a ChaCha20 quarter round on 4 elements of the state array.
///
/// This implementation:
/// - Loads values directly from memory into registers
/// - Performs all arithmetic in registers (no stack temporaries)
/// - Writes results back to memory
/// - Zeroizes all used registers before returning
///
/// # Arguments
/// - `state`: The 16-element ChaCha20 state array
/// - `a`, `b`, `c`, `d`: Indices into the state array (0..15)
///
/// # Preconditions
/// - Indices a, b, c, d must be in range 0..15
///
/// # Note on rotations
/// ARM uses ROR (rotate right), so rotate_left(x, n) = ror(x, 32-n)
/// - rotate_left(16) = ror(16)
/// - rotate_left(12) = ror(20)
/// - rotate_left(8)  = ror(24)
/// - rotate_left(7)  = ror(25)
#[inline(always)]
pub unsafe fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    // Get raw pointers to each element we need to operate on.
    // By passing pointers directly to asm, we bypass Rust's Copy semantics.
    unsafe {
        let pa = state.as_mut_ptr().add(a); // pointer to state[a]
        let pb = state.as_mut_ptr().add(b); // pointer to state[b]
        let pc = state.as_mut_ptr().add(c); // pointer to state[c]
        let pd = state.as_mut_ptr().add(d); // pointer to state[d]

        asm!(
            // Load state[a], state[b], state[c], state[d] into 32-bit registers
            "ldr {a:w}, [{pa}]",
            "ldr {b:w}, [{pb}]",
            "ldr {c:w}, [{pc}]",
            "ldr {d:w}, [{pd}]",

            // a += b; d ^= a; d = rotate_left(d, 16) = ror(d, 16)
            "add {a:w}, {a:w}, {b:w}",
            "eor {d:w}, {d:w}, {a:w}",
            "ror {d:w}, {d:w}, #16",

            // c += d; b ^= c; b = rotate_left(b, 12) = ror(b, 20)
            "add {c:w}, {c:w}, {d:w}",
            "eor {b:w}, {b:w}, {c:w}",
            "ror {b:w}, {b:w}, #20",

            // a += b; d ^= a; d = rotate_left(d, 8) = ror(d, 24)
            "add {a:w}, {a:w}, {b:w}",
            "eor {d:w}, {d:w}, {a:w}",
            "ror {d:w}, {d:w}, #24",

            // c += d; b ^= c; b = rotate_left(b, 7) = ror(b, 25)
            "add {c:w}, {c:w}, {d:w}",
            "eor {b:w}, {b:w}, {c:w}",
            "ror {b:w}, {b:w}, #25",

            // Store results back to memory
            "str {a:w}, [{pa}]",
            "str {b:w}, [{pb}]",
            "str {c:w}, [{pc}]",
            "str {d:w}, [{pd}]",

            // Zeroize registers before returning
            "mov {a:w}, wzr",
            "mov {b:w}, wzr",
            "mov {c:w}, wzr",
            "mov {d:w}, wzr",

            pa = in(reg) pa,
            pb = in(reg) pb,
            pc = in(reg) pc,
            pd = in(reg) pd,
            a = out(reg) _,
            b = out(reg) _,
            c = out(reg) _,
            d = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}
