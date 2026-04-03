// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! x86_64 assembly implementations for ChaCha20 and Poly1305.
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
            // Load state[a], state[b], state[c], state[d] into registers
            "mov {a:e}, [{pa}]",
            "mov {b:e}, [{pb}]",
            "mov {c:e}, [{pc}]",
            "mov {d:e}, [{pd}]",

            // a += b; d ^= a; d = rotate_left(d, 16)
            "add {a:e}, {b:e}",
            "xor {d:e}, {a:e}",
            "rol {d:e}, 16",

            // c += d; b ^= c; b = rotate_left(b, 12)
            "add {c:e}, {d:e}",
            "xor {b:e}, {c:e}",
            "rol {b:e}, 12",

            // a += b; d ^= a; d = rotate_left(d, 8)
            "add {a:e}, {b:e}",
            "xor {d:e}, {a:e}",
            "rol {d:e}, 8",

            // c += d; b ^= c; b = rotate_left(b, 7)
            "add {c:e}, {d:e}",
            "xor {b:e}, {c:e}",
            "rol {b:e}, 7",

            // Store results back
            "mov [{pa}], {a:e}",
            "mov [{pb}], {b:e}",
            "mov [{pc}], {c:e}",
            "mov [{pd}], {d:e}",

            // Zeroize registers
            "xor {a:e}, {a:e}",
            "xor {b:e}, {b:e}",
            "xor {c:e}, {c:e}",
            "xor {d:e}, {d:e}",

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
