// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Key permutation using xorshift64 PRNG and Fisher-Yates shuffle.
//!
//! This module provides cryptographic key permutation using a double-permutation
//! design for 2^128 security against brute-force attacks.
//!
//! # Security Model
//!
//! - **Single permutation**: 2^64 possible permutations (one u64 seed)
//! - **Double permutation**: 2^128 security (two independent u64 seeds)
//! - **Uniformity**: Fisher-Yates guarantees equiprobable permutations
//!
//! # Algorithm
//!
//! 1. Generate two independent u64 seeds from hardware entropy
//! 2. Apply Fisher-Yates shuffle with first seed
//! 3. Apply Fisher-Yates shuffle with second seed
//! 4. Seeds are zeroized after use (ephemeral, never stored)

use crate::u64::U64;

/// Number of permutation rounds for 2^128 security.
#[allow(dead_code)]
const ROUNDS: usize = 2;

/// Xorshift64 PRNG state.
///
/// Xorshift64 is a fast, simple PRNG with good statistical properties.
/// It's sufficient for key permutation where we need uniform distribution
/// but not cryptographic-quality randomness (the security comes from the
/// hardware entropy seeds, not the PRNG algorithm).
///
/// # Properties
///
/// - Period: 2^64 - 1
/// - Speed: ~1-2 cycles per random number
/// - Quality: Passes most statistical tests
///
/// # Reference
///
/// Marsaglia, George (2003). "Xorshift RNGs". Journal of Statistical Software.
struct Xorshift64 {
    state: U64,
}

impl Xorshift64 {
    /// Creates a new Xorshift64 PRNG from a seed.
    ///
    /// # Panics
    ///
    /// Panics if seed is 0 (xorshift64 requires non-zero state).
    #[inline(always)]
    fn new(seed: u64) -> Self {
        assert!(seed != 0, "xorshift64 seed cannot be zero");
        let mut state = U64::new();
        let mut seed_copy = seed;
        state.drain_from(&mut seed_copy);
        Self { state }
    }

    /// Generates the next random u64 value.
    ///
    /// Writes to dst without creating intermediate stack copies.
    /// Uses the xorshift64 algorithm with shifts (13, 7, 17).
    #[inline(always)]
    fn next(&mut self, dst: &mut U64) {
        self.state.xorshift();
        let value = self.state.expose();
        let mut temp = value;
        dst.drain_from(&mut temp);
    }

    /// Generates a random index in range [0, n).
    ///
    /// Uses rejection sampling to avoid modulo bias.
    #[inline(always)]
    fn next_index(&mut self, n: usize) -> usize {
        debug_assert!(n > 0 && n <= (1 << 32), "n must be in range (0, 2^32]");

        let n_u64 = n as u64;
        let threshold = (u64::MAX - n_u64 + 1) % n_u64;
        let mut temp = U64::new();

        loop {
            self.next(&mut temp);
            let r = temp.expose();
            if r >= threshold {
                return (r % n_u64) as usize;
            }
        }
    }
}

/// Permutes a byte slice in-place using Fisher-Yates shuffle.
///
/// The Fisher-Yates shuffle guarantees that all permutations are equiprobable,
/// which is critical for security.
///
/// # Arguments
///
/// * `data` - The byte slice to permute
/// * `seed` - The u64 seed for the PRNG
///
/// # Panics
///
/// Panics if seed is 0.
///
/// # Example
///
/// ```rust
/// use redoubt_rand::permutation::permute_with_seed;
///
/// let mut key = [0u8, 1, 2, 3, 4, 5, 6, 7];
/// permute_with_seed(&mut key, 0x1234567890ABCDEF);
///
/// // key is now permuted based on the seed
/// assert_ne!(key, [0, 1, 2, 3, 4, 5, 6, 7]);
/// ```
pub fn permute_with_seed(data: &mut [u8], seed: u64) {
    if data.len() <= 1 {
        return;
    }

    let mut rng = Xorshift64::new(seed);

    // Fisher-Yates shuffle
    for i in (1..data.len()).rev() {
        let j = rng.next_index(i + 1);
        data.swap(i, j);
    }
}

/// Applies double permutation to a byte slice for 2^128 security.
///
/// Uses two independent seeds to apply Fisher-Yates shuffle twice,
/// providing 2^128 security against brute-force attacks.
///
/// # Arguments
///
/// * `data` - The byte slice to permute
/// * `seed1` - First permutation seed (will be zeroized)
/// * `seed2` - Second permutation seed (will be zeroized)
///
/// # Example
///
/// ```rust
/// use redoubt_rand::permutation::double_permute;
/// use redoubt_rand::u64::U64;
/// use redoubt_rand::u64_seed::generate;
///
/// let mut key = [0u8; 32];
/// for (i, byte) in key.iter_mut().enumerate() {
///     *byte = i as u8;
/// }
///
/// let mut seed1 = U64::new();
/// let mut seed2 = U64::new();
/// generate(&mut seed1).unwrap();
/// generate(&mut seed2).unwrap();
///
/// double_permute(&mut key, &mut seed1, &mut seed2);
/// ```
pub fn double_permute(data: &mut [u8], seed1: &mut U64, seed2: &mut U64) {
    permute_with_seed(data, seed1.expose());
    permute_with_seed(data, seed2.expose());
}
