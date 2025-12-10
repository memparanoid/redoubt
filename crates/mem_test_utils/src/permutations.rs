// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Permutation utilities for exhaustive testing.

/// Heap's algorithm for generating all permutations in-place.
fn heap_permute<F>(indices: &mut [usize], k: usize, callback: &mut F)
where
    F: FnMut(&[usize]),
{
    if k == 1 {
        callback(indices);
        return;
    }

    heap_permute(indices, k - 1, callback);

    for i in 0..k - 1 {
        if k % 2 == 0 {
            indices.swap(i, k - 1);
        } else {
            indices.swap(0, k - 1);
        }
        heap_permute(indices, k - 1, callback);
    }
}

/// Generates all permutations of indices [0, 1, 2, ..., len-1].
///
/// # Example
/// ```
/// use mem_test_utils::index_permutations;
///
/// let mut count = 0;
/// index_permutations(3, |_perm| {
///     count += 1;
/// });
/// assert_eq!(count, 6); // 3! = 6
/// ```
pub fn index_permutations<F>(len: usize, mut callback: F)
where
    F: FnMut(&[usize]),
{
    if len == 0 {
        return;
    }
    let mut indices: Vec<usize> = (0..len).collect();
    heap_permute(&mut indices, len, &mut callback);
}

/// Applies a permutation in-place using cycle-following swaps.
///
/// `perm[i]` indicates which element should end up at position `i`.
///
/// # Example
/// ```
/// use mem_test_utils::apply_permutation;
///
/// let mut arr = ['a', 'b', 'c', 'd'];
/// apply_permutation(&mut arr, &[3, 2, 1, 0]);
/// assert_eq!(arr, ['d', 'c', 'b', 'a']);
/// ```
pub fn apply_permutation<T>(slice: &mut [T], idx_perm: &[usize]) {
    let n = slice.len();
    debug_assert_eq!(n, idx_perm.len());

    let mut visited = [false; 32];
    assert!(n <= 32, "apply_permutation supports max 32 elements");

    for start in 0..n {
        if visited[start] {
            continue;
        }

        let mut curr = start;
        while !visited[idx_perm[curr]] {
            let next = idx_perm[curr];

            if next != curr {
                slice.swap(curr, next);
            }

            visited[curr] = true;
            curr = next;
        }

        visited[curr] = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_permutations_counts() {
        for (len, expected) in [(0, 0), (1, 1), (2, 2), (3, 6), (4, 24), (5, 120), (6, 720)] {
            let mut count = 0;
            index_permutations(len, |_| count += 1);
            assert_eq!(count, expected, "{}! should be {}", len, expected);
        }
    }

    #[test]
    fn test_apply_permutation_identity() {
        let mut arr = [0, 1, 2, 3];
        apply_permutation(&mut arr, &[0, 1, 2, 3]);
        assert_eq!(arr, [0, 1, 2, 3]);
    }

    #[test]
    fn test_apply_permutation_reverse() {
        let mut arr = ['a', 'b', 'c', 'd'];
        apply_permutation(&mut arr, &[3, 2, 1, 0]);
        assert_eq!(arr, ['d', 'c', 'b', 'a']);
    }

    #[test]
    fn test_apply_permutation_rotate() {
        let mut arr = [1, 2, 3];
        apply_permutation(&mut arr, &[2, 0, 1]);
        assert_eq!(arr, [3, 1, 2]);
    }

    #[test]
    fn test_apply_permutation_swap_pair() {
        let mut arr = [1, 2, 3, 4];
        apply_permutation(&mut arr, &[1, 0, 2, 3]);
        assert_eq!(arr, [2, 1, 3, 4]);
    }
}
