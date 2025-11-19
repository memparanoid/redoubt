// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// Generates up to `count` deterministic permutations of indices `0..n-1`
/// using Lehmer / factoradic encoding. The results are reproducible and
/// independent of RNG or system state.
pub fn lehmer_decode_many(n: usize, count: usize) -> Vec<Vec<usize>> {
    let total = factorial(n);
    let limit = count.min(total);

    (0..limit).map(|i| lehmer_decode(i, n)).collect()
}

/// Decodes one permutation by its index in factoradic order.
fn lehmer_decode(mut i: usize, n: usize) -> Vec<usize> {
    let mut elems: Vec<usize> = (0..n).collect();
    let mut result = Vec::with_capacity(n as usize);

    for j in (1..=n).rev() {
        let fact = factorial(j - 1);
        let idx = i / fact;

        i %= fact;

        result.push(elems.remove(idx as usize));
    }

    result
}

/// Computes factorial of n, saturating at usize::MAX (small n expected).
const fn factorial(n: usize) -> usize {
    let mut acc: usize = 1;
    let mut k = 2;

    while k <= n {
        acc = acc.saturating_mul(k);
        k += 1;
    }

    acc
}

/// Computes the inverse of a permutation.
/// Given a permutation `perm`, returns a new vector `inv` such that:
/// `inv[perm[i]] == i` for every valid index `i`.
pub fn invert_perm(perm: &[usize]) -> Vec<usize> {
    let mut inv = vec![0; perm.len()];
    for (i, &p) in perm.iter().enumerate() {
        inv[p] = i;
    }
    inv
}

/// Applies a permutation of indices to a list of items, returning a new reordered vector.
/// Does **not** modify the original input.
pub fn apply_permutation_in_place<T: ?Sized>(data: &mut [&mut T], perm: &[usize]) {
    assert_eq!(data.len(), perm.len(), "length mismatch");
    let mut visited = vec![false; data.len()];

    for i in 0..data.len() {
        if visited[i] {
            continue;
        }

        let mut current = i;

        while !visited[current] {
            visited[current] = true;
            let next = perm[current];

            if next == i {
                break;
            }

            data.swap(current, next);
            current = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factorial() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(5), 120);
    }

    #[test]
    fn test_lehmer_decode_small() {
        let perms = lehmer_decode_many(3, 6);

        assert_eq!(perms.len(), 6);
        assert_eq!(perms[0], vec![0, 1, 2]);
        assert_eq!(perms[5], vec![2, 1, 0]);
    }

    #[test]
    fn test_lehmer_is_deterministic() {
        let p1 = lehmer_decode_many(4, 5);
        let p2 = lehmer_decode_many(4, 5);

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_apply_permutation_in_place() {
        let mut a = 10;
        let mut b = 20;
        let mut c = 30;
        let original = [a, b, c];
        let mut fields: Vec<&mut i32> = vec![&mut a, &mut b, &mut c];

        let perms = lehmer_decode_many(3, 3 * 2 * 1);

        for perm in &perms {
            let perm_a_la_menos_uno = invert_perm(perm);

            apply_permutation_in_place(&mut fields, perm);
            for (i, p) in perm.iter().enumerate() {
                assert_eq!(*fields[i], original[*p]);
            }
            apply_permutation_in_place(&mut fields, &perm_a_la_menos_uno);
        }

        assert_eq!(*fields[0], 10);
        assert_eq!(*fields[1], 20);
        assert_eq!(*fields[2], 30);
    }
}
