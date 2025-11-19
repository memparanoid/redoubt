// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub fn permute_with<T, F>(slice: &mut [T], mut f: F)
where
    F: FnMut(&mut [T]),
{
    fn backtrack<T, F>(i: usize, slice: &mut [T], f: &mut F)
    where
        F: FnMut(&mut [T]),
    {
        if i == slice.len() {
            f(slice);
            return;
        }

        for j in i..slice.len() {
            slice.swap(i, j);
            backtrack(i + 1, slice, f);
            slice.swap(i, j);
        }
    }

    backtrack(0, slice, &mut f);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permute_with() {
        let mut data = vec![1, 2, 3];
        let mut perms = Vec::new();

        permute_with(&mut data, |p| {
            perms.push(p.to_vec());
        });

        perms.sort();
        let expected = vec![
            vec![1, 2, 3],
            vec![1, 3, 2],
            vec![2, 1, 3],
            vec![2, 3, 1],
            vec![3, 1, 2],
            vec![3, 2, 1],
        ];
        assert_eq!(perms, expected);
    }
}
