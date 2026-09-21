// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod try_split_at_mut_tests {
    use redoubt_util::try_split_at_mut;

    const REFUSED: &str = "a split inside the slice was refused";

    #[test]
    fn test_try_split_at_mut_valid() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut(&mut data, 2).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2]);
        assert_eq!(right, &[3, 4, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_out_of_bounds() {
        let mut data = [1u8, 2, 3, 4, 5];
        assert!(try_split_at_mut(&mut data, 10).is_none());
        assert!(try_split_at_mut(&mut data, 6).is_none());
    }

    #[test]
    fn test_try_split_at_mut_at_start() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut(&mut data, 0).ok_or(REFUSED)?;
        assert_eq!(left, &[]);
        assert_eq!(right, &[1, 2, 3, 4, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_at_end() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut(&mut data, 5).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2, 3, 4, 5]);
        assert_eq!(right, &[]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_empty_slice() -> Result<(), Box<dyn std::error::Error>> {
        let mut data: [u8; 0] = [];
        let (left, right) = try_split_at_mut(&mut data, 0).ok_or(REFUSED)?;
        assert_eq!(left, &[]);
        assert_eq!(right, &[]);
        assert!(try_split_at_mut(&mut data, 1).is_none());

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_mutability() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut(&mut data, 2).ok_or(REFUSED)?;

        // Modify both parts
        left[0] = 10;
        right[0] = 20;

        assert_eq!(data, [10, 2, 20, 4, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_with_different_types() -> Result<(), Box<dyn std::error::Error>> {
        let mut ints = [1u32, 2, 3, 4];
        let (left, right) = try_split_at_mut(&mut ints, 2).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2]);
        assert_eq!(right, &[3, 4]);

        Ok(())
    }
}
