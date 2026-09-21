// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
mod try_split_at_mut_from_end_tests {
    use redoubt_util::try_split_at_mut_from_end;

    const REFUSED: &str = "a split inside the slice was refused";

    #[test]
    fn test_try_split_at_mut_from_end_valid() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut_from_end(&mut data, 2).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2, 3]);
        assert_eq!(right, &[4, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_out_of_bounds() {
        let mut data = [1u8, 2, 3, 4, 5];
        assert!(try_split_at_mut_from_end(&mut data, 10).is_none());
        assert!(try_split_at_mut_from_end(&mut data, 6).is_none());
    }

    #[test]
    fn test_try_split_at_mut_from_end_zero_size() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut_from_end(&mut data, 0).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2, 3, 4, 5]);
        assert_eq!(right, &[]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_full_slice() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut_from_end(&mut data, 5).ok_or(REFUSED)?;
        assert_eq!(left, &[]);
        assert_eq!(right, &[1, 2, 3, 4, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_empty_slice() -> Result<(), Box<dyn std::error::Error>> {
        let mut data: [u8; 0] = [];
        let (left, right) = try_split_at_mut_from_end(&mut data, 0).ok_or(REFUSED)?;
        assert_eq!(left, &[]);
        assert_eq!(right, &[]);
        assert!(try_split_at_mut_from_end(&mut data, 1).is_none());

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_mutability() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [1u8, 2, 3, 4, 5];
        let (left, right) = try_split_at_mut_from_end(&mut data, 2).ok_or(REFUSED)?;

        // Modify both parts
        left[0] = 10;
        right[0] = 40;

        assert_eq!(data, [10, 2, 3, 40, 5]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_with_different_types()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut ints = [1u32, 2, 3, 4];
        let (left, right) = try_split_at_mut_from_end(&mut ints, 2).ok_or(REFUSED)?;
        assert_eq!(left, &[1, 2]);
        assert_eq!(right, &[3, 4]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_single_element() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = [42u8];
        let (left, right) = try_split_at_mut_from_end(&mut data, 1).ok_or(REFUSED)?;
        assert_eq!(left, &[]);
        assert_eq!(right, &[42]);

        Ok(())
    }

    #[test]
    fn test_try_split_at_mut_from_end_tag_use_case() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate ciphertext + tag scenario
        let mut buffer = [1u8, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes total
        let tag_size = 2;

        let (ciphertext, tag) = try_split_at_mut_from_end(&mut buffer, tag_size).ok_or(REFUSED)?;

        assert_eq!(ciphertext.len(), 6);
        assert_eq!(tag.len(), 2);
        assert_eq!(ciphertext, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(tag, &[7, 8]);

        Ok(())
    }
}
