// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

mod redoubt_array;
mod redoubt_string;
mod redoubt_vec;
mod vec;

#[cfg(test)]
mod tests {
    #[test]
    fn test_str() {
        let mut s = String::from("hello");
        unsafe {
            s.as_bytes_mut().fill(0); // Todos los bytes a 0x00
        }

        assert_eq!(s.len(), 5); // ✅ len = 5, NO 0
        assert_eq!(s.is_empty(), false); // ✅ NO está vacío
        assert_eq!(s, "\0\0\0\0\0"); // 5 NUL characters
    }
}
