// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! # Memlock
//!
//! Memory locking utilities for Memora framework
//! Prevents sensitive memory from being swapped to disk

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests {
    #[test]
    fn test_ptr() {
        let mut vec = vec![1u8];
        let ptr = vec.as_mut_ptr();
        println!("original ptr: {:?}", ptr);

        // Serializar a u64
        let ptr_as_u64: u64 = ptr as u64;
        println!("as u64: {}", ptr_as_u64);

        // Deserializar de vuelta
        let ptr_back: *mut u8 = ptr_as_u64 as *mut u8;
        println!("back to ptr: {:?}", ptr_back);

        // Probar que funciona
        unsafe {
            *ptr_back = 42;
        }
        assert_eq!(vec[0], 42);
        println!("funciona!");
    }
}
