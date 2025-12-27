// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Memory buffers with platform-specific protections and automatic zeroization.
//!
//! This crate provides buffer implementations that combine automatic zeroization
//! with platform-specific memory protection capabilities.
//!
//! # Buffer Types
//!
//! ## PortableBuffer
//!
//! Cross-platform buffer that works everywhere:
//! - Uses standard heap allocation
//! - Automatic zeroization on drop
//! - No platform-specific protections
//! - Available on all platforms
//!
//! ## PageBuffer (Unix only)
//!
//! Platform-specific buffer with memory protection:
//! - Uses `mmap` for allocation
//! - Optional `mlock` to prevent swapping to disk
//! - Optional `mprotect` to make pages read-only when not in use
//! - Automatic zeroization on drop
//! - Only available on Unix platforms
//!
//! # Protection Strategies
//!
//! `PageBuffer` supports two protection strategies:
//!
//! - **MemProtected**: Uses `mprotect` to make pages read-only by default.
//!   Data can only be accessed through closures that temporarily unprotect the page.
//! - **MemNonProtected**: Pages remain readable/writable. Data can be accessed
//!   directly through slices.
//!
//! # Example: PortableBuffer
//!
//! ```rust
//! use redoubt_buffer::{Buffer, PortableBuffer, BufferError};
//!
//! fn example() -> Result<(), BufferError> {
//!     let mut buffer = PortableBuffer::create(32);
//!
//!     buffer.open_mut(&mut |slice: &mut [u8]| {
//!         slice[0] = 42;
//!         Ok(())
//!     })?;
//!
//!     buffer.open(&mut |slice: &[u8]| {
//!         assert_eq!(slice[0], 42);
//!         Ok(())
//!     })?;
//!
//!     // Buffer is zeroized on drop
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! # Example: PageBuffer with Protection
//!
//! ```rust
//! #[cfg(unix)]
//! fn example() -> Result<(), redoubt_buffer::BufferError> {
//!     use redoubt_buffer::{Buffer, PageBuffer, ProtectionStrategy};
//!
//!     let mut buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 32)?;
//!
//!     // Page is protected (read-only)
//!     // Must use closures to access data
//!     buffer.open_mut(&mut |slice: &mut [u8]| {
//!         slice[0] = 42;
//!         Ok(())
//!     })?;
//!
//!     buffer.open(&mut |slice: &[u8]| {
//!         assert_eq!(slice[0], 42);
//!         Ok(())
//!     })?;
//!
//!     // Page is automatically unprotected, zeroized, and freed on drop
//!     Ok(())
//! }
//! # #[cfg(unix)]
//! # example().unwrap();
//! ```

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
mod tests;

#[cfg(unix)]
mod page_buffer;

#[cfg(unix)]
mod page;

mod error;
mod portable_buffer;
mod traits;

#[cfg(unix)]
pub use page_buffer::{PageBuffer, ProtectionStrategy};

pub use error::BufferError;
pub use portable_buffer::PortableBuffer;
pub use traits::Buffer;
