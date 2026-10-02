// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Buffer creation logic
use alloc::boxed::Box;

use redoubt_buffer::{Buffer, BufferError};
use redoubt_rand::{EntropySource, SystemEntropySource};

#[cfg(unix)]
use redoubt_buffer::PageBuffer;
#[cfg(not(unix))]
use redoubt_buffer::PortableBuffer;

use super::consts::MASTER_KEY_LEN;

#[cfg(not(unix))]
pub fn create_buffer() -> Result<Box<dyn Buffer>, BufferError> {
    Ok(Box::new(PortableBuffer::create(MASTER_KEY_LEN)))
}

#[cfg(unix)]
pub fn create_buffer() -> Result<Box<dyn Buffer>, BufferError> {
    // SECURITY: the key's page is mlocked, kept at PROT_NONE between uses, and
    // excluded from core dumps with madvise(MADV_DONTDUMP). Everything that
    // guards it is on the mapping itself, so it holds whatever the process
    // around it does.
    Ok(Box::new(PageBuffer::new(MASTER_KEY_LEN)?))
}

pub fn create_initialized_buffer() -> Result<Box<dyn Buffer>, BufferError> {
    let mut buffer = create_buffer()?;

    initialize_buffer_with(&SystemEntropySource::default(), &mut *buffer)?;

    Ok(buffer)
}

pub(crate) fn initialize_buffer_with(
    entropy: &dyn EntropySource,
    buffer: &mut dyn Buffer,
) -> Result<(), BufferError> {
    buffer.open_mut(&mut |bytes| {
        entropy
            .fill_bytes(bytes)
            .map_err(BufferError::callback_error)?;
        Ok(())
    })
}
