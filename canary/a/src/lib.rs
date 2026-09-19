// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! A generic with branches and a `?`, covered to the last region by this
//! crate's own tests at one instantiation.
//!
//! `test-b` instantiates the same generic at another type and reaches only the
//! path that succeeds. So a report that counts instantiations separately has
//! regions here that nobody covers, and this crate stops reading 100% because
//! of tests that are not its own.
//!
//! Each type is a struct rather than the integer itself, and none of them is
//! `#[repr(transparent)]`, so that nothing collapses the instantiations into
//! one before the question is asked.

#![no_std]

#[cfg(test)]
mod tests;

/// One byte, in a type of its own.
pub struct Narrow(pub u8);

/// Four bytes, in a type of its own.
pub struct Wide(pub u32);

/// What either of them is worth.
pub trait Counted {
    /// The number it stands for.
    fn count(&self) -> u64;
}

impl Counted for Narrow {
    fn count(&self) -> u64 {
        u64::from(self.0)
    }
}

impl Counted for Wide {
    fn count(&self) -> u64 {
        u64::from(self.0)
    }
}

/// Why a count was not halved.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// Nothing to halve.
    Zero,
    /// More than the ceiling below allows.
    TooMany,
}

/// What the ceiling is, small enough that a single byte can pass it.
const CEILING: u64 = 32;

/// Half of what `value` counts.
///
/// # Errors
///
/// [`Refused::Zero`], where there is nothing to halve.
pub fn halved<T>(value: &T) -> Result<u64, Refused>
where
    T: Counted,
{
    let said = value.count();

    if said == 0 {
        return Err(Refused::Zero);
    }

    Ok(said / 2)
}

/// Half of the half, where the half is not more than the ceiling.
///
/// # Errors
///
/// [`Refused::Zero`] from `halved`, and [`Refused::TooMany`] where what it
/// answered is above [`CEILING`].
pub fn twice_halved<T>(value: &T) -> Result<u64, Refused>
where
    T: Counted,
{
    let once = halved(value)?;

    if once > CEILING {
        return Err(Refused::TooMany);
    }

    Ok(once / 2)
}
