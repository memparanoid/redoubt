// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.// Copyright (C) 2024 Mem Paranoid
// Use of this software is governed by the MIT License.
// See the LICENSE file for details.
use zeroize::Zeroize;

use super::drop_sentinel::DropSentinel;

pub trait Zeroizable {
    fn self_zeroize(&mut self);
}

pub trait ZeroizationProbe {
    fn is_zeroized(&self) -> bool;
}

pub trait AssertZeroizeOnDrop {
    fn clone_drop_sentinel(&self) -> DropSentinel;
    fn assert_zeroize_on_drop(self);
}

pub trait MutGuarded<'a, T>: Zeroizable + ZeroizationProbe + AssertZeroizeOnDrop
where
    T: Zeroize + Zeroizable + ZeroizationProbe,
{
    fn expose(&self) -> &T;
    fn expose_mut(&mut self) -> &mut T;
}
