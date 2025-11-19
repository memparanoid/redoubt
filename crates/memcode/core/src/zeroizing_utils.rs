// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::sync::atomic::{Ordering, compiler_fence};

use zeroize::Zeroize;

#[inline(never)]
pub(crate) fn zeroize_mut_slice<T: Zeroize>(tmp: &mut [T]) {
    compiler_fence(Ordering::SeqCst);
    for t in tmp.iter_mut() {
        t.zeroize();
    }
    compiler_fence(Ordering::SeqCst);
}
