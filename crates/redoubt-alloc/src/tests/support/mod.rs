// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[global_allocator]
static ALLOCATOR: redoubt_forensics::ForensicsAllocator<std::alloc::System> =
    redoubt_forensics::ForensicsAllocator::new(std::alloc::System);
