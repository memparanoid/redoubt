// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

fn main() {
    use memcode_derive::MemCodec;

    #[derive(MemCodec)]
    struct Lambda {
        beta: Beta, // Beta doesn't implement MemCode and MemDecode traits
    }

    struct Beta {
        field_1: Vec<u8>,
    }
}
