// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(all(test, feature = "benchmark"))]
mod bench;

mod blankets;
mod codec_buffer;
mod collections;
mod decode_buffer;
mod error;
mod primitives;
mod support;
mod zeroizing;
