// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! The vectors RFC 8439 prints in appendix A.3, through every way of reaching
//! a tag.
//!
//! The expected tags are the specification's and not this crate's, so what
//! they answer is whether the code agrees with the document rather than with
//! itself.

use rstest::rstest;

use redoubt_asm::Backend;

use crate::poly1305::tag;

use crate::tests::support::{against_the_appendix, tag_of};

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_finalize_mut_returns_the_appendix_tag(#[case] backend: Backend) {
    against_the_appendix(|key, message, out| *out = tag_of(backend, key, message));
}

#[rstest]
#[case::rust(Backend::Rust)]
#[case::auto(Backend::Auto)]
fn test_tag_returns_the_appendix_tag(#[case] backend: Backend) {
    against_the_appendix(|key, message, out| tag(backend, key, message, out));
}
