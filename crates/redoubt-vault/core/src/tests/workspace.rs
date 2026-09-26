// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use redoubt_zero::{FastZeroizable, ZeroizationProbe, ZeroizeMetadata};

use crate::workspace::Workspace;

// ============================================================================
// Workspace::new
// ============================================================================

#[test]
fn test_new_holds_an_empty_buffer() {
    let workspace = Workspace::new();

    assert!(workspace.lock().is_empty());
}

// ============================================================================
// Workspace::lock
// ============================================================================

#[test]
fn test_lock_hands_the_same_buffer_every_time() {
    let workspace = Workspace::new();

    workspace.lock().extend_from_slice(&[1, 2, 3]);

    assert_eq!(workspace.lock().as_slice(), &[1, 2, 3]);
}

// ============================================================================
// ZeroizeMetadata for Workspace
// ============================================================================

#[test]
fn test_a_workspace_is_never_bulk_zeroized() {
    const { assert!(!Workspace::CAN_BE_BULK_ZEROIZED) };
}

// ============================================================================
// FastZeroizable for Workspace
// ============================================================================

#[test]
fn test_fast_zeroize_empties_the_buffer_it_holds() {
    let mut workspace = Workspace::new();

    workspace.lock().extend_from_slice(&[0xAA; 64]);
    workspace.fast_zeroize();

    assert!(workspace.lock().iter().all(|&byte| byte == 0));
}

// ============================================================================
// ZeroizationProbe for Workspace
// ============================================================================

#[test]
fn test_is_zeroized_answers_false_while_the_buffer_holds_bytes() {
    let workspace = Workspace::new();

    workspace.lock().extend_from_slice(&[0xAA; 64]);

    assert!(!workspace.is_zeroized());
}

#[test]
fn test_is_zeroized_answers_true_once_the_buffer_is_emptied() {
    let mut workspace = Workspace::new();

    workspace.lock().extend_from_slice(&[0xAA; 64]);
    workspace.fast_zeroize();

    assert!(workspace.is_zeroized());
}
