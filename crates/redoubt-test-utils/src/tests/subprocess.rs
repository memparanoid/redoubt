// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::process::{ExitStatus, Output};

use crate::subprocess::{
    concluded, ran, run_test_as_subprocess, run_test_as_subprocess_with, verdict,
};

// ============================================================================
// run_test_as_subprocess
// ============================================================================

#[test]
#[ignore]
fn subprocess_test_passes() {}

#[test]
#[ignore]
fn subprocess_test_exits_with_one() {
    std::process::exit(1);
}

#[test]
#[ignore]
fn subprocess_test_aborts() {
    std::process::abort();
}

#[test]
#[should_panic(expected = "did not run exactly one test")]
fn test_run_test_as_subprocess_panics_when_no_test_has_the_name() {
    run_test_as_subprocess("tests::subprocess::subprocess_test_that_does_not_exist");
}

#[test]
fn test_run_test_as_subprocess_returns_zero_for_a_test_that_passes() {
    assert_eq!(
        run_test_as_subprocess("tests::subprocess::subprocess_test_passes"),
        Some(0)
    );
}

#[test]
fn test_run_test_as_subprocess_returns_one_for_a_test_that_exits_with_one() {
    assert_eq!(
        run_test_as_subprocess("tests::subprocess::subprocess_test_exits_with_one"),
        Some(1)
    );
}

/// Unix only: elsewhere an abort is an exit code, not a signal.
#[test]
#[cfg(unix)]
fn test_run_test_as_subprocess_returns_nothing_for_a_test_a_signal_ended() {
    assert_eq!(
        run_test_as_subprocess("tests::subprocess::subprocess_test_aborts"),
        None
    );
}

// ============================================================================
// run_test_as_subprocess_with
// ============================================================================

#[test]
#[should_panic(expected = "cannot name its own binary")]
fn test_run_test_as_subprocess_with_panics_when_the_process_cannot_name_its_binary() {
    let nameless = Err(std::io::Error::from(std::io::ErrorKind::NotFound));

    run_test_as_subprocess_with(nameless, "tests::subprocess::subprocess_test_passes");
}

// ============================================================================
// concluded
// ============================================================================

#[test]
#[should_panic(expected = "did not start")]
fn test_concluded_panics_when_the_binary_did_not_start() {
    let never = Err(std::io::Error::from(std::io::ErrorKind::NotFound));

    concluded(never, "a_test");
}

#[test]
fn test_concluded_returns_the_verdict_on_a_child_that_started() {
    let started = Ok(Output {
        status: ExitStatus::default(),
        stdout: b"running 1 test\n".to_vec(),
        stderr: Vec::new(),
    });

    assert_eq!(concluded(started, "a_test"), Some(0));
}

// ============================================================================
// verdict
// ============================================================================

#[test]
#[should_panic(expected = "did not run exactly one test")]
fn test_verdict_panics_when_no_test_ran() {
    verdict("running 0 tests\n", Some(0), "a_test");
}

#[test]
#[should_panic(expected = "did not run exactly one test")]
fn test_verdict_panics_when_more_than_one_test_ran() {
    verdict("running 2 tests\n", Some(0), "a_test");
}

#[test]
fn test_verdict_returns_the_exit_code_of_the_one_test() {
    assert_eq!(verdict("running 1 test\n", Some(3), "a_test"), Some(3));
}

#[test]
fn test_verdict_returns_nothing_for_the_one_test_a_signal_ended() {
    assert_eq!(verdict("running 1 test\n", None, "a_test"), None);
}

// ============================================================================
// ran
// ============================================================================

#[test]
fn test_ran_returns_nothing_without_a_header() {
    assert_eq!(ran("error: no such file\n"), None);
}

#[test]
fn test_ran_returns_nothing_when_the_header_has_no_count() {
    assert_eq!(ran("running \n"), None);
}

#[test]
fn test_ran_returns_nothing_when_the_count_is_not_a_number() {
    assert_eq!(ran("running some tests\n"), None);
}

#[test]
fn test_ran_counts_no_test() {
    assert_eq!(ran("\nrunning 0 tests\n\ntest result: ok."), Some(0));
}

#[test]
fn test_ran_counts_one_test() {
    assert_eq!(ran("\nrunning 1 test\ntest a ... ok\n"), Some(1));
}
