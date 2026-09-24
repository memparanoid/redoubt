// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! One of a test binary's own ignored tests, run in a process of its own.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Runs the ignored test named `test` in a process of its own, and returns its
/// exit code, or `None` when a signal ended it.
///
/// # Panics
///
/// When no test, or more than one, has that name: libtest runs nothing and
/// exits zero, which would read as the test having passed.
pub fn run_test_as_subprocess(test: &str) -> Option<i32> {
    run_test_as_subprocess_with(std::env::current_exe(), test)
}

/// [`run_test_as_subprocess`], with the binary as the process answered when
/// asked for its own path.
pub(crate) fn run_test_as_subprocess_with(
    binary: std::io::Result<PathBuf>,
    test: &str,
) -> Option<i32> {
    let binary = binary.expect("this process cannot name its own binary");

    let run = Command::new(binary)
        .args([
            "--exact",
            test,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .output();

    concluded(run, test)
}

/// What the spawn amounted to, once it is known to have started.
pub(crate) fn concluded(run: std::io::Result<Output>, test: &str) -> Option<i32> {
    let run = run.expect("the test binary did not start");

    verdict(
        &String::from_utf8_lossy(&run.stdout),
        run.status.code(),
        test,
    )
}

/// The exit code of a child that ran exactly the one test it was asked for.
pub(crate) fn verdict(stdout: &str, code: Option<i32>, test: &str) -> Option<i32> {
    assert_eq!(
        ran(stdout),
        Some(1),
        "{test} did not run exactly one test:\n{stdout}"
    );

    code
}

/// How many tests libtest announced, off its header: `running 1 test`.
///
/// The header and not the summary, which a child a signal ended never prints.
pub(crate) fn ran(stdout: &str) -> Option<usize> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("running "))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
