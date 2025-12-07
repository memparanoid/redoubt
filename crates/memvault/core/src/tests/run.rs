// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

pub fn run_test_as_subprocess(test_name: &str) -> Option<i32> {
    let exe = std::env::current_exe().expect("Failed to get current exe");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .expect("Failed to run subprocess");

    if output.stdout.starts_with(b"\nrunning 0 tests") {
        return Some(-1);
    }

    output.status.code()
}

#[test]
fn test_run_test_as_subprocess_fails_if_test_does_not_exist() {
    let exit_code = run_test_as_subprocess("uknown::test");
    assert_eq!(exit_code, Some(-1), "test should have failed");
}
