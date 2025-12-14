// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for redoubt_guard

#[cfg(target_os = "linux")]
mod linux {
    use serial_test::serial;

    fn reset_state() {
        use core::sync::atomic::Ordering;
        crate::INIT_STATE.store(crate::STATE_UNINIT, Ordering::SeqCst);
        crate::PRCTL_SUCCEEDED.store(0, Ordering::SeqCst);
    }

    /// Runs an ignored test as a subprocess and returns its exit code.
    fn run_test_as_subprocess(test_name: &str) -> Option<i32> {
        let exe = std::env::current_exe().expect("Failed to get current exe");
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                test_name,
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .status()
            .expect("Failed to run subprocess");
        status.code()
    }

    #[test]
    fn test_is_guarded_is_idempotent() {
        // Multiple calls should not panic or deadlock
        let _ = crate::is_guarded();
        let _ = crate::is_guarded();
        let _ = crate::is_guarded();
    }

    // Subprocess test: prctl blocked by seccomp
    #[test]
    #[ignore]
    fn subprocess_test_prctl_blocked_returns_false() {
        use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

        // Block prctl syscall
        let mut filter =
            ScmpFilterContext::new(ScmpAction::Allow).expect("Failed to create filter");
        filter
            .add_rule(
                ScmpAction::Errno(libc::EPERM),
                ScmpSyscall::from_name("prctl").expect("Failed to from_name(..)"),
            )
            .expect("Failed to add rule");
        filter.load().expect("Failed to load filter");

        reset_state();

        assert!(!crate::is_guarded(), "prctl should have failed");

        std::process::exit(0);
    }

    #[test]
    #[serial(seccomp)]
    fn test_prctl_blocked_returns_false() {
        let exit_code =
            run_test_as_subprocess("tests::linux::subprocess_test_prctl_blocked_returns_false");
        assert_eq!(exit_code, Some(0), "Subprocess should exit with 0");
    }

    // Subprocess test: prctl succeeds
    #[test]
    #[ignore]
    fn subprocess_test_prctl_succeeds() {
        reset_state();

        assert!(crate::is_guarded(), "prctl should have succeeded");

        std::process::exit(0);
    }

    #[test]
    #[serial(seccomp)]
    fn test_prctl_succeeds() {
        let exit_code = run_test_as_subprocess("tests::linux::subprocess_test_prctl_succeeds");
        assert_eq!(exit_code, Some(0), "Subprocess should exit with 0");
    }

    // Subprocess test: concurrent access
    #[test]
    #[ignore]
    fn subprocess_test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        reset_state();

        let barrier = Arc::new(std::sync::Barrier::new(100));
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    crate::is_guarded()
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().expect("Failed to join()")).collect();

        // All threads should get the same result (true on Linux)
        assert!(results.iter().all(|&r| r == results[0]));
        assert!(results[0], "prctl should have succeeded");

        std::process::exit(0);
    }

    #[test]
    #[serial(seccomp)]
    fn test_concurrent_access() {
        let exit_code = run_test_as_subprocess("tests::linux::subprocess_test_concurrent_access");
        assert_eq!(exit_code, Some(0), "Subprocess should exit with 0");
    }
}

#[cfg(not(target_os = "linux"))]
mod non_linux {
    #[test]
    fn test_is_guarded_returns_false() {
        assert!(!crate::is_guarded(), "prctl not available on non-Linux");
    }
}
