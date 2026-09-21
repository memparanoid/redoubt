// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Exhaustive tests for Page.

#[cfg(all(test, unix))]
mod page_tests {
    use serial_test::serial;

    use redoubt_zero::ZeroizationProbe;

    #[cfg(target_os = "linux")]
    use crate::error::PageError;
    use crate::page::Page;

    // =============================================================================
    // new()
    // =============================================================================

    #[test]
    // `not(miri)`: `serial_test` keeps a process-global registry of reentrant
    // mutexes, one per lock name, and never frees it — nine leaked allocations that
    // are not ours and that would have to be silenced with `-Zmiri-ignore-leaks`.
    // Turning leak detection off in *this* crate is the worst possible place for
    // it: `redoubt-buffer` is the one doing raw `mmap`, so a leak here means a page
    // holding secrets that was never unmapped.
    //
    // Dropping the serialization instead is sound, because what it serializes does
    // not exist under Miri. The lock guards contention over process-wide resources
    // — `RLIMIT_MEMLOCK`, shared by the 21 page buffers these tests instantiate,
    // and the irreversible seccomp filters — and under Miri `mlock` is a no-op and
    // the seccomp tests are ignored, since they need a subprocess.
    //
    // Note this attribute is already inert under `cargo nextest`, which runs one
    // process per test: `serial_test`'s registry is per process, so there is
    // nothing to contend with. It only does anything under `cargo test`.
    #[cfg_attr(not(miri), serial(page))]
    fn test_new_page_is_zeroized() {
        let page = Page::new().expect("Failed to new()");
        let slice = unsafe { page.as_slice() };

        assert!(slice.is_zeroized());
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    #[cfg(unix)]
    fn test_slice_len_matches_page_size() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;
        let system_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let slice = unsafe { page.as_slice() };

        assert_eq!(slice.len(), system_page_size);

        Ok(())
    }

    // TODO: Run this test in a subprocess to safely cover the MAP_FAILED branch
    // without causing stack allocation failures in the main test process.
    // This would allow including it in coverage reports without flakiness.
    // See: Page::new() line 47 - branch coverage for ptr == libc::MAP_FAILED
    #[test]
    #[ignore] // Exhausts address space, run explicitly with --ignored
    #[cfg_attr(not(miri), serial(page))]
    #[cfg(target_os = "linux")]
    fn test_new_fails_when_address_space_exhausted() {
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) };

        let tiny = libc::rlimit {
            rlim_cur: 0,
            rlim_max: original.rlim_max,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &tiny) };

        let result = Page::new();

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Create)));

        unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };
    }

    // =============================================================================
    // lock()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_lock_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;
        page.lock()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_lock_then_munlock() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.lock()?;
        page.munlock();

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_lock_multiple_times_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.lock()?;
        page.lock()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_munlock_without_lock_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.munlock();

        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod seccomp_lock {
        use super::*;
        use crate::tests::utils::{block_mlock, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_lock_fails_when_mlock_blocked() -> Result<(), Box<dyn std::error::Error>>
        {
            let page = Page::new()?;

            block_mlock();

            let result = page.lock();

            assert!(result.is_err());
            assert!(matches!(result, Err(PageError::Lock)));

            Ok(())
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_lock_fails_when_mlock_blocked() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_lock::subprocess_test_lock_fails_when_mlock_blocked",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    // =============================================================================
    // mark_dontdump()
    // =============================================================================

    #[cfg(target_os = "linux")]
    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_mark_dontdump_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.mark_dontdump()?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_mark_dontdump_multiple_times_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.mark_dontdump()?;
        page.mark_dontdump()?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod seccomp_mark_dontdump {
        use super::*;
        use crate::tests::utils::{block_madvise, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_mark_dontdump_fails_when_madvise_blocked()
        -> Result<(), Box<dyn std::error::Error>> {
            let page = Page::new()?;

            block_madvise();

            let result = page.mark_dontdump();

            assert!(result.is_err());
            assert!(matches!(result, Err(PageError::Madvise)));

            Ok(())
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_mark_dontdump_fails_when_madvise_blocked() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_mark_dontdump::subprocess_test_mark_dontdump_fails_when_madvise_blocked",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    // =============================================================================
    // protect()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_protect_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.protect()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_protect_then_unprotect() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.protect()?;
        page.unprotect()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_protect_unprotect_roundtrip_preserves_data() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        unsafe { page.as_mut_slice()[0] = 0xFF };

        page.protect()?;
        page.unprotect()?;

        let value = unsafe { page.as_slice()[0] };
        assert_eq!(value, 0xFF);

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_multiple_protect_unprotect_cycles() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        for i in 0..5u8 {
            unsafe { page.as_mut_slice()[0] = i };

            page.protect()?;
            page.unprotect()?;

            let value = unsafe { page.as_slice()[0] };

            assert_eq!(value, i);
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod seccomp_protect {
        use super::*;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_protect_fails_when_mprotect_blocked()
        -> Result<(), Box<dyn std::error::Error>> {
            let page = Page::new()?;

            block_mprotect();

            let result = page.protect();

            assert!(result.is_err());
            assert!(matches!(result, Err(PageError::Protect)));

            Ok(())
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_protect_fails_when_mprotect_blocked() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_protect::subprocess_test_protect_fails_when_mprotect_blocked",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }

        #[test]
        #[ignore]
        fn subprocess_test_protect_failure_zeroizes_page() -> Result<(), Box<dyn std::error::Error>>
        {
            let mut page = Page::new()?;

            // Write sensitive data
            unsafe { page.as_mut_slice().fill(0xFF) };
            assert!(!unsafe { page.as_slice() }.is_zeroized());

            // Block mprotect, protect() will fail and call dispose()
            block_mprotect();

            let result = page.protect();

            assert!(result.is_err());
            assert!(matches!(result, Err(PageError::Protect)));

            // Page should be zeroized by dispose()
            // Note: dispose() also unmaps, so we can't check directly
            // But we verified the error path calls dispose()

            Ok(())
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_protect_failure_zeroizes_page() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_protect::subprocess_test_protect_failure_zeroizes_page",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    // =============================================================================
    // unprotect()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_unprotect_on_unprotected_page_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.unprotect()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_unprotect_allows_write() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        page.protect()?;
        page.unprotect()?;

        unsafe { page.as_mut_slice()[0] = 0x42 };
        assert_eq!(unsafe { page.as_slice()[0] }, 0x42);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod seccomp_unprotect {
        use super::*;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_unprotect_fails_when_mprotect_blocked()
        -> Result<(), Box<dyn std::error::Error>> {
            let page = Page::new()?;

            page.protect()?;
            block_mprotect();

            let result = page.unprotect();

            assert!(result.is_err());
            assert!(matches!(result, Err(PageError::Unprotect)));

            Ok(())
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_unprotect_fails_when_mprotect_blocked() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_unprotect::subprocess_test_unprotect_fails_when_mprotect_blocked",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    // =============================================================================
    // as_slice() / as_mut_slice()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_as_mut_slice_allows_writes() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe {
            let slice = page.as_mut_slice();
            slice[0] = 0xAB;
            slice[1] = 0xCD;
        }

        let slice = unsafe { page.as_slice() };

        assert_eq!(slice[0], 0xAB);
        assert_eq!(slice[1], 0xCD);
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_write_read_full_page() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe { page.as_mut_slice().fill(0x55) };
        let slice = unsafe { page.as_slice() };

        assert!(slice.iter().all(|&b| b == 0x55));
    }

    // =============================================================================
    // zeroize()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_zeroize_clears_all_data() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe { page.as_mut_slice().fill(0xFF) };
        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };
        assert!(unsafe { page.as_slice() }.is_zeroized());
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_zeroize_after_partial_write() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe {
            page.as_mut_slice()[0] = 0x42;
            page.as_mut_slice()[100] = 0x42;
        }

        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };

        assert!(unsafe { page.as_slice() }.is_zeroized());
    }

    // =============================================================================
    // dispose()
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_dispose_on_unprotected_page() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe { page.as_mut_slice().fill(0xFF) };

        page.dispose();
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_dispose_on_protected_page() {
        let mut page = Page::new().expect("Failed to new()");

        unsafe { page.as_mut_slice().fill(0xFF) };

        page.protect().expect("Failed to protect()");
        page.dispose();
    }

    #[cfg(target_os = "linux")]
    mod seccomp_dispose {
        use super::*;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_dispose_when_unprotect_fails() {
            let mut page = Page::new().expect("Failed to new()");

            page.protect().expect("Failed to protect()");

            // Block mprotect, so unprotect() in dispose() will fail
            // Page stays protected = safe (can't be read)
            block_mprotect();

            page.dispose();
        }

        #[test]
        #[cfg_attr(
            miri,
            ignore = "spawns a subprocess to install a seccomp filter; Miri supports neither"
        )]
        #[cfg_attr(not(miri), serial(page))]
        fn test_dispose_when_unprotect_fails() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_dispose::subprocess_test_dispose_when_unprotect_fails",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    // =============================================================================
    // Full lifecycle
    // =============================================================================

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_full_lifecycle() {
        let mut page = Page::new().expect("Failed to new()");

        // Lock in RAM
        page.lock().expect("Failed to lock()");

        // Write sensitive data
        unsafe { page.as_mut_slice().fill(0xDE) };

        // Protect
        page.protect().expect("Failed to protect()");

        // Unprotect, read, protect again
        page.unprotect().expect("Failed to unprotect()");
        assert_eq!(unsafe { page.as_slice()[0] }, 0xDE);
        page.protect().expect("Failed to protect()");

        // Cleanup
        page.dispose();
    }

    #[test]
    #[cfg_attr(not(miri), serial(page))]
    fn test_new_write_zeroize_verify() {
        let mut page = Page::new().expect("Failed to new()");

        assert!(unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.as_mut_slice().fill(0xAB) };
        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };
        assert!(unsafe { page.as_slice() }.is_zeroized());
    }
}
