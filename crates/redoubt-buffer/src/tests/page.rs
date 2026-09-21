// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Exhaustive tests for Page.

#[cfg(all(test, unix))]
mod page_tests {
    use redoubt_zero::ZeroizationProbe;

    #[cfg(target_os = "linux")]
    use crate::error::PageError;
    use crate::page::Page;

    // =============================================================================
    // new()
    // =============================================================================

    #[test]
    fn test_new_page_is_zeroized() {
        let page = Page::new().expect("Failed to new()");
        let slice = unsafe { page.as_slice() };

        assert!(slice.is_zeroized());
    }

    #[test]
    #[cfg(unix)]
    fn test_slice_len_matches_page_size() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;
        let system_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let slice = unsafe { page.as_slice() };

        assert_eq!(slice.len(), system_page_size);

        Ok(())
    }

    /// A process of its own: the limit is the whole address space, so every
    /// other test sharing the process would fail its next allocation too.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn subprocess_test_new_reports_create_when_the_address_space_is_exhausted() {
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

        // CORRECTNESS: before the assertion. A failing `assert!` formats its
        // message, and there is no address space to allocate that in while the
        // limit stands.
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };

        assert!(matches!(result, Err(PageError::Create)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_new_reports_create_when_the_address_space_is_exhausted() {
        use crate::tests::utils::run_test_as_subprocess;

        let exit_code = run_test_as_subprocess(
            "tests::page::page_tests::subprocess_test_new_reports_create_when_the_address_space_is_exhausted",
        );

        assert_eq!(
            exit_code,
            Some(0),
            "Subprocess should exit cleanly after assertion"
        );
    }

    // =============================================================================
    // lock()
    // =============================================================================

    #[test]
    fn test_lock_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;
        page.lock()?;

        Ok(())
    }

    #[test]
    fn test_lock_then_munlock() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.lock()?;
        page.munlock();

        Ok(())
    }

    #[test]
    fn test_lock_multiple_times_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.lock()?;
        page.lock()?;

        Ok(())
    }

    #[test]
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
    fn test_mark_dontdump_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.mark_dontdump()?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
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
    fn test_protect_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.protect()?;

        Ok(())
    }

    #[test]
    fn test_protect_then_unprotect() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.protect()?;
        page.unprotect()?;

        Ok(())
    }

    #[test]
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
    }

    // =============================================================================
    // unprotect()
    // =============================================================================

    #[test]
    fn test_unprotect_on_unprotected_page_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let page = Page::new()?;

        page.unprotect()?;

        Ok(())
    }

    #[test]
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
    fn test_as_mut_slice_allows_writes() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        unsafe {
            let slice = page.as_mut_slice();
            slice[0] = 0xAB;
            slice[1] = 0xCD;
        }

        let slice = unsafe { page.as_slice() };

        assert_eq!(slice[0], 0xAB);
        assert_eq!(slice[1], 0xCD);

        Ok(())
    }

    #[test]
    fn test_write_read_full_page() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        unsafe { page.as_mut_slice().fill(0x55) };
        let slice = unsafe { page.as_slice() };

        assert!(slice.iter().all(|&b| b == 0x55));

        Ok(())
    }

    // =============================================================================
    // zeroize()
    // =============================================================================

    #[test]
    fn test_zeroize_clears_all_data() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        unsafe { page.as_mut_slice().fill(0xFF) };
        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };
        assert!(unsafe { page.as_slice() }.is_zeroized());

        Ok(())
    }

    #[test]
    fn test_zeroize_after_partial_write() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        unsafe {
            page.as_mut_slice()[0] = 0x42;
            page.as_mut_slice()[100] = 0x42;
        }

        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };

        assert!(unsafe { page.as_slice() }.is_zeroized());

        Ok(())
    }

    // =============================================================================
    // Drop
    // =============================================================================

    /// The oracle is the MMU: a write to a page at `PROT_NONE` raises
    /// `SIGSEGV`, so a clean exit is what says the unprotect ran before the
    /// zeroize. The subprocess is what turns a fault into an exit code instead
    /// of the end of the suite.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn subprocess_test_drop_unprotects_before_zeroizing() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut page = Page::new()?;

        unsafe { page.as_mut_slice().fill(0xFF) };
        page.protect()?;

        drop(page);

        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_drop_unprotects_before_zeroizing() {
        use crate::tests::utils::run_test_as_subprocess;

        let exit_code = run_test_as_subprocess(
            "tests::page::page_tests::subprocess_test_drop_unprotects_before_zeroizing",
        );

        assert_eq!(
            exit_code,
            Some(0),
            "dropping a protected page faulted instead of unprotecting first"
        );
    }

    #[cfg(target_os = "linux")]
    mod seccomp_drop {
        use super::*;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        /// The oracle is the MMU: a page whose `mprotect` is refused stays at
        /// `PROT_NONE`, so a clean exit is what says the zeroize was skipped
        /// rather than attempted on a page nothing may write.
        #[test]
        #[ignore]
        fn subprocess_test_drop_skips_the_zeroize_when_unprotect_fails()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut page = Page::new()?;

            unsafe { page.as_mut_slice().fill(0xFF) };
            page.protect()?;

            block_mprotect();

            drop(page);

            Ok(())
        }

        #[test]
        fn test_drop_skips_the_zeroize_when_unprotect_fails() {
            let exit_code = run_test_as_subprocess(
                "tests::page::page_tests::seccomp_drop::subprocess_test_drop_skips_the_zeroize_when_unprotect_fails",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "dropping a page that would not reopen faulted instead of leaving it alone"
            );
        }
    }

    // =============================================================================
    // Full lifecycle
    // =============================================================================

    #[test]
    fn test_full_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        // Lock in RAM
        page.lock()?;

        // Write sensitive data
        unsafe { page.as_mut_slice().fill(0xDE) };

        // Protect
        page.protect()?;

        // Unprotect, read, protect again
        page.unprotect()?;
        assert_eq!(unsafe { page.as_slice()[0] }, 0xDE);
        page.protect()?;

        Ok(())
    }

    #[test]
    fn test_new_write_zeroize_verify() -> Result<(), Box<dyn std::error::Error>> {
        let mut page = Page::new()?;

        assert!(unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.as_mut_slice().fill(0xAB) };
        assert!(!unsafe { page.as_slice() }.is_zeroized());

        unsafe { page.zeroize() };
        assert!(unsafe { page.as_slice() }.is_zeroized());

        Ok(())
    }
}
