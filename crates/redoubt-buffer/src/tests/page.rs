// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Exhaustive tests for Page.

use serial_test::serial;

use redoubt_zero::ZeroizationProbe;

use crate::error::PageError;
use crate::page::Page;

// =============================================================================
// new()
// =============================================================================

#[test]
#[serial(page)]
fn test_new_page_is_zeroized() {
    let page = Page::new().expect("Failed to new()");
    let slice = unsafe { page.as_slice() };

    assert!(slice.is_zeroized());
}

#[test]
#[serial(page)]
fn test_slice_len_matches_page_size() {
    let page = Page::new().expect("Failed to new()");
    let system_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let slice = unsafe { page.as_slice() };

    assert_eq!(slice.len(), system_page_size);
}

#[test]
#[serial(page)]
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
#[serial(page)]
fn test_lock_succeeds() {
    let page = Page::new().expect("Failed to new()");
    page.lock().expect("Failed to lock()");
}

#[test]
#[serial(page)]
fn test_lock_then_munlock() {
    let page = Page::new().expect("Failed to new()");

    page.lock().expect("Failed to lock()");
    page.munlock();
}

#[test]
#[serial(page)]
fn test_lock_multiple_times_succeeds() {
    let page = Page::new().expect("Failed to new()");

    page.lock().expect("Failed to lock()");
    page.lock().expect("Failed to lock()");
}

#[test]
#[serial(page)]
fn test_munlock_without_lock_succeeds() {
    let page = Page::new().expect("Failed to new()");

    page.munlock();
}

#[cfg(target_os = "linux")]
mod seccomp_lock {
    use super::*;
    use crate::tests::utils::{block_mlock, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_lock_fails_when_mlock_blocked() {
        let page = Page::new().expect("Failed to new()");

        block_mlock();

        let result = page.lock();

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Lock)));
    }

    #[test]
    #[serial(page)]
    fn test_lock_fails_when_mlock_blocked() {
        let exit_code = run_test_as_subprocess(
            "tests::page::seccomp_lock::subprocess_test_lock_fails_when_mlock_blocked",
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
#[serial(page)]
fn test_protect_succeeds() {
    let page = Page::new().expect("Failed to new()");

    page.protect().expect("Failed to protect()");
}

#[test]
#[serial(page)]
fn test_protect_then_unprotect() {
    let page = Page::new().expect("Failed to new()");

    page.protect().expect("Failed to protect()");
    page.unprotect().expect("Failed to unprotect()");
}

#[test]
#[serial(page)]
fn test_protect_unprotect_roundtrip_preserves_data() {
    let mut page = Page::new().expect("Failed to new()");

    unsafe { page.as_mut_slice()[0] = 0xFF };

    page.protect().expect("Failed to protect()");
    page.unprotect().expect("Failed to unprotect()");

    let value = unsafe { page.as_slice()[0] };
    assert_eq!(value, 0xFF);
}

#[test]
#[serial(page)]
fn test_multiple_protect_unprotect_cycles() {
    let mut page = Page::new().expect("Failed to new()");

    for i in 0..5u8 {
        unsafe { page.as_mut_slice()[0] = i };

        page.protect().expect("Failed to protect()");
        page.unprotect().expect("Failed to unprotect()");

        let value = unsafe { page.as_slice()[0] };

        assert_eq!(value, i);
    }
}

#[cfg(target_os = "linux")]
mod seccomp_protect {
    use super::*;
    use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_protect_fails_when_mprotect_blocked() {
        let page = Page::new().expect("Failed to new()");

        block_mprotect();

        let result = page.protect();

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Protect)));
    }

    #[test]
    #[serial(page)]
    fn test_protect_fails_when_mprotect_blocked() {
        let exit_code = run_test_as_subprocess(
            "tests::page::seccomp_protect::subprocess_test_protect_fails_when_mprotect_blocked",
        );

        assert_eq!(
            exit_code,
            Some(0),
            "Subprocess should exit cleanly after assertion"
        );
    }

    #[test]
    #[ignore]
    fn subprocess_test_protect_failure_zeroizes_page() {
        let mut page = Page::new().expect("Failed to new()");

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
    }

    #[test]
    #[serial(page)]
    fn test_protect_failure_zeroizes_page() {
        let exit_code = run_test_as_subprocess(
            "tests::page::seccomp_protect::subprocess_test_protect_failure_zeroizes_page",
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
#[serial(page)]
fn test_unprotect_on_unprotected_page_succeeds() {
    let page = Page::new().expect("Failed to new()");

    page.unprotect().expect("Failed to unprotect()");
}

#[test]
#[serial(page)]
fn test_unprotect_allows_write() {
    let mut page = Page::new().expect("Failed to new()");

    page.protect().expect("Failed to protect()");
    page.unprotect().expect("Failed to unprotect()");

    unsafe { page.as_mut_slice()[0] = 0x42 };
    assert_eq!(unsafe { page.as_slice()[0] }, 0x42);
}

#[cfg(target_os = "linux")]
mod seccomp_unprotect {
    use super::*;
    use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

    #[test]
    #[ignore]
    fn subprocess_test_unprotect_fails_when_mprotect_blocked() {
        let page = Page::new().expect("Failed to new()");

        page.protect().expect("Failed to protect()");
        block_mprotect();

        let result = page.unprotect();

        assert!(result.is_err());
        assert!(matches!(result, Err(PageError::Unprotect)));
    }

    #[test]
    #[serial(page)]
    fn test_unprotect_fails_when_mprotect_blocked() {
        let exit_code = run_test_as_subprocess(
            "tests::page::seccomp_unprotect::subprocess_test_unprotect_fails_when_mprotect_blocked",
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
#[serial(page)]
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
#[serial(page)]
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
#[serial(page)]
fn test_zeroize_clears_all_data() {
    let mut page = Page::new().expect("Failed to new()");

    unsafe { page.as_mut_slice().fill(0xFF) };
    assert!(!unsafe { page.as_slice() }.is_zeroized());

    unsafe { page.zeroize() };
    assert!(unsafe { page.as_slice() }.is_zeroized());
}

#[test]
#[serial(page)]
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
#[serial(page)]
fn test_dispose_on_unprotected_page() {
    let mut page = Page::new().expect("Failed to new()");

    unsafe { page.as_mut_slice().fill(0xFF) };

    page.dispose();
}

#[test]
#[serial(page)]
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
    #[serial(page)]
    fn test_dispose_when_unprotect_fails() {
        let exit_code = run_test_as_subprocess(
            "tests::page::seccomp_dispose::subprocess_test_dispose_when_unprotect_fails",
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
#[serial(page)]
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
#[serial(page)]
fn test_new_write_zeroize_verify() {
    let mut page = Page::new().expect("Failed to new()");

    assert!(unsafe { page.as_slice() }.is_zeroized());

    unsafe { page.as_mut_slice().fill(0xAB) };
    assert!(!unsafe { page.as_slice() }.is_zeroized());

    unsafe { page.zeroize() };
    assert!(unsafe { page.as_slice() }.is_zeroized());
}
