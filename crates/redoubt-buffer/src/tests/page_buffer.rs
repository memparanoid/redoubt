// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Tests for PageBuffer.

#[cfg(all(test, unix))]
mod page_buffer_tests {
    use redoubt_zero::ZeroizationProbe;

    use crate::error::BufferError;
    use crate::page_buffer::{PageBuffer, ProtectionStrategy};
    use crate::traits::Buffer;

    fn protected() -> Result<PageBuffer, Box<dyn std::error::Error>> {
        Ok(PageBuffer::new(ProtectionStrategy::MemProtected, 32)?)
    }

    /// What a callback hands back where the test is about the refusal rather
    /// than about what it says.
    #[derive(Debug, thiserror::Error)]
    #[error("a test callback refused")]
    struct Refused;

    // =============================================================================
    // new()
    // =============================================================================

    /// A process of its own: the limit is the whole address space, so every
    /// other test sharing the process would fail its next allocation too.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn subprocess_test_new_propagates_page_create_error() {
        use crate::error::PageError;

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

        let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

        // CORRECTNESS: before the assertion. A failing `assert!` formats its
        // message, and there is no address space to allocate that in while the
        // limit stands.
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) };

        assert!(matches!(result, Err(PageError::Create)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_new_propagates_page_create_error() {
        use crate::tests::utils::run_test_as_subprocess;

        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::page_buffer_tests::subprocess_test_new_propagates_page_create_error",
        );

        assert_eq!(
            exit_code,
            Some(0),
            "Subprocess should exit cleanly after assertion"
        );
    }

    #[cfg(target_os = "linux")]
    mod seccomp_new {
        use super::*;
        use crate::error::PageError;
        use crate::tests::utils::{
            block_madvise, block_mlock, block_mprotect, run_test_as_subprocess,
        };

        #[test]
        #[ignore]
        fn subprocess_test_new_propagates_page_lock_error() {
            block_mlock();

            let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

            assert!(matches!(result, Err(PageError::Lock)));
        }

        #[test]
        fn test_new_propagates_page_lock_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_new::subprocess_test_new_propagates_page_lock_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }

        #[test]
        #[ignore]
        fn subprocess_test_new_propagates_page_madvise_error() {
            block_madvise();

            let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

            assert!(matches!(result, Err(PageError::Madvise)));
        }

        #[test]
        fn test_new_propagates_page_madvise_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_new::subprocess_test_new_propagates_page_madvise_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }

        #[test]
        #[ignore]
        fn subprocess_test_new_propagates_page_protect_error() {
            block_mprotect();

            let result = PageBuffer::new(ProtectionStrategy::MemProtected, 32);

            assert!(matches!(result, Err(PageError::Protect)));
        }

        #[test]
        fn test_new_propagates_page_protect_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_new::subprocess_test_new_propagates_page_protect_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    #[test]
    fn test_new_returns_a_protected_buffer() -> Result<(), Box<dyn std::error::Error>> {
        let buffer = protected()?;

        assert!(format!("{:?}", buffer).contains("MemProtected"));

        Ok(())
    }

    #[test]
    fn test_new_returns_a_non_protected_buffer() -> Result<(), Box<dyn std::error::Error>> {
        let buffer = PageBuffer::new(ProtectionStrategy::MemNonProtected, 32)?;

        assert!(format!("{:?}", buffer).contains("MemNonProtected"));

        Ok(())
    }

    // =============================================================================
    // unseal()
    // =============================================================================

    #[test]
    fn test_unseal_reports_page_no_longer_available() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.poisoned = true;

        assert!(matches!(
            buffer.unseal(),
            Err(BufferError::PageNoLongerAvailable)
        ));

        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod seccomp_unseal {
        use super::*;
        use crate::error::PageError;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_unseal_propagates_unprotect_error()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut buffer = protected()?;

            block_mprotect();

            assert!(matches!(
                buffer.unseal(),
                Err(BufferError::Page(PageError::Unprotect))
            ));

            assert!(
                buffer.poisoned,
                "a page that would not open left the buffer usable"
            );

            Ok(())
        }

        #[test]
        fn test_unseal_propagates_unprotect_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_unseal::subprocess_test_unseal_propagates_unprotect_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    /// The oracle is the MMU: reading a page at `PROT_NONE` raises `SIGSEGV`,
    /// so the read returning at all is what says the page opened.
    #[test]
    fn test_unseal_opens_the_page() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.unseal()?;

        assert!(unsafe { buffer.page.as_slice() }.is_zeroized());

        buffer.seal()?;

        Ok(())
    }

    // =============================================================================
    // seal()
    // =============================================================================

    #[cfg(target_os = "linux")]
    mod seccomp_seal {
        use super::*;
        use crate::error::PageError;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_seal_propagates_protect_error() -> Result<(), Box<dyn std::error::Error>>
        {
            let mut buffer = protected()?;

            buffer.unseal()?;
            unsafe { buffer.page.as_mut_slice().fill(0xFF) };

            block_mprotect();

            assert!(matches!(
                buffer.seal(),
                Err(BufferError::Page(PageError::Protect))
            ));

            assert!(
                buffer.poisoned,
                "a page that would not close left the buffer usable"
            );

            assert!(
                unsafe { buffer.page.as_slice() }.is_zeroized(),
                "a page left readable kept its contents"
            );

            Ok(())
        }

        #[test]
        fn test_seal_propagates_protect_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_seal::subprocess_test_seal_propagates_protect_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    #[test]
    fn test_seal_leaves_the_buffer_usable() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.unseal()?;
        buffer.seal()?;

        assert!(!buffer.poisoned);

        Ok(())
    }

    // =============================================================================
    // is_empty()
    // =============================================================================

    #[test]
    fn test_is_empty_returns_false() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!protected()?.is_empty());

        Ok(())
    }

    #[test]
    fn test_is_empty_returns_true() -> Result<(), Box<dyn std::error::Error>> {
        let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 0)?;

        assert!(buffer.is_empty());

        Ok(())
    }

    // =============================================================================
    // Debug
    // =============================================================================

    #[test]
    fn test_debug_does_not_expose_contents() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.open_mut(&mut |bytes| {
            bytes.fill(0xAB);
            Ok(())
        })?;

        let debug_output = format!("{:?}", buffer);

        assert!(debug_output.contains("PageBuffer"));
        assert!(debug_output.contains("len"));
        assert!(debug_output.contains("32"));
        assert!(debug_output.contains("MemProtected"));
        assert!(!debug_output.contains("ab"));

        Ok(())
    }

    // =============================================================================
    // open()
    // =============================================================================

    #[test]
    fn test_open_propagates_unseal_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.poisoned = true;

        let result = buffer.open(&mut |_| Ok(()));

        assert!(matches!(result, Err(BufferError::PageNoLongerAvailable)));

        Ok(())
    }

    #[test]
    fn test_open_propagates_callback_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        let result = buffer.open(&mut |_| Err(BufferError::callback_error(Refused)));

        assert!(matches!(result, Err(BufferError::CallbackError(_))));

        Ok(())
    }

    /// The oracle is the MMU: reading a page at `PROT_NONE` raises `SIGSEGV`,
    /// so being killed by a signal is what says the page was closed. A clean
    /// exit means the callback's error carried the page out still readable,
    /// for the rest of the process.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn subprocess_test_open_seals_the_page_when_the_callback_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        let _ = buffer.open(&mut |_| Err(BufferError::callback_error(Refused)));

        core::hint::black_box(unsafe { buffer.page.as_slice() }[0]);

        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_seals_the_page_when_the_callback_errors() {
        use crate::tests::utils::run_test_as_subprocess;

        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::page_buffer_tests::subprocess_test_open_seals_the_page_when_the_callback_errors",
        );

        assert_eq!(
            exit_code, None,
            "the page stayed readable after the callback failed"
        );
    }

    #[cfg(target_os = "linux")]
    mod seccomp_open {
        use super::*;
        use crate::error::PageError;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_open_propagates_seal_error() -> Result<(), Box<dyn std::error::Error>> {
            let mut buffer = protected()?;

            let result = buffer.open(&mut |_| {
                block_mprotect();
                Ok(())
            });

            assert!(matches!(result, Err(BufferError::Page(PageError::Protect))));

            Ok(())
        }

        #[test]
        fn test_open_propagates_seal_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_open::subprocess_test_open_propagates_seal_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    #[test]
    fn test_open_returns_the_page_contents() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.open_mut(&mut |bytes| {
            bytes[0] = 0xAB;
            Ok(())
        })?;

        buffer.open(&mut |bytes| {
            assert_eq!(bytes[0], 0xAB);
            assert_eq!(bytes.len(), 32);
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_open_returns_the_page_contents_when_non_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = PageBuffer::new(ProtectionStrategy::MemNonProtected, 32)?;

        buffer.open_mut(&mut |bytes| {
            bytes[0] = 0xCD;
            Ok(())
        })?;

        buffer.open(&mut |bytes| {
            assert_eq!(bytes[0], 0xCD);
            Ok(())
        })?;

        Ok(())
    }

    // =============================================================================
    // open_mut()
    // =============================================================================

    #[test]
    fn test_open_mut_propagates_unseal_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.poisoned = true;

        let result = buffer.open_mut(&mut |_| Ok(()));

        assert!(matches!(result, Err(BufferError::PageNoLongerAvailable)));

        Ok(())
    }

    #[test]
    fn test_open_mut_propagates_callback_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        let result = buffer.open_mut(&mut |_| Err(BufferError::callback_error(Refused)));

        assert!(matches!(result, Err(BufferError::CallbackError(_))));

        Ok(())
    }

    /// The oracle is the MMU: writing to a page at `PROT_NONE` raises
    /// `SIGSEGV`, so being killed by a signal is what says the page was closed.
    /// A clean exit means the callback's error carried the page out still
    /// writable, for the rest of the process.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn subprocess_test_open_mut_seals_the_page_when_the_callback_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        let _ = buffer.open_mut(&mut |_| Err(BufferError::callback_error(Refused)));

        unsafe { buffer.page.as_mut_slice()[0] = 0xFF };

        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_mut_seals_the_page_when_the_callback_errors() {
        use crate::tests::utils::run_test_as_subprocess;

        let exit_code = run_test_as_subprocess(
            "tests::page_buffer::page_buffer_tests::subprocess_test_open_mut_seals_the_page_when_the_callback_errors",
        );

        assert_eq!(
            exit_code, None,
            "the page stayed writable after the callback failed"
        );
    }

    #[cfg(target_os = "linux")]
    mod seccomp_open_mut {
        use super::*;
        use crate::error::PageError;
        use crate::tests::utils::{block_mprotect, run_test_as_subprocess};

        #[test]
        #[ignore]
        fn subprocess_test_open_mut_propagates_seal_error() -> Result<(), Box<dyn std::error::Error>>
        {
            let mut buffer = protected()?;

            let result = buffer.open_mut(&mut |_| {
                block_mprotect();
                Ok(())
            });

            assert!(matches!(result, Err(BufferError::Page(PageError::Protect))));

            Ok(())
        }

        #[test]
        fn test_open_mut_propagates_seal_error() {
            let exit_code = run_test_as_subprocess(
                "tests::page_buffer::page_buffer_tests::seccomp_open_mut::subprocess_test_open_mut_propagates_seal_error",
            );

            assert_eq!(
                exit_code,
                Some(0),
                "Subprocess should exit cleanly after assertion"
            );
        }
    }

    #[test]
    fn test_open_mut_writes_the_page() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.open_mut(&mut |bytes| {
            bytes.fill(0xFF);
            Ok(())
        })?;

        buffer.open(&mut |bytes| {
            assert!(bytes.iter().all(|&b| b == 0xFF));
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_open_mut_zeroizes_the_page() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = protected()?;

        buffer.open_mut(&mut |bytes| {
            bytes.fill(0xFF);
            Ok(())
        })?;

        buffer.open_mut(&mut |bytes| {
            bytes.fill(0);
            Ok(())
        })?;

        buffer.open(&mut |bytes| {
            assert!(bytes.is_zeroized());
            Ok(())
        })?;

        Ok(())
    }

    // =============================================================================
    // len()
    // =============================================================================

    #[test]
    fn test_len_returns_the_requested_length() -> Result<(), Box<dyn std::error::Error>> {
        let buffer = PageBuffer::new(ProtectionStrategy::MemProtected, 64)?;

        assert_eq!(buffer.len(), 64);

        Ok(())
    }
}
