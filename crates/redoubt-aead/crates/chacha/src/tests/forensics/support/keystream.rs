// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

/// A keystream laid over a buffer, both ways: what encrypting and decrypting
/// write, each found while it is kept, and what either leaves once the caller
/// has emptied what is its own.
///
/// A macro and not a function taking the operation: a function in between
/// would run after the operation returned and before the freeze.
macro_rules! test_what_a_keystream_leaves {
    (
        $encrypted_is_found:ident,
        $decrypted_is_found:ident,
        $encrypting_leaves_nothing:ident,
        $decrypting_leaves_nothing:ident,
        $what:literal,
        $ciphertext:expr,
        [$(($name:literal, $needle:expr)),* $(,)?],
        |$key:ident, $data:ident| $operation:expr $(,)?
    ) => {
        #[redoubt_forensics::test]
        fn $encrypted_is_found() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards(&$ciphertext))?;

            let mut $key = a_key();

            forensics!({
                // Leaked and not a local: a local is dropped at the end of the
                // block, and its drop empties or frees what the operation wrote
                // before the photograph.
                let $data: &mut [u8] = holding(&PLAINTEXT).leak();

                capture(|| $operation);

                $key.fast_zeroize();
            });

            is_found(&watch.snapshot()?, concat!($what, ", encrypting, and kept"));

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $decrypted_is_found() -> Result<(), AnyError> {
            let mut watch = Forensics::watching(&backwards(&PLAINTEXT))?;

            let mut $key = a_key();

            forensics!({
                // Leaked and not a local: a local is dropped at the end of the
                // block, and its drop empties or frees what the operation wrote
                // before the photograph.
                let $data: &mut [u8] = holding(&$ciphertext).leak();

                capture(|| $operation);

                $key.fast_zeroize();
            });

            is_found(&watch.snapshot()?, concat!($what, ", decrypting, and kept"));

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $encrypting_leaves_nothing() -> Result<(), AnyError> {
            let mut watching = Watching::start(&[
                ("key", &backwards(&KEY)),
                ("plaintext", &backwards(&PLAINTEXT)),
                $(($name, &backwards(&$needle)),)*
            ])?;

            let mut $key = a_key();
            let mut buffer = holding(&PLAINTEXT);

            forensics!({
                let $data: &mut [u8] = &mut buffer;

                capture(|| $operation);

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                //
                // The key is the caller's. The buffer holds the ciphertext,
                // which is public, and so stays.
                $key.fast_zeroize();
            });

            watching.none_left(concat!($what, ", encrypting"))?;

            Ok(())
        }

        #[redoubt_forensics::test]
        fn $decrypting_leaves_nothing() -> Result<(), AnyError> {
            let mut watching = Watching::start(&[
                ("key", &backwards(&KEY)),
                ("plaintext", &backwards(&PLAINTEXT)),
                $(($name, &backwards(&$needle)),)*
            ])?;

            let mut $key = a_key();
            let mut buffer = holding(&$ciphertext);

            forensics!({
                let $data: &mut [u8] = &mut buffer;

                capture(|| $operation);

                // CORRECTNESS: after the capture. A call made before it writes
                // over the stack and the registers the operation left, and
                // then the absence below is about that call and not about the
                // operation.
                //
                // The key and the plaintext in the buffer are the caller's.
                $key.fast_zeroize();
                buffer.fast_zeroize();
            });

            watching.none_left(concat!($what, ", decrypting"))?;

            Ok(())
        }
    };
}

pub(crate) use test_what_a_keystream_leaves;
