// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

// use zeroize::Zeroizing;

// use crate::error::DecodeError;
// use crate::traits::{Decode, DecodeBuffer};

// use super::helpers::process_header;

// trait TryDecode {
//     fn try_decode_from(&mut self, buf: &mut [u8]) -> Result<(), DecodeError>;
// }

// impl<T> TryDecode for [T]
// where
//     T: Decode,
// {
//     fn try_decode_from(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
//         let mut size = Zeroizing::new(0);
//         let mut bytes_required = Zeroizing::new(0);

//         process_header(buf, &mut size, &mut bytes_required)?;

//         T::decode_slice_from(self, buf)?;

//         Ok(())
//     }
// }

// impl<T> Decode for [T]
// where
//     T: Decode,
// {
//     fn decode_from(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
//         let result = self.try_decode_from(buf);

//         #[cfg(feature = "zeroize")]
//         if result.is_err() {
//             memutil::fast_zeroize_slice(buf);
//         }

//         result
//     }
// }
