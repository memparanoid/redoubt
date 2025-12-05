// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

![Redoubt](/logo.png)

> A systematic framework for secure memory handling in Rust.

Memora provides a comprehensive set of tools and abstractions for handling sensitive data in memory securely. It combines multiple security techniques to prevent common vulnerabilities:

- **Automatic Zeroing**: Secure cleanup of sensitive data
- **Memory Encryption**: Encrypt sensitive data at rest in memory
- **Bounds Checking**: Prevent buffer overflows and out-of-bounds access
- **Safe Allocations**: Type-safe wrappers for memory allocation

## Features

- 🛡️ **Defense in Depth**: Multiple layers of protection
- 🎯 **Zero-cost Abstractions**: Minimal runtime overhead
- 🔧 **Flexible**: Mid-level API with escape hatches when needed
- ✅ **No Unsafe Surprises**: Clear boundaries between safe and unsafe code

## Quick Start

```rust
use memora::SecureBuffer;

fn main() {
    // Create a secure buffer for sensitive data
    let mut password = SecureBuffer::new(b"super_secret_password");

    // Use it normally
    assert_eq!(password.as_slice(), b"super_secret_password");

    // Automatically zeroed on drop
} // password memory is now zeroed
```

## Architecture

Memora is organized into several modules:

- `core`: Core traits and types
- `secure`: Secure memory containers (SecureBuffer, SecureVec, etc.)
- `alloc`: Safe allocation primitives
- `bounds`: Bounds-checked access
- `crypto`: Optional memory encryption support

## Safety Guarantees

Memora uses a **mid-level** approach:
- Public APIs are safe by default
- Unsafe operations are clearly marked and documented
- Internal unsafe code is thoroughly reviewed and tested
- Extensive testing including property-based tests

## License

Licensed under either of Apache License, Version 2.0 or MIT license 
