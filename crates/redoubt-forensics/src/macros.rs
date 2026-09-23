// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! What a measurement is shaped like, so that its answer is about the
//! operation.
//!
//! # The problem all of this is about
//!
//! Whatever runs after an operation is written onto the stack the operation
//! just used, over the frames that are the whole reason to look. A secret a
//! few dozen bytes wide goes under one call whole, and the photograph then
//! reports a clean process — just as cleanly as it would for an operation that
//! wiped nothing.
//!
//! [`forensics!`] and [`freeze!`] answer it by taking the evidence out of the
//! stack at the moment it exists, so that nothing afterwards can reach it.
//! Everything a caller has to get right is on one line: nothing goes between
//! the operation and the capture.

/// Everything the operation left, out of the stack and into memory nothing
/// else is about to write.
///
/// Three things, in an order that is the whole of why it works:
///
/// 1. the general registers, into the room,
/// 2. the window, into [`COPY`],
/// 3. the vector registers, into the room.
///
/// Steps 1 and 2 are stores and a string move. Neither is a call, so neither
/// moves the stack pointer and neither can write into the window. Step 3 is a
/// call and costs eight bytes below the stack pointer on `x86_64` — the
/// shallowest eight bytes of what the operation left, and the ones a secret
/// sitting at the top of its frame would be in. They are affordable there and
/// nowhere else, because step 2 has already taken them.
///
/// The generals have to come first because step 2 destroys three of them. The
/// vectors can wait because step 2 touches none: a string move reads and
/// writes through general registers and leaves the vector file exactly as the
/// operation left it.
///
/// It is one `asm!` block and not three statements, so there is no place
/// between the three for the compiler to put anything.
///
/// # Where it goes
///
/// Straight after the operation, with nothing in between — not a `?`, not a
/// `format!`, not a temporary whose drop runs at the end of the statement.
/// Anything called there writes over the frames the operation just released,
/// which is the one thing this cannot see through. Everything *after* it is
/// free: cleanup, drops, a `?`, the photograph itself.
///
/// # What it costs
///
/// No frame, no return address, no allocation. It writes into statics reached
/// relative to the instruction pointer, so nothing has to be passed and
/// nothing has to be computed. That is what lets it stand in the middle of
/// somebody else's code without disturbing what it came to read.
///
/// The registers it does spend — `rdi`, `rsi` and `rcx`, or `x0`–`x5` and the
/// linker's two scratch registers — are written down in step 1 before they are
/// touched. On `aarch64` the slots for `x16` and `x17` hold this capture's own
/// working rather than the caller's, which costs nothing: the ABI lets a
/// veneer clobber both at any call boundary, so nothing ever rests a value
/// there.
///
/// # Without a window
///
/// A capture with no [`open`] before it finds [`COPY`] null and copies
/// nothing. The registers are still written. That is the one branch in here,
/// and it is there because the alternative is a string move through a null
/// pointer.
#[macro_export]
macro_rules! freeze {
    () => {{
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        // SAFETY: every store is into one of this crate's own statics at an
        // offset inside it, and the string move reads this thread's own stack
        // between an address the thread reported and its own stack pointer —
        // one mapping, live for as long as the thread is. The call reaches a
        // form this machine was found to support before any of this ran, and
        // that form writes memory and no register, which is why no register is
        // declared for it.
        unsafe {
            ::core::arch::asm!(
                "mov qword ptr [rip + {regs} + 0], rax",
                "mov qword ptr [rip + {regs} + 8], rbx",
                "mov qword ptr [rip + {regs} + 16], rcx",
                "mov qword ptr [rip + {regs} + 24], rdx",
                "mov qword ptr [rip + {regs} + 32], rsi",
                "mov qword ptr [rip + {regs} + 40], rdi",
                "mov qword ptr [rip + {regs} + 48], rbp",
                "mov qword ptr [rip + {regs} + 56], rsp",
                "mov qword ptr [rip + {regs} + 64], r8",
                "mov qword ptr [rip + {regs} + 72], r9",
                "mov qword ptr [rip + {regs} + 80], r10",
                "mov qword ptr [rip + {regs} + 88], r11",
                "mov qword ptr [rip + {regs} + 96], r12",
                "mov qword ptr [rip + {regs} + 104], r13",
                "mov qword ptr [rip + {regs} + 112], r14",
                "mov qword ptr [rip + {regs} + 120], r15",
                "mov rcx, qword ptr [rip + {top}]",
                "cmp rcx, rsp",
                "cmovb rcx, rsp",
                "mov qword ptr [rip + {top}], 0",
                "mov qword ptr [rip + {at}], rcx",

                "mov rdi, qword ptr [rip + {copy}]",
                "test rdi, rdi",
                "jz 2f",
                "mov rsi, qword ptr [rip + {floor}]",
                "sub rcx, rsi",
                // The direction flag is clear at every function boundary and
                // nothing here sets it, so this is that guarantee made local
                // rather than borrowed.
                "cld",
                "rep movsb",
                "2:",

                "call {vectors}",

                regs    = sym $crate::redoubt_spill_room,
                copy    = sym $crate::COPY,
                floor   = sym $crate::FLOOR,
                at      = sym $crate::SP,
                top     = sym $crate::TOP,
                vectors = sym $crate::redoubt_spill_vectors,

                out("rdi") _,
                out("rsi") _,
                out("rcx") _,
            );
        }

        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        // SAFETY: as above. The window is a whole number of sixteens wide —
        // the floor is a page boundary and the stack pointer is sixteen-byte
        // aligned by the ABI — which is what lets the copy step in pairs.
        unsafe {
            ::core::arch::asm!(
                "adrp x16, {regs}",
                "add x16, x16, :lo12:{regs}",
                "stp x0, x1, [x16, #0]",
                "stp x2, x3, [x16, #16]",
                "stp x4, x5, [x16, #32]",
                "stp x6, x7, [x16, #48]",
                "stp x8, x9, [x16, #64]",
                "stp x10, x11, [x16, #80]",
                "stp x12, x13, [x16, #96]",
                "stp x14, x15, [x16, #112]",
                "stp x16, x17, [x16, #128]",
                "stp x18, x19, [x16, #144]",
                "stp x20, x21, [x16, #160]",
                "stp x22, x23, [x16, #176]",
                "stp x24, x25, [x16, #192]",
                "stp x26, x27, [x16, #208]",
                "stp x28, x29, [x16, #224]",
                "str x30, [x16, #240]",
                "mov x0, sp",
                "str x0, [x16, #248]",
                "adrp x1, {top}",
                "ldr x3, [x1, :lo12:{top}]",
                "str xzr, [x1, :lo12:{top}]",
                "cmp x3, x0",
                "csel x3, x3, x0, hi",
                "adrp x1, {at}",
                "str x3, [x1, :lo12:{at}]",

                "adrp x1, {copy}",
                "ldr x1, [x1, :lo12:{copy}]",
                "cbz x1, 2f",
                "adrp x2, {floor}",
                "ldr x2, [x2, :lo12:{floor}]",
                "cmp x2, x3",
                "b.hs 2f",
                "3:",
                "ldp x4, x5, [x2], #16",
                "stp x4, x5, [x1], #16",
                "cmp x2, x3",
                "b.lo 3b",
                "2:",

                "bl {vectors}",

                regs    = sym $crate::redoubt_spill_room,
                copy    = sym $crate::COPY,
                floor   = sym $crate::FLOOR,
                at      = sym $crate::SP,
                top     = sym $crate::TOP,
                vectors = sym $crate::redoubt_spill_vectors,

                out("x0") _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                out("x4") _,
                out("x5") _,
                out("x16") _,
                out("x17") _,
                out("x30") _,
            );
        }
    }};
}

/// A measurement, with the window open around it.
///
/// ```no_run
/// # use redoubt_forensics::{Forensics, Reason, freeze, forensics};
/// # fn seal(into: &mut [u8]) {}
/// # fn measured() -> Result<(), Reason> {
/// # let needle: Vec<u8> = Vec::new();
/// let mut watch = Forensics::watching(&needle)?;
/// let report_before = watch.snapshot()?;
///
/// let mut buffer = [0_u8; 32];
///
/// forensics!({
///     seal(&mut buffer);
///     freeze!();
/// });
///
/// let report_after = watch.snapshot()?;
///
/// println!("{}", report_after.against(&report_before));
/// # Ok(())
/// # }
/// ```
///
/// # Why a macro, and why the body is a plain block
///
/// A function would take the body as a closure, and a closure stops a `?`, a
/// `return` and an `.await` from reaching the function they were written in.
/// The body is expanded as it was written, so all three still mean what they
/// say.
///
/// # The `return` inside it
///
/// A window that could not be opened leaves the enclosing function, so this
/// can only be written inside one returning a `Result` whose error is reachable
/// by `From` from [`Reason`]. [`crate::AnyError`] is that type.
///
/// It is a `return` and not a `?`: a `?` here would leave the expansion an
/// expression of a type nothing has named, and `rustc` would find more than one
/// conversion that serves.
///
/// # What it does before the body
///
/// Asks the thread where its stack ends and reserves somewhere to put a copy
/// of it. Both are calls, both happen before the operation, and their frames
/// are inside the window the operation is about to write over — which is why
/// they can be calls at all.
///
/// They are also what stops the enclosing function from being a leaf. A leaf
/// may use the 128 bytes below the stack pointer without adjusting it, and
/// those bytes are the shallowest of the window.
#[macro_export]
macro_rules! forensics {
    ($body:block) => {{
        match $crate::open() {
            Ok(()) => {}
            // The `return` is the point, and it is explained above the macro.
            Err(why) => return Err(::core::convert::From::from(why)),
        }

        $body
    }};
}
