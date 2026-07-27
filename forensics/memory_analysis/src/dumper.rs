// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Self-contained memory dumper for forensic analysis.
//!
//! Writes the process's own writable memory and vector-register state to a
//! file, for offline analysis by the Python scripts under `scripts/`.
//!
//! ## Why not a core dump
//!
//! A core dump is produced by the kernel and routed by `kernel.core_pattern`,
//! which is a **global** sysctl — it is not namespaced per container. On a host
//! that pipes cores to `systemd-coredump` the file never appears where the lab
//! looks for it, and the lab has no way to fix that from the inside. Attaching
//! with `gcore` avoids the sysctl but needs `CAP_SYS_PTRACE`, which CI runners
//! do not necessarily grant.
//!
//! Dumping from inside the process needs no capability, no sysctl and no root,
//! so it behaves identically on a developer host, inside a container, and in
//! CI.
//!
//! ## What it captures
//!
//! | region | source |
//! |---|---|
//! | vector registers | the `xsave64` instruction |
//! | heap, stacks, anonymous maps | `/proc/self/maps` filtered to `rw`, read via `/proc/self/mem` |
//!
//! Registers matter as much as memory: a secret copied by glibc's `memcpy` on
//! an AVX-512 host lands in `ZMM16`-`ZMM31`, and those registers are almost
//! never touched by ordinary code, so the value survives there until the
//! process dies. No amount of zeroizing memory reaches it.
//!
//! ## Ordering
//!
//! [`capture_xsave`] runs first, before this module touches anything else.
//! `memcpy` and `memset` are themselves vectorized, so any work done before the
//! capture overwrites the very registers being measured.
//!
//! ## Allocation
//!
//! Nothing here allocates. Every buffer is a pre-reserved `static`, and the
//! output paths are supplied by the caller — built at startup, before any
//! secret exists. An allocation made at dump time could be served out of a heap
//! block that still holds a secret, overwriting the evidence before it is read.
//!
//! ## The output
//!
//! Two files. `<name>.bin` is the concatenated region contents; `<name>.idx`
//! names them:
//!
//! ```text
//! # file_offset length vaddr label
//! 0 988 0 REGISTERS/xsave
//! 988 21000 2740f000 [heap]
//! 21988 2000 7ffd1000 [stack]
//! ```
//!
//! Python resolves a hit's file offset against that, so a match reports as
//! `REGISTERS/xsave +0x5c0` or `[heap] +0x1a88` rather than a bare number. The
//! distinction is the finding: a hit in the heap is a buffer that was not
//! wiped, a hit in the registers is one that memory zeroization cannot reach.
//!
//! Lines labelled `DUMPER_SELF` cover this module's own buffers, which hold a
//! copy of whatever region was read last. Hits there are self-contamination and
//! the analyzer discards them.
//!
//! ## The output file is a secret
//!
//! It contains, by construction, everything the run was hunting for. It is
//! created `0600`. Keep it on tmpfs, delete it after analysis, and never
//! publish it as a CI artifact.

use core::arch::asm;
use core::fmt::Write as _;

/// Size of the `XSAVE` area. 2440 bytes on a current AVX-512 part; the extra
/// room covers wider future state components.
const XSAVE_LEN: usize = 4096;

/// `/proc/self/maps` is a few hundred lines even for a large process.
const MAPS_LEN: usize = 128 * 1024;

/// Chunk used to move region contents. Large enough that the syscall overhead
/// is irrelevant, small enough to stay out of the way.
const COPY_LEN: usize = 1024 * 1024;

const IDX_LEN: usize = 64 * 1024;
const PATH_LEN: usize = 4096;

#[repr(C, align(64))]
struct Aligned64<const N: usize>([u8; N]);

/// `xsave64` requires a 64-byte aligned destination.
static mut XSAVE_BUF: Aligned64<XSAVE_LEN> = Aligned64([0; XSAVE_LEN]);
static mut MAPS_BUF: [u8; MAPS_LEN] = [0; MAPS_LEN];
static mut COPY_BUF: [u8; COPY_LEN] = [0; COPY_LEN];
static mut IDX_BUF: [u8; IDX_LEN] = [0; IDX_LEN];
static mut PATH_BUF: [u8; PATH_LEN] = [0; PATH_LEN];

/// Whether [`capture_xsave`] has run. Dumping without it would silently produce
/// a register area full of zeroes, which reads as "clean" — the most dangerous
/// possible failure for this tool.
static mut XSAVE_CAPTURED: bool = false;

/// Errors are plain enough that a string is more useful than a type.
pub type DumpResult = Result<(), &'static str>;

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ REGISTERS                                                                  ║
// ╚════════════════════════════════════════════════════════════════════════════╝

/// Captures this thread's vector-register state into a static buffer.
///
/// Call it as the **first** thing after the code under test finishes, before
/// any I/O, formatting or allocation. Those all go through vectorized libc
/// routines that overwrite the registers being measured — a `memset` alone is
/// enough to zero out `Hi16_ZMM` and hide the finding.
///
/// `XSAVE` saves whichever components `XCR0` enables; passing an all-ones mask
/// asks for every one of them. It does not disturb the registers it reads.
///
/// Only the calling thread is captured. `XSAVE` has no cross-thread form, so on
/// a multi-threaded program each thread that handled secrets has to reach this
/// on its own, or the gap has to be stated.
#[inline(always)]
pub fn capture_xsave() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let buf = &raw mut XSAVE_BUF;
        asm!(
            "xsave64 [{buf}]",
            buf = in(reg) buf,
            in("eax") u32::MAX,
            in("edx") u32::MAX,
            options(nostack, preserves_flags),
        );
        XSAVE_CAPTURED = true;
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        // aarch64 has no XSAVE equivalent reachable from user space. The
        // register gap is real on that target and is left explicit rather than
        // papered over with a zero-filled buffer.
        XSAVE_CAPTURED = false;
    }
}

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ DUMP                                                                       ║
// ╚════════════════════════════════════════════════════════════════════════════╝

/// Writes the register state and every writable memory region to
/// `<stem>.bin`, with the region map in `<stem>.idx`.
///
/// `stem` must be supplied by the caller and built before the run touches any
/// secret, because constructing it here would allocate.
pub fn dump(stem: &str) -> DumpResult {
    if stem.len() + 8 >= PATH_LEN {
        return Err("dump path too long");
    }

    let bin_fd = open_write(stem, b".bin")?;
    let idx_fd = open_write(stem, b".idx")?;

    let mut idx = Cursor::new(unsafe { &mut *(&raw mut IDX_BUF) });
    let _ = writeln!(idx, "# file_offset length vaddr label");

    let mut written: u64 = 0;

    // Registers first in the file, so a hit at a low offset is immediately
    // recognizable even before the index is consulted.
    written += write_registers(bin_fd, &mut idx)?;

    let maps = read_maps()?;
    let mem_fd = open_read(c_path(b"/proc/self/mem\0"))?;

    for line in maps.split(|&b| b == b'\n') {
        let Some(region) = Region::parse(line) else {
            continue;
        };
        if !region.wanted() {
            continue;
        }
        match copy_region(mem_fd, bin_fd, &region) {
            // A region can vanish or refuse to be read between `maps` being
            // parsed and the `pread` landing; that is normal and not a failure
            // of the dump.
            0 => continue,
            n => {
                let _ = writeln!(
                    idx,
                    "{:x} {:x} {:x} {}",
                    written,
                    n,
                    region.start,
                    region.label()
                );
                written += n;
            }
        }
    }

    unsafe { libc::close(mem_fd) };

    write_self_ranges(&mut idx);

    let idx_bytes = idx.filled();
    write_all(idx_fd, idx_bytes)?;

    unsafe {
        libc::close(bin_fd);
        libc::close(idx_fd);
    }

    Ok(())
}

/// Emits the `XSAVE` area as the first region.
fn write_registers(fd: i32, idx: &mut Cursor<'_>) -> Result<u64, &'static str> {
    let captured = unsafe { XSAVE_CAPTURED };
    if !captured {
        // Recorded rather than silently skipped: an absent register area and a
        // clean register area look identical to the analyzer otherwise.
        let _ = writeln!(idx, "# WARNING: capture_xsave() was never called");
        return Ok(0);
    }

    let buf = unsafe { &(*(&raw const XSAVE_BUF)).0 };
    write_all(fd, buf)?;
    let _ = writeln!(idx, "0 {:x} 0 REGISTERS/xsave", buf.len());
    Ok(buf.len() as u64)
}

/// Records where this module's own buffers live, so the analyzer can discard
/// hits that are just the dumper holding a copy of what it read.
fn write_self_ranges(idx: &mut Cursor<'_>) {
    let ranges: [(&str, usize, usize); 3] = [
        ("COPY_BUF", (&raw const COPY_BUF) as usize, COPY_LEN),
        ("MAPS_BUF", (&raw const MAPS_BUF) as usize, MAPS_LEN),
        ("IDX_BUF", (&raw const IDX_BUF) as usize, IDX_LEN),
    ];
    for (name, addr, len) in ranges {
        let _ = writeln!(idx, "# DUMPER_SELF {:x} {:x} {}", addr, len, name);
    }
}

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ REGIONS                                                                    ║
// ╚════════════════════════════════════════════════════════════════════════════╝

struct Region<'a> {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    path: &'a [u8],
}

impl<'a> Region<'a> {
    /// Parses one `/proc/self/maps` line:
    /// `7fb3bce00000-7fb3bce28000 rw-p 00000000 fe:00 87847500  /lib/libc.so.6`
    fn parse(line: &'a [u8]) -> Option<Self> {
        let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
        let range = fields.next()?;
        let perms = fields.next()?;

        let dash = range.iter().position(|&b| b == b'-')?;
        let start = parse_hex(&range[..dash])?;
        let end = parse_hex(&range[dash + 1..])?;

        // Skip offset, dev and inode; whatever is left is the path.
        let path = fields.nth(3).unwrap_or(b"");

        Some(Self {
            start,
            end,
            readable: perms.first() == Some(&b'r'),
            writable: perms.get(1) == Some(&b'w'),
            path,
        })
    }

    /// Only writable memory can hold a secret produced at runtime. Read-only
    /// and executable maps are file-backed pages of the binary and its
    /// libraries — constants, not runtime state — and skipping them removes
    /// most of the dump's size along with most of its noise.
    fn wanted(&self) -> bool {
        if !(self.readable && self.writable) {
            return false;
        }
        // Kernel-provided maps: reading them is either meaningless or fatal.
        if matches!(self.path, b"[vvar]" | b"[vdso]" | b"[vsyscall]") {
            return false;
        }
        // Device mappings can have side effects on read.
        if self.path.starts_with(b"/dev/") {
            return false;
        }
        true
    }

    fn label(&self) -> &str {
        if self.path.is_empty() {
            "anon"
        } else {
            core::str::from_utf8(self.path).unwrap_or("?")
        }
    }
}

/// Copies one region into the output, returning how many bytes made it.
///
/// `pread` is mandatory here: `/proc/self/mem` is the whole address space, with
/// enormous unmapped gaps between regions, so a sequential read is meaningless.
/// A region can still refuse to be read — the mapping may be gone, or backed by
/// something the kernel will not hand over — and that is reported as zero bytes
/// rather than aborting the dump.
fn copy_region(mem_fd: i32, out_fd: i32, region: &Region<'_>) -> u64 {
    let buf = unsafe { &mut *(&raw mut COPY_BUF) };
    let mut done: u64 = 0;
    let total = region.end - region.start;

    while done < total {
        let want = core::cmp::min(COPY_LEN as u64, total - done) as usize;
        let got = unsafe {
            libc::pread(
                mem_fd,
                buf.as_mut_ptr().cast(),
                want,
                (region.start + done) as libc::off_t,
            )
        };
        if got <= 0 {
            break;
        }
        let got = got as usize;
        if write_all(out_fd, &buf[..got]).is_err() {
            break;
        }
        done += got as u64;
    }

    done
}

fn read_maps() -> Result<&'static [u8], &'static str> {
    let fd = open_read(c_path(b"/proc/self/maps\0"))?;
    let buf = unsafe { &mut *(&raw mut MAPS_BUF) };
    let mut filled = 0usize;

    // `/proc` files report size 0 and must be read until EOF.
    loop {
        if filled == buf.len() {
            return Err("maps buffer too small");
        }
        let got = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
            )
        };
        if got <= 0 {
            break;
        }
        filled += got as usize;
    }

    unsafe { libc::close(fd) };
    Ok(&buf[..filled])
}

// ╔════════════════════════════════════════════════════════════════════════════╗
// ║ PRIMITIVES                                                                 ║
// ╚════════════════════════════════════════════════════════════════════════════╝

/// Borrows the shared path buffer as a NUL-terminated C string.
fn c_path(bytes: &[u8]) -> *const libc::c_char {
    let buf = unsafe { &mut *(&raw mut PATH_BUF) };
    buf[..bytes.len()].copy_from_slice(bytes);
    buf.as_ptr().cast()
}

fn open_read(path: *const libc::c_char) -> Result<i32, &'static str> {
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 { Err("open failed") } else { Ok(fd) }
}

/// Creates `<stem><suffix>` with mode `0600` — the file holds the secrets the
/// run is hunting for.
fn open_write(stem: &str, suffix: &[u8]) -> Result<i32, &'static str> {
    let buf = unsafe { &mut *(&raw mut PATH_BUF) };
    let n = stem.len();
    buf[..n].copy_from_slice(stem.as_bytes());
    buf[n..n + suffix.len()].copy_from_slice(suffix);
    buf[n + suffix.len()] = 0;

    let fd = unsafe {
        libc::open(
            buf.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600 as libc::c_int,
        )
    };
    if fd < 0 { Err("create failed") } else { Ok(fd) }
}

/// `write` is one syscall and may consume only part of the buffer, reporting
/// the short count as success. Looping is the only correct use.
fn write_all(fd: i32, mut buf: &[u8]) -> DumpResult {
    while !buf.is_empty() {
        let got = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if got <= 0 {
            return Err("write failed");
        }
        buf = &buf[got as usize..];
    }
    Ok(())
}

fn parse_hex(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        acc = acc.checked_mul(16)?.checked_add(digit as u64)?;
    }
    Some(acc)
}

/// A `core::fmt::Write` over a fixed slice, so the index can be formatted
/// without allocating.
struct Cursor<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn filled(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}
