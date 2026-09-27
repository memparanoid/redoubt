// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for redoubt-buffer.

#[cfg(target_os = "linux")]
fn block_syscall(name: &str) {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).expect("Failed to create filter");
    filter
        .add_rule(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name(name).expect("Failed to from_name(..)"),
        )
        .expect("Failed to add rule");
    filter.load().expect("Failed to load seccomp filter");
}

#[cfg(target_os = "linux")]
pub fn block_mlock() {
    block_syscall("mlock");
}

#[cfg(target_os = "linux")]
pub fn block_mprotect() {
    block_syscall("mprotect");
}

#[cfg(target_os = "linux")]
pub fn block_madvise() {
    block_syscall("madvise");
}

#[cfg(target_os = "linux")]
pub struct Region {
    pub permissions: String,
    pub locked_kb: u64,
    pub vm_flags: Vec<String>,
}

#[cfg(target_os = "linux")]
pub fn region(address: usize) -> Result<Option<Region>, Box<dyn std::error::Error>> {
    let smaps = std::fs::read_to_string("/proc/self/smaps")?;

    let mut found: Option<Region> = None;

    for line in smaps.lines() {
        if let Some((from, to, permissions)) = mapping(line) {
            if found.is_some() {
                break;
            }

            if from <= address && address < to {
                found = Some(Region {
                    permissions: permissions.to_owned(),
                    locked_kb: 0,
                    vm_flags: Vec::new(),
                });
            }

            continue;
        }

        let Some(region) = found.as_mut() else {
            continue;
        };

        if let Some(kb) = line.strip_prefix("Locked:") {
            region.locked_kb = kb.trim().trim_end_matches("kB").trim().parse()?;
        }

        if let Some(flags) = line.strip_prefix("VmFlags:") {
            region.vm_flags = flags.split_whitespace().map(str::to_owned).collect();
        }
    }

    Ok(found)
}

#[cfg(target_os = "linux")]
fn mapping(line: &str) -> Option<(usize, usize, &str)> {
    let mut fields = line.split_whitespace();

    let (from, to) = fields.next()?.split_once('-')?;
    let permissions = fields.next()?;

    let from = usize::from_str_radix(from, 16).ok()?;
    let to = usize::from_str_radix(to, 16).ok()?;

    Some((from, to, permissions))
}

#[cfg(target_os = "linux")]
pub fn page_kb() -> u64 {
    // SAFETY: it reads a number the C library holds, takes no pointer and
    // writes nowhere.
    (unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64) / 1024
}
