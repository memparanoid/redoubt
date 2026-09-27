// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

//! Test utilities for redoubt-buffer.

#[cfg(target_os = "linux")]
pub struct Region {
    pub permissions: String,
    pub locked_kb: u64,
    pub vm_flags: Vec<String>,
}

#[cfg(target_os = "linux")]
const SMAPS_ROOM: usize = 1 << 20;

/// `/proc/self/smaps` opened, and the room it is read into, both made before
/// what is measured, so the read allocates nothing.
///
/// An allocation after a `munmap` may be handed the hole it left (musl's
/// allocator maps its memory, and the kernel reuses the highest free range),
/// and then `smaps` shows the reader's own buffer where the page was.
#[cfg(target_os = "linux")]
pub struct Smaps {
    file: std::fs::File,
    text: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl Smaps {
    pub fn open() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            file: std::fs::File::open("/proc/self/smaps")?,
            text: vec![0_u8; SMAPS_ROOM],
        })
    }

    pub fn region(&mut self, address: usize) -> Result<Option<Region>, Box<dyn std::error::Error>> {
        use std::io::Read;

        let mut len = 0;

        loop {
            let read = self.file.read(&mut self.text[len..])?;

            if read == 0 {
                break;
            }

            len += read;

            if len == self.text.len() {
                return Err("smaps did not fit in the room made for it".into());
            }
        }

        region_in(std::str::from_utf8(&self.text[..len])?, address)
    }
}

#[cfg(target_os = "linux")]
pub fn region(address: usize) -> Result<Option<Region>, Box<dyn std::error::Error>> {
    Smaps::open()?.region(address)
}

#[cfg(target_os = "linux")]
fn region_in(smaps: &str, address: usize) -> Result<Option<Region>, Box<dyn std::error::Error>> {
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
