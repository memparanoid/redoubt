// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ptr;

/// Pages of this process, readable and writable, with one of them still mapped
/// and refusing every read.
pub(crate) struct Holed {
    base: *mut u8,
    page: usize,
    pages: usize,
    hole: usize,
}

impl Holed {
    /// `pages` pages, page `hole` among them past the end of an empty file.
    ///
    /// Mapped over rather than unmapped: a page given back is anybody's, and an
    /// allocator that maps its own pages takes it before the test looks.
    pub(crate) fn new(pages: usize, hole: usize) -> Self {
        assert!(hole < pages, "the hole is page {hole} of {pages}");

        // SAFETY: a query of a constant the kernel answers for every process.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // SAFETY: an anonymous private mapping at an address of the kernel's
        // choosing, touching nothing that exists.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                pages * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        assert_ne!(base, libc::MAP_FAILED, "no mapping to make a hole in");

        let base = base.cast::<u8>();

        // SAFETY: a name the call reads and does not keep, terminated.
        let empty = unsafe { libc::memfd_create(c"holed".as_ptr(), libc::MFD_CLOEXEC) };

        assert!(empty >= 0, "no empty file to map the hole from");

        // SAFETY: one page of the mapping just made, `hole` being below `pages`,
        // replaced in place: `MAP_FIXED` leaves no moment in which it is free.
        let mapped = unsafe {
            libc::mmap(
                base.add(hole * page).cast(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                empty,
                0,
            )
        };

        // SAFETY: the descriptor made above; the mapping keeps the file alive.
        unsafe { libc::close(empty) };

        assert_ne!(
            mapped,
            libc::MAP_FAILED,
            "page {hole} could not be mapped over"
        );

        Self {
            base,
            page,
            pages,
            hole,
        }
    }

    /// The size of a page, as the kernel made the mapping in.
    pub(crate) fn page(&self) -> usize {
        self.page
    }

    /// The whole range, the hole included, as a sweep is handed a mapping.
    pub(crate) fn span(&self) -> (u64, u64) {
        let from = self.base as u64;

        (from, from + (self.pages * self.page) as u64)
    }

    /// The address page `page` starts at.
    pub(crate) fn at(&self, page: usize) -> u64 {
        self.base as u64 + (page * self.page) as u64
    }

    /// The bytes, at the start of a page that is not the hole.
    pub(crate) fn plant(&self, page: usize, bytes: &[u8]) {
        assert!(page < self.pages, "page {page} of {}", self.pages);
        assert_ne!(page, self.hole, "page {page} is the hole");
        assert!(bytes.len() <= self.page, "{} bytes in a page", bytes.len());

        // SAFETY: inside a page of the anonymous mapping, as just asserted.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.add(page * self.page), bytes.len())
        };
    }
}

impl Drop for Holed {
    fn drop(&mut self) {
        // SAFETY: the whole range `new` mapped, the hole included, read by
        // nothing after this.
        unsafe { libc::munmap(self.base.cast(), self.pages * self.page) };
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use super::Holed;

    /// Whether the kernel has a page at that address, asked of `mincore`.
    fn mapped(at: u64) -> bool {
        let mut resident = 0_u8;

        // SAFETY: one page at a page-aligned address, its answer written into a
        // local byte.
        unsafe { libc::mincore(at as *mut libc::c_void, 1, &mut resident) == 0 }
    }

    /// Whether `/proc/self/mem` hands over the byte at that address.
    fn readable(at: u64) -> bool {
        let mem = File::open("/proc/self/mem")
            .expect("this process should be able to open its own memory");
        let mut byte = [0_u8; 1];

        mem.read_at(&mut byte, at).is_ok_and(|got| got == 1)
    }

    // ========================================================================
    // Holed::new
    // ========================================================================

    #[test]
    fn test_new_keeps_the_hole_mapped() {
        let holed = Holed::new(3, 1);

        assert!(mapped(holed.at(0)));
        assert!(mapped(holed.at(1)));
        assert!(mapped(holed.at(2)));
    }

    #[test]
    fn test_new_leaves_the_hole_alone_refusing_a_read() {
        let holed = Holed::new(3, 1);

        assert!(readable(holed.at(0)));
        assert!(!readable(holed.at(1)));
        assert!(readable(holed.at(2)));
    }

    // ========================================================================
    // Holed::span
    // ========================================================================

    #[test]
    fn test_span_runs_from_the_first_page_to_past_the_last() {
        let holed = Holed::new(3, 1);

        assert_eq!(
            holed.span(),
            (holed.at(0), holed.at(0) + 3 * holed.page() as u64)
        );
    }

    // ========================================================================
    // Holed::at
    // ========================================================================

    #[test]
    fn test_at_is_a_page_apart_from_one_page_to_the_next() {
        let holed = Holed::new(3, 0);

        assert_eq!(holed.at(2) - holed.at(1), holed.page() as u64);
        assert_eq!(holed.at(1) - holed.at(0), holed.page() as u64);
    }

    // ========================================================================
    // Holed::plant
    // ========================================================================

    #[test]
    fn test_plant_writes_at_the_start_of_its_page() {
        let holed = Holed::new(2, 0);

        holed.plant(1, &[0x6C, 0x93, 0x2A]);

        // SAFETY: the first three bytes of page 1, mapped and just written.
        let planted = unsafe { core::slice::from_raw_parts(holed.at(1) as *const u8, 3) };

        assert_eq!(planted, [0x6C, 0x93, 0x2A]);
    }

    #[test]
    #[should_panic(expected = "page 2 of 2")]
    fn test_plant_panics_on_a_page_past_the_mapping() {
        let holed = Holed::new(2, 0);

        holed.plant(2, &[0x6C]);

        unreachable!("a page past the mapping was planted: {:#x}", holed.at(2));
    }

    #[test]
    #[should_panic(expected = "page 0 is the hole")]
    fn test_plant_panics_on_the_hole() {
        let holed = Holed::new(2, 0);

        holed.plant(0, &[0x6C]);

        unreachable!("the hole was planted: {:#x}", holed.at(0));
    }
}
