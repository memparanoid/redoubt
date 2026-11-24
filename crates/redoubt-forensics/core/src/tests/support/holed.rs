// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use core::ptr;

/// Pages of this process, readable and writable, with one of them unmapped.
pub(crate) struct Holed {
    base: *mut u8,
    page: usize,
    pages: usize,
    hole: usize,
}

impl Holed {
    /// `pages` pages, page `hole` among them unmapped.
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

        // SAFETY: one page of the mapping just made, `hole` being below `pages`.
        let unmapped = unsafe { libc::munmap(base.add(hole * page).cast(), page) };

        assert_eq!(unmapped, 0, "page {hole} could not be unmapped");

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

    /// The bytes, at the start of a page that is mapped.
    pub(crate) fn plant(&self, page: usize, bytes: &[u8]) {
        assert!(page < self.pages, "page {page} of {}", self.pages);
        assert_ne!(page, self.hole, "page {page} is the hole");
        assert!(bytes.len() <= self.page, "{} bytes in a page", bytes.len());

        // SAFETY: inside a mapped page of the mapping, as just asserted.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.add(page * self.page), bytes.len())
        };
    }
}

impl Drop for Holed {
    fn drop(&mut self) {
        let after = self.hole + 1;

        // Never the hole itself: once unmapped it is anybody's, and an allocator
        // that maps its own pages may have been handed it since.
        //
        // SAFETY: the pages below the hole, mapped by `new` and read by nothing
        // after this. With the hole first there are none, and a length of zero
        // is refused without touching anything.
        unsafe { libc::munmap(self.base.cast(), self.hole * self.page) };
        // SAFETY: the pages above the hole, mapped by `new` and read by nothing
        // after this.
        unsafe {
            libc::munmap(
                self.base.add(after * self.page).cast(),
                (self.pages - after) * self.page,
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::Holed;

    /// Whether the kernel has a page at that address, asked of `mincore`.
    fn mapped(at: u64) -> bool {
        let mut resident = 0_u8;

        // SAFETY: one page at a page-aligned address, its answer written into a
        // local byte.
        unsafe { libc::mincore(at as *mut libc::c_void, 1, &mut resident) == 0 }
    }

    // ========================================================================
    // Holed::new
    // ========================================================================

    #[test]
    fn test_new_unmaps_the_hole_and_keeps_every_other_page() {
        let holed = Holed::new(3, 1);

        assert!(mapped(holed.at(0)));
        assert!(!mapped(holed.at(1)));
        assert!(mapped(holed.at(2)));
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

    // ========================================================================
    // Holed::drop
    // ========================================================================

    #[test]
    fn test_drop_leaves_a_page_mapped_into_the_hole_since() {
        let holed = Holed::new(3, 1);
        let hole = holed.at(1);

        // SAFETY: one page at the hole's address, which nothing maps, and
        // `MAP_FIXED_NOREPLACE` refuses rather than replace what might.
        let since = unsafe {
            libc::mmap(
                hole as *mut libc::c_void,
                holed.page(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };

        assert_eq!(since as u64, hole, "no page could be mapped into the hole");

        let page = holed.page();

        drop(holed);

        let kept = mapped(hole);

        // SAFETY: the page this test mapped, read by nothing after this.
        unsafe { libc::munmap(since, page) };

        assert!(kept, "the drop unmapped a page that was not the mapping's");
    }
}
