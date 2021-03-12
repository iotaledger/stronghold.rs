use core::alloc::{GlobalAlloc, Layout};

/// A Zeroing Allocator which wraps the standard memory allocator.  This allocator zeroes out memory when it is dropped.
pub struct ZeroingAlloc<T: GlobalAlloc>(pub T);

unsafe impl<T> GlobalAlloc for ZeroingAlloc<T>
where
    T: GlobalAlloc,
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    /// Zero the memory before deallocation.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        zero(ptr, layout.size());
        #[cfg(not(test))]
        self.0.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }
}

/// Zeroes out memory at pointer in place based on the given size.
unsafe fn zero(ptr: *mut u8, size: usize) {
    for i in 0..size {
        core::ptr::write_volatile(ptr.offset(i as isize), 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod test {
    use super::*;

    extern crate std;

    use quickcheck::quickcheck;
    use std::vec::Vec;

    #[global_allocator]
    static ALLOC: ZeroingAlloc<std::alloc::System> = ZeroingAlloc(std::alloc::System);

    #[test]
    fn test_vec() {
        use std::vec::Vec;

        let mut a = Vec::with_capacity(2);

        a.push(222);
        a.push(173);

        let ptr1: *const u8 = &a[0];

        a.push(190);
        a.push(239);

        let ptr2: *const u8 = &a[0];

        assert_eq!(&[222, 173, 190, 239], &a[..]);

        assert_eq!(unsafe { ptr1.as_ref() }, Some(&0));
        drop(a);
        assert_eq!(unsafe { ptr2.as_ref() }, Some(&0));
    }

    quickcheck! {
        fn prop(v1: Vec<u8>, v2: Vec<u8>) -> bool {
            let mut v1 = v1;
            if v1.len() == 0 || v2.len() == 0 {
                return true;
            }
            let ptr1: *const u8 = &v1[0];
            v1.shrink_to_fit();
            let ptr2: *const u8 = &v2[0];
            v1.extend(v2);
            let ptr3: *const u8 = &v1[0];
            assert_eq!(unsafe { ptr1.as_ref() }, Some(&0));
            assert_eq!(unsafe { ptr2.as_ref() }, Some(&0));
            drop(v1);
            assert_eq!(unsafe { ptr3.as_ref() }, Some(&0));
            true
        }
    }
}
