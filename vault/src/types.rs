use std::mem;

pub use transactions::{DataTransaction, SealedPayload, SealedTransaction};

pub mod transactions;
pub mod utils;

// a view over raw data.
pub trait AsView<T: Sized>: AsRef<[u8]> {
    // creates a view
    fn view(&self) -> &T {
        // get the bytes
        let bytes = self.as_ref();
        // validate the bytes
        assert!(
            mem::size_of::<T>() <= bytes.len(),
            "Can't create view over this memory"
        );
        // get the pointer
        let bytes = bytes.as_ptr();
        // validate alignment
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );
        // cast the pointer
        unsafe { bytes.cast::<T>().as_ref() }.unwrap()
    }
}

// a mutable view over raw data.
pub trait AsViewMut<T: Sized>: AsMut<[u8]> {
    // creates a mutable view
    fn view_mut(&mut self) -> &mut T {
        // get bytes
        let bytes = self.as_mut();
        // validate bytes
        assert!(
            mem::size_of::<T>() <= bytes.len(),
            "Can't create view over this memory"
        );
        // get mute pointer
        let bytes = bytes.as_mut_ptr();
        // validate alignment
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );

        // cast mutable pointer
        unsafe { bytes.cast::<T>().as_mut() }.unwrap()
    }
}
