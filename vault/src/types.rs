use std::mem;

pub mod commits;
pub mod utils;

pub trait AsView<T: Sized>: AsRef<[u8]> {
    fn view(&self) -> &T {
        let bytes = self.as_ref();

        assert!(
            mem::size_of::<T>() <= bytes.len(),
            "Can't create view over this memory"
        );

        let bytes = bytes.as_ptr();
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );
        unsafe { bytes.cast::<T>().as_ref() }.unwrap()
    }
}

pub trait AsViewMut<T: Sized>: AsMut<[u8]> {
    fn view_mut(&mut self) -> &mut T {
        let bytes = self.as_mut();

        assert!(
            mem::size_of::<T>() <= bytes.len(),
            "Can't create view over this memory"
        );

        let bytes = bytes.as_mut_ptr();
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );
        unsafe { bytes.cast::<T>().as_mut() }.unwrap()
    }
}
