pub enum StatusMessage {
    Ok,
    Busy,
    Error,
}

pub enum StrongholdFlags {
    Readable(bool),
}

pub enum VaultFlags {}

pub fn index_of_unchecked<T>(slice: &[T], item: &T) -> usize {
    if ::std::mem::size_of::<T>() == 0 {
        return 0; // do what you will with this case
    }
    (item as *const _ as usize - slice.as_ptr() as usize) / std::mem::size_of::<T>()
}
