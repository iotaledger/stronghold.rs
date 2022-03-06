// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use new_runtime::{
    crypto_utils::{
        crypto_box::{BoxProvider, Key},
        provider::Provider,
    },
    locked_memory::{Lock, LockedMemory, NCMemory::*},
    memories::{
        buffer::Buffer,
        file_memory::FileMemory,
        noncontiguous_memory::{NonContiguousMemory, NC_DATA_SIZE},
        ram_memory::RamMemory,
    },
};

macro_rules! init_and_launch_test {
    ($type:ident,$lock:expr) => {
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let lock = $lock;
        let lm = $type::<Provider>::alloc(&data, NC_DATA_SIZE, lock.clone());
        assert!(lm.is_ok());
        let lm = lm.unwrap();
        test_unlock_and_update(lm, &data, NC_DATA_SIZE, lock);
    };
}

#[test]
fn file_memory_plain() {
    init_and_launch_test!(FileMemory, Lock::Plain);
}

#[test]
fn file_memory_encryption() {
    init_and_launch_test!(FileMemory, Lock::Encryption(Key::random()));
}

#[test]
fn ram_memory_plain() {
    init_and_launch_test!(RamMemory, Lock::Plain);
}

#[test]
fn ram_memory_encryption() {
    init_and_launch_test!(RamMemory, Lock::Encryption(Key::random()));
}

#[test]
fn noncontiguous_memory_ram() {
    init_and_launch_test!(NonContiguousMemory, Lock::NonContiguous(NCRam));
}

#[test]
fn noncontiguous_memory_ram_and_file() {
    init_and_launch_test!(NonContiguousMemory, Lock::NonContiguous(NCRamFile));
}

// We test that the locked data corresponds to the origin data
// Then we update the locked data and check that it matches
fn test_unlock_and_update(lm: impl LockedMemory<Provider>, data: &[u8], size: usize, lock: Lock<Provider>) {
    let buf = lm.unlock(lock.clone());
    assert!(buf.is_ok());
    let buf = buf.unwrap();
    assert_eq!((&*buf.borrow()), data);

    // Create new data
    let new_data = Provider::random_vec(NC_DATA_SIZE).unwrap();

    // Update the LockedMemory with the new data
    let new_buf = Buffer::alloc(&new_data, size);
    let new_lm = lm.update(new_buf, size, lock.clone());
    assert!(new_lm.is_ok());
    let new_lm = new_lm.unwrap();

    // Check that new locked memory has the updated data
    let buf = new_lm.unlock(lock);
    assert!(buf.is_ok());
    let buf = buf.unwrap();
    assert_ne!(&*buf.borrow(), data);
    assert_eq!(&*buf.borrow(), new_data);
}
