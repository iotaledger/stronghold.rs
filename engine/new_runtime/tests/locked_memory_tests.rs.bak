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
    DEBUG_MSG,
};

macro_rules! init {
    ($type:ident,$lock:expr) => {{
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let lock = $lock;
        let lm = $type::<Provider>::alloc(&data, NC_DATA_SIZE, lock.clone());
        assert!(lm.is_ok());
        let lm = lm.unwrap();
        (lm, data, NC_DATA_SIZE, lock)
    }};
}

macro_rules! init_and_test_unlock_update {
    ($type:ident,$lock:expr) => {
        let (lm, data, size, lock) = init!($type, $lock);
        test_unlock_and_update(lm, &data, size, lock);
    };
}

macro_rules! init_and_test_clone {
    ($type:ident,$lock:expr) => {
        let (lm, _, size, lock) = init!($type, $lock);
        test_clone(lm, size, lock);
    };
}

macro_rules! init_and_test_debug {
    ($type:ident,$lock:expr) => {
        let (lm, _, _, _) = init!($type, $lock);
        assert_eq!(format!("{:?}", lm), DEBUG_MSG);
    };
}

// Check that certain memory types are not compatible with certain
// locks. For example:
// - RamMemory with NC lock
// - FileMemory with NC lock
// - NonContiguousMemory with anything else than NC lock
macro_rules! check_illegal_lock {
    ($type:ident,$lock:expr) => {
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let lock = $lock;
        let lm = $type::<Provider>::alloc(&data, NC_DATA_SIZE, lock.clone());
        assert!(lm.is_err());
    };
}

#[test]
fn file_memory() {
    init_and_test_unlock_update!(FileMemory, Lock::Plain);
    init_and_test_unlock_update!(FileMemory, Lock::Encryption(Key::random()));
    init_and_test_clone!(FileMemory, Lock::Plain);
    init_and_test_clone!(FileMemory, Lock::Encryption(Key::random()));
    init_and_test_debug!(FileMemory, Lock::Plain);
    init_and_test_debug!(FileMemory, Lock::Encryption(Key::random()));
    check_illegal_lock!(FileMemory, Lock::NonContiguous(NCRam));
    check_illegal_lock!(FileMemory, Lock::NonContiguous(NCRamFile));
}

#[test]
fn ram_memory() {
    init_and_test_unlock_update!(RamMemory, Lock::Plain);
    init_and_test_unlock_update!(RamMemory, Lock::Encryption(Key::random()));
    init_and_test_clone!(RamMemory, Lock::Plain);
    init_and_test_clone!(RamMemory, Lock::Encryption(Key::random()));
    init_and_test_debug!(RamMemory, Lock::Plain);
    init_and_test_debug!(RamMemory, Lock::Encryption(Key::random()));
    check_illegal_lock!(RamMemory, Lock::NonContiguous(NCRam));
    check_illegal_lock!(RamMemory, Lock::NonContiguous(NCRamFile));
}

#[test]
fn noncontiguous_memory() {
    init_and_test_unlock_update!(NonContiguousMemory, Lock::NonContiguous(NCRam));
    init_and_test_unlock_update!(NonContiguousMemory, Lock::NonContiguous(NCRamFile));
    init_and_test_clone!(NonContiguousMemory, Lock::NonContiguous(NCRam));
    init_and_test_clone!(NonContiguousMemory, Lock::NonContiguous(NCRamFile));
    init_and_test_debug!(NonContiguousMemory, Lock::NonContiguous(NCRam));
    init_and_test_debug!(NonContiguousMemory, Lock::NonContiguous(NCRamFile));
    check_illegal_lock!(NonContiguousMemory, Lock::Plain);
    check_illegal_lock!(NonContiguousMemory, Lock::Encryption(Key::random()));
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

// We test cloning, first check that clone has same value, and
// then check that locked memories are independent from each other
fn test_clone(lm: impl LockedMemory<Provider>, size: usize, lock: Lock<Provider>) {
    // Clone
    let lm_clone = lm.clone();

    // Check that they contain the same values
    let buf = lm.unlock(lock.clone());
    let buf_clone = lm_clone.unlock(lock.clone());
    assert!(buf.is_ok());
    assert!(buf_clone.is_ok());
    let buf = buf.unwrap();
    let buf_clone = buf_clone.unwrap();
    assert_eq!(*buf.borrow(), *buf_clone.borrow());

    // Update the clone with a new value
    let new_data = Provider::random_vec(NC_DATA_SIZE).unwrap();
    let new_buf = Buffer::alloc(&new_data, size);
    let lm_clone = lm_clone.update(new_buf, size, lock.clone());
    assert!(lm_clone.is_ok());
    let lm_clone = lm_clone.unwrap();

    // Check that the two locked memories have different values
    let buf = lm.unlock(lock.clone());
    let buf_clone = lm_clone.unlock(lock);
    assert!(buf.is_ok());
    assert!(buf_clone.is_ok());
    let buf = buf.unwrap();
    let buf_clone = buf_clone.unwrap();
    assert_ne!(*buf.borrow(), *buf_clone.borrow());
}
