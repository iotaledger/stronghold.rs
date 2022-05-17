// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use runtime::{
    locked_memory::LockedMemory,
    memories::{
        buffer::Buffer,
        file_memory::FileMemory,
        noncontiguous_memory::{NCConfig::*, NonContiguousMemory, NC_DATA_SIZE},
        ram_memory::RamMemory,
    },
    utils::random_vec,
    DEBUG_MSG,
};

macro_rules! init {
    ($type:ident) => {{
        let data = random_vec(NC_DATA_SIZE);
        let lm = $type::alloc(&data, NC_DATA_SIZE);
        assert!(lm.is_ok());
        let lm = lm.unwrap();
        (lm, data, NC_DATA_SIZE)
    }};
}

macro_rules! init_nc {
    ($type:ident) => {{
        let data = random_vec(NC_DATA_SIZE);
        let lm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, $type);
        assert!(lm.is_ok());
        let lm = lm.unwrap();
        (lm, data, NC_DATA_SIZE)
    }};
}

macro_rules! init_and_test_unlock_update {
    ($type:ident) => {
        let (lm, data, size) = init!($type);
        test_unlock_and_update(lm, &data, size);
    };
}

macro_rules! init_and_test_clone {
    ($type:ident) => {
        let (lm, _, size) = init!($type);
        test_clone(lm, size);
    };
}

macro_rules! init_and_test_debug {
    ($type:ident) => {
        let (lm, _, _) = init!($type);
        assert_eq!(format!("{:?}", lm), DEBUG_MSG);
    };
}

#[test]
fn file_memory() {
    init_and_test_unlock_update!(FileMemory);
    init_and_test_clone!(FileMemory);
    init_and_test_debug!(FileMemory);
}

#[test]
fn ram_memory() {
    init_and_test_unlock_update!(RamMemory);
    init_and_test_clone!(RamMemory);
    init_and_test_debug!(RamMemory);
}

#[test]
fn noncontiguous_memory() {
    let (lm, data, size) = init_nc!(FullRam);
    test_unlock_and_update(lm, &data, size);
    let (lm, _, size) = init_nc!(FullRam);
    test_clone(lm, size);
    let (lm, _, _) = init_nc!(FullRam);
    assert_eq!(format!("{:?}", lm), DEBUG_MSG);

    let (lm, data, size) = init_nc!(RamAndFile);
    test_unlock_and_update(lm, &data, size);
    let (lm, _, size) = init_nc!(RamAndFile);
    test_clone(lm, size);
    let (lm, _, _) = init_nc!(RamAndFile);
    assert_eq!(format!("{:?}", lm), DEBUG_MSG);
}

// We test that the locked data corresponds to the origin data
// Then we update the locked data and check that it matches
fn test_unlock_and_update(lm: impl LockedMemory, data: &[u8], size: usize) {
    let buf = lm.unlock();
    assert!(buf.is_ok());
    let buf = buf.unwrap();
    assert_eq!((&*buf.borrow()), data);

    // Create new data
    let new_data = random_vec(size);

    // Update the LockedMemory with the new data
    let new_buf = Buffer::alloc(&new_data, size);
    let new_lm = lm.update(new_buf, size);
    assert!(new_lm.is_ok());
    let new_lm = new_lm.unwrap();

    // Check that new locked memory has the updated data
    let buf = new_lm.unlock();
    assert!(buf.is_ok());
    let buf = buf.unwrap();
    assert_ne!(&*buf.borrow(), data);
    assert_eq!(&*buf.borrow(), new_data);
}

// We test cloning, first check that clone has same value, and
// then check that locked memories are independent from each other
fn test_clone(lm: impl LockedMemory, size: usize) {
    // Clone
    let lm_clone = lm.clone();

    // Check that they contain the same values
    let buf = lm.unlock();
    let buf_clone = lm_clone.unlock();
    assert!(buf.is_ok());
    assert!(buf_clone.is_ok());
    let buf = buf.unwrap();
    let buf_clone = buf_clone.unwrap();
    assert_eq!(*buf.borrow(), *buf_clone.borrow());

    // drop(buf); // check, if locks are being released

    // Update the clone with a new value
    let new_data = random_vec(size);
    let new_buf = Buffer::alloc(&new_data, size);
    let lm_clone = lm_clone.update(new_buf, size);
    assert!(lm_clone.is_ok());
    let lm_clone = lm_clone.unwrap();

    // Check that the two locked memories have different values
    let buf = lm.unlock();
    let buf_clone = lm_clone.unlock();
    assert!(buf.is_ok());
    assert!(buf_clone.is_ok());
    let buf = buf.unwrap();
    let buf_clone = buf_clone.unwrap();
    assert_ne!(*buf.borrow(), *buf_clone.borrow());
}
