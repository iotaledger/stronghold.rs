// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use new_runtime::{
    locked_memory::LockedMemory,
    memories::{
        buffer::Buffer,
        file_memory::FileMemory,
        noncontiguous_memory::{NCConfig::*, NonContiguousMemory, NC_DATA_SIZE},
        ram_memory::RamMemory,
    },
    utils::random_vec,
};

#[test]
fn serialize_deserialize_ok() {
    let data = random_vec(NC_DATA_SIZE);

    // Buffers
    let buf = Buffer::alloc(&data, NC_DATA_SIZE);
    let serialized = serde_json::to_string(&buf).unwrap();
    let buf: Buffer<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(&*buf.borrow(), data);

    // RamMemory
    let ram = RamMemory::alloc(&data, NC_DATA_SIZE).unwrap();
    let serialized = serde_json::to_string(&ram).unwrap();
    let ram: RamMemory = serde_json::from_str(&serialized).unwrap();
    let buf = ram.unlock().unwrap();
    assert_eq!(&*buf.borrow(), data);

    // FileMemory
    let fmem = FileMemory::alloc(&data, NC_DATA_SIZE).unwrap();
    let serialized = serde_json::to_string(&fmem).unwrap();
    let fmem: FileMemory = serde_json::from_str(&serialized).unwrap();
    let buf = fmem.unlock().unwrap();
    assert_eq!(&*buf.borrow(), data);

    // NonContiguousMemory
    let nc = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, FullRam).unwrap();
    let serialized = serde_json::to_string(&nc).unwrap();
    let nc: NonContiguousMemory = serde_json::from_str(&serialized).unwrap();
    let buf = nc.unlock().unwrap();
    assert_eq!(&*buf.borrow(), data);
}

#[test]
// For backward compatibility all the types should return same kind of data
fn serialized_data_equal() {
    let data = random_vec(NC_DATA_SIZE);
    let buf = Buffer::alloc(&data, NC_DATA_SIZE);
    let ser_buf = serde_json::to_string(&buf).unwrap();
    let ram = RamMemory::alloc(&data, NC_DATA_SIZE).unwrap();
    let ser_ram = serde_json::to_string(&ram).unwrap();
    let fmem = FileMemory::alloc(&data, NC_DATA_SIZE).unwrap();
    let ser_fmem = serde_json::to_string(&fmem).unwrap();
    let nc = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, FullRam).unwrap();
    let ser_nc = serde_json::to_string(&nc).unwrap();

    assert_eq!(ser_buf, ser_ram);
    assert_eq!(ser_buf, ser_fmem);
    assert_eq!(ser_buf, ser_ram);
    assert_eq!(ser_buf, ser_nc);
}
