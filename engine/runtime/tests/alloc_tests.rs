// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ptr::NonNull;

use runtime::{
    memories::frag::{Frag, FragStrategy},
    MemoryError,
};

#[derive(PartialEq, Debug, Clone)]
struct TestStruct {
    id: usize,
    name: String,
}

impl Default for TestStruct {
    fn default() -> Self {
        Self {
            id: 123456789,
            name: "Some heap allocated value".to_owned(),
        }
    }
}

/// this fails under windows
#[test]
fn test_allocate_direct() {
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc(FragStrategy::Direct)).is_ok());
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc2(FragStrategy::Direct, 0xFFFF)).is_ok());
}

#[test]
fn test_allocate_map() {
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc(FragStrategy::Map)).is_ok());
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc2(FragStrategy::Map, 0xFFFF)).is_ok());
}

fn test_allocate<T, F>(allocator: F) -> Result<(), MemoryError>
where
    T: Default,
    F: Fn() -> Option<(NonNull<T>, NonNull<T>)>,
{
    let min_distance = 0xFFFF;
    let result = allocator();
    assert!(result.is_some());
    let (a, b) = result.unwrap();

    unsafe {
        assert!(distance(a.as_ref(), b.as_ref()) > min_distance);
    }

    Ok(())
}

// ----------------------------------------------------------------------------

/// Calculates the distance between two pointers
fn distance<T>(a: &T, b: &T) -> usize {
    let a = a as *const T as usize;
    let b = b as *const T as usize;

    a.abs_diff(b)
}
