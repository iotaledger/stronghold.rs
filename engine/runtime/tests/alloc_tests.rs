// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use log::*;

use runtime::{
    memories::frag::{Frag, FragStrategy},
    MemoryError,
};
use std::fmt::Debug;

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

#[test]
fn test_allocate_direct() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter(None, log::LevelFilter::Info)
        .try_init();

    info!("Test Fixed Distance");
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc(FragStrategy::Direct)).is_ok());

    info!("Test Arbitrary Distance");
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc2(FragStrategy::Direct, 0xFFFF)).is_ok());
}

#[test]
fn test_allocate_map() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter(None, log::LevelFilter::Info)
        .try_init();

    info!("Test Fixed Distance");
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc(FragStrategy::Map)).is_ok());

    info!("Test Arbitrary Distance");
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc2(FragStrategy::Map, 0xFFFF)).is_ok());
}

fn test_allocate<T, F>(allocator: F) -> Result<(), MemoryError>
where
    T: Default + Debug + PartialEq,
    F: Fn() -> Result<(Frag<T>, Frag<T>), MemoryError>,
{
    let min_distance = 0xFFFF;
    let result = allocator();
    assert!(result.is_ok(), "Failed to allocate memory");

    let (a, b) = result.unwrap();

    let aa = &*a;
    let bb = &*b;

    assert!(distance(aa, bb) >= min_distance);
    assert_eq!(aa, &T::default());
    assert_eq!(bb, &T::default());

    assert!(Frag::<T>::dealloc(a).is_ok());
    assert!(Frag::<T>::dealloc(b).is_ok());

    Ok(())
}

// ----------------------------------------------------------------------------

/// Calculates the distance between two pointers
fn distance<T>(a: &T, b: &T) -> usize {
    let a = a as *const T as usize;
    let b = b as *const T as usize;

    a.abs_diff(b)
}
