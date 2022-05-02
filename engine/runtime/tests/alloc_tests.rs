// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use runtime::{
    memories::frag::{Frag, FragStrategy},
    MemoryError,
};

#[derive(PartialEq, Debug)]
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
fn test_allocate_default() -> Result<(), MemoryError> {
    test_allocate(FragStrategy::Default)
}

#[test]
fn test_allocate_map() -> Result<(), MemoryError> {
    test_allocate(FragStrategy::MMap)
}

fn test_allocate(strategy: FragStrategy) -> Result<(), MemoryError> {
    let runs = 100;

    for _ in 0..runs {
        let result = Frag::alloc::<TestStruct>(strategy.clone());
        assert!(result.is_ok());
        // assert_eq!(&*result.unwrap(), &TestStruct::default());

        let a = Frag::alloc::<TestStruct>(strategy.clone())?;
        let b = Frag::alloc::<TestStruct>(strategy.clone())?;
        let distance = distance(&*a, &*b);
        assert!(distance > 0xFFFF, "Illegal distance {}", distance);
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
