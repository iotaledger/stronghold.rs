// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

#[test]
fn test_allocate_direct() {
    assert!(test_allocate(FragStrategy::Direct).is_ok());
    assert!(test_allocate2(FragStrategy::Direct).is_ok());
}

#[test]
fn test_allocate_map() {
    assert!(test_allocate(FragStrategy::MMap).is_ok());
    assert!(test_allocate2(FragStrategy::MMap).is_ok());
}

fn test_allocate2(strategy: FragStrategy) -> Result<(), MemoryError> {
    loop {
        unsafe {
            match Frag::alloc2::<TestStruct>(strategy, 0xFFFF) {
                Some((a, b)) => {
                    assert!(distance(a.as_ref(), b.as_ref()) > 0xFFFF);
                    break;
                }
                None => continue,
            }
        }
    }

    Ok(())
}

fn test_allocate(strategy: FragStrategy) -> Result<(), MemoryError> {
    let runs = 100;
    for _ in 0..runs {
        unsafe {
            match Frag::alloc::<TestStruct>(strategy) {
                Some((a, b)) => {
                    assert!(distance(a.as_ref(), b.as_ref()) > 0xFFFF);
                    break;
                }
                None => continue,
            }
        }
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
