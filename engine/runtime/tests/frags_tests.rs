// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use log::*;

use runtime::{
    memories::frag::{Frag, FragStrategy, FRAG_MIN_DISTANCE},
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
fn test_fragments_allocate() {
    test_allocate_strategy(FragStrategy::Direct);
    test_allocate_strategy(FragStrategy::Map);
    test_allocate_strategy(FragStrategy::Hybrid);
}

fn test_allocate_strategy(strat: FragStrategy) {
    let _ = env_logger::builder()
        .is_test(true)
        .filter(None, log::LevelFilter::Info)
        .try_init();

    info!("Test Fixed Distance");
    assert!(
        test_allocate::<TestStruct, _>(|| Frag::alloc_initialized(strat, TestStruct::default(), TestStruct::default())).is_ok()
    );

    info!("Test Arbitrary Distance");
    assert!(test_allocate::<TestStruct, _>(|| Frag::alloc_default(strat, 0xFFFF)).is_ok());
}

#[test]
fn test_fragments_deallocate() {
    test_deallocate(FragStrategy::Direct);
    test_deallocate(FragStrategy::Map);
    test_deallocate(FragStrategy::Hybrid);
}

fn test_deallocate(strat: FragStrategy) {
    let _ = env_logger::builder()
        .is_test(true)
        .filter(None, log::LevelFilter::Info)
        .try_init();

    info!("Test Fixed Distance");
    let frags = Frag::alloc_initialized(strat, TestStruct::default(), TestStruct::default());
    assert!(frags.is_ok());
    let (mut f1, mut f2) = frags.unwrap();

    assert!(Frag::dealloc(&mut f1).is_ok());
    assert!(Frag::dealloc(&mut f2).is_ok());

    // To avoid double deallocation
    std::mem::forget(f1);
    std::mem::forget(f2);
}

fn test_allocate<T, F>(allocator: F) -> Result<(), MemoryError>
where
    T: Default + Debug + PartialEq + Clone,
    F: Fn() -> Result<(Frag<T>, Frag<T>), MemoryError>,
{
    let result = allocator();
    assert!(result.is_ok(), "Failed to allocate memory");

    let (a, b) = result.unwrap();

    let aa = a.get()?;
    let bb = b.get()?;

    assert!(distance(aa, bb) >= FRAG_MIN_DISTANCE);
    assert_eq!(aa, &T::default());
    assert_eq!(bb, &T::default());

    Ok(())
}

// ----------------------------------------------------------------------------

/// Calculates the distance between two pointers
fn distance<T>(a: &T, b: &T) -> usize {
    let a = a as *const T as usize;
    let b = b as *const T as usize;

    a.abs_diff(b)
}
