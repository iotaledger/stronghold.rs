// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use macros::impl_count_tuples;

/// Local type that will be implemented by the trait
pub trait Count {
    /// Returns the number of items of an implementor
    fn count(&self) -> usize;
}

impl_count_tuples!(16);

#[test]
fn test_tuple_count() {
    assert_eq!((1, 2, 3, 4).count(), 4);
    assert_eq!((1, 2, 3, 4, "string").count(), 5);
    assert_eq!((1, 2, 3, 4, 232.32, 34, 'a', "other string").count(), 8);
}
