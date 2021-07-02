// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types

/// Count trait for types that hold a number of items
/// Is being used to count the number of items inside a tuple
pub trait Count {
    /// Returns the number of items of an implementor
    fn count(&self) -> usize;
}
