// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types being used by the policy system

pub mod access;
pub mod anymap;

/// Count trait for types that hold a number of items
/// Is being used to count the number of items inside a tuple
pub trait Count {
    /// Returns the number of items of an implementor
    fn count(&self) -> usize;
}

/// The Cardinality trait may be useful to return the size of a set. One
/// useful example is the derivation of this trait on an enum to return
/// the number of variants inside it.
pub trait Cardinality {
    /// Returns the size of the implementor
    fn cardinality() -> usize;
}
