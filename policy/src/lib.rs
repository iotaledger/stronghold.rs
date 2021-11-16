// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Policy Engine
//!
//! A dynamic policy engine for stronghold.
//!
//! use cases for a dynamic policy engine are
//! - configuring diverse type of snapshot synchronization (local full/partial, remote)
//! - setting firewall policies ( this peer with this address allow procs x y z)
//! - creating actors according to remote peer addresses, and their set conditions

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

pub mod types;

use std::{collections::HashMap, hash::Hash};

use types::{access::Access, Count};

// impl tuple count fn
// todo move into other crate
macros::impl_count_tuples!(26);

#[derive(Default)]
pub struct Engine<
    T, // this could be the general context
    U, // this could be an associated mapping
    V, // this could be an associated access type with
> where
    T: Hash + PartialEq + Eq,
    U: Clone + Hash + PartialEq + Eq,
    V: Clone + Hash + Eq,
{
    target: HashMap<T, U>, // the target mapping

    access: HashMap<U, HashMap<Access, Vec<V>>>, // the access type mapping
    values: HashMap<U, HashMap<V, Access>>,      // the direct mapping of value and access type
}

impl<T, U, V> Engine<T, U, V>
where
    T: Hash + PartialEq + Eq,
    U: Clone + Hash + PartialEq + Eq,
    V: Clone + Hash + Eq,
{
    /// creates a new policy with ctx - a context to map an outer type, and
    /// a mapping to an internal type
    pub fn context(&mut self, ctx: T, internal: U) {
        self.target.insert(ctx, internal);
    }
}

/// Policy trait for a target type T
pub trait Policy {
    type Error;
    type Result;
    type Context;
    type Mapped;
    type Value: Clone + Hash + Eq;

    /// Checks a reference to type Self::Context as ref, what kind of policy applies to what values.
    /// An optional [`Access`] policy can be provided to check if it is applied, otherwise
    /// [`Access::All`] is being assumed.
    fn check(&self, input: &Self::Context, access: Option<Access>) -> Self::Result;

    /// Checks the access type for a [`Self::Value`], and returns and an optional [`Access`] type
    fn check_access(&self, input: &Self::Context, value: &Self::Value) -> Result<Access, Self::Error>;

    /// Insert a new policy for mapped U to access Type
    fn insert(&mut self, id: Self::Mapped, access: Access, value: Self::Value);

    /// Removes a mapping
    fn remove(&mut self, id: Self::Mapped);

    /// Clears a context mapping
    fn clear(&mut self, context: Self::Context);

    /// Clears all
    fn clear_all(&mut self);
}

impl<T, U, V> Policy for Engine<T, U, V>
where
    T: Hash + Eq,
    U: Clone + Hash + Eq,
    V: Clone + Hash + Eq,
{
    type Error = ();
    type Context = T;
    type Mapped = U;
    type Value = V;

    type Result = Option<Vec<Self::Value>>;

    fn check(&self, input: &Self::Context, access: Option<Access>) -> Self::Result {
        // (1) get mapped type
        let key = match self.target.get(input) {
            Some(mapped) => mapped,
            None => return None,
        };

        // (2) get access mapping
        let map = match self.access.get(&key) {
            Some(mapping) => mapping,
            None => return None,
        };

        match access {
            Some(access) => map.get(&access).cloned(),
            None => map.get(&Access::All).cloned(),
        }
    }

    /// Checks the access type for a [`Self::Value`], and returns and optional access type
    fn check_access(&self, input: &Self::Context, value: &Self::Value) -> Result<Access, Self::Error> {
        // (1) get mapped type
        let key = match self.target.get(input) {
            Some(mapped) => mapped,
            None => return Err(()), // error should be : no mapping present
        };

        // (2) get access mapping
        let map = match self.values.get(&key) {
            Some(mapping) => mapping,
            None => return Err(()), // error should be : no mapping present
        };

        map.get(&value).map(Clone::clone).ok_or(())
    }

    fn insert(&mut self, id: Self::Mapped, access: Access, value: Self::Value) {
        let previous = self.access.get(&id).cloned();
        let previous = self.access.entry(id.clone()).or_insert(HashMap::new());

        let p = previous.entry(access.clone()).or_insert(Vec::new());
        p.push(value.clone());

        let previous = self.values.get(&id).cloned();
        let previous = self.values.entry(id).or_insert(HashMap::new());

        previous.entry(value).or_insert(access);
    }

    fn remove(&mut self, id: Self::Mapped) {
        self.access.remove(&id);
    }

    fn clear(&mut self, context: Self::Context) {
        self.target.remove(&context);
    }

    fn clear_all(&mut self) {
        self.target.clear();
        self.access.clear();
    }
}
