// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Policy Engine
//!
//! A dynamic policy engine for stronghold. A policy consists
//! of a context for which a mapping for an inner type is present. This
//! deviates a bit from a pure policy engine implementation, but enables
//! the user to create a more lose coupling across remote peers. In
//! Stronghold parlance a context may represent a peer id that is
//! mapped to an arbitrary client id, and each client (eg. a client actor
//! with a state) has some fine grained access control that can be checked with
//! the policy engine.

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

pub mod types;

use std::{collections::HashMap, hash::Hash};

use types::access::Access;

// #[derive(Default)]
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
    pub fn new() -> Self {
        Self {
            target: HashMap::new(),
            access: HashMap::new(),
            values: HashMap::new(),
        }
    }

    /// creates a new policy with ctx - a context to map an outer type, and
    /// a mapping to an internal type
    pub fn context(&mut self, ctx: T, internal: U) {
        self.target.insert(ctx, internal.clone());
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
    fn check_access<I>(&self, input: &Self::Context, value: I) -> Result<Access, Self::Error>
    where
        I: Into<Self::Value>;

    /// Sets a default policy, of no policy for a given value is present
    fn set_default(&mut self, id: Self::Mapped, access: Access);

    /// Insert a new policy for mapped U to access Type
    fn insert<I>(&mut self, id: Self::Mapped, access: Access, value: I)
    where
        I: Into<Self::Value>;

    /// Inserts a new policy for many values
    fn insert_all<I>(&mut self, id: Self::Mapped, access: Access, values: Vec<I>)
    where
        I: Into<Self::Value>;

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
    fn check_access<I>(&self, input: &Self::Context, value: I) -> Result<Access, Self::Error>
    where
        I: Into<Self::Value>,
    {
        let value = value.into();

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

    fn set_default(&mut self, id: Self::Mapped, access: Access) {
        // todo how to handle default rules
    }

    fn insert<I>(&mut self, id: Self::Mapped, access: Access, value: I)
    where
        I: Into<Self::Value>,
    {
        let new_value = value.into();

        // reverse mapping
        let a = self.access.entry(id.clone()).or_insert(HashMap::new());
        a.entry(access.clone()).or_insert(Vec::new()).push(new_value.clone());

        // forward mapping
        let b = self.values.entry(id).or_insert(HashMap::new());
        b.entry(new_value).or_insert(access);
    }

    fn insert_all<I>(&mut self, id: Self::Mapped, access: Access, values: Vec<I>)
    where
        I: Into<Self::Value>,
    {
        for value in values {
            self.insert(id.clone(), access.clone(), value)
        }
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
