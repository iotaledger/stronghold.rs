// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rules Engine
//!
//! A dynamic rules engine for stronghold.
//!
//! use cases for a dynamic rules engine are
//! - configuring diverse type of snapshot synchronization (local full/partial, remote)
//! - setting firewall rules ( this peer with this address allow procs x y z)
//! - creating actors according to remote peer addresses, and their set conditions
//!
//! TODO: Focus implementation of rule engine for one type

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

pub mod types;

use std::{any::TypeId, collections::HashMap};
use thiserror::Error as DeriveError;
use types::Count;

// use macros::map;

// impl tuple count fn
macros::impl_count_tuples!(26);

#[derive(Debug, DeriveError)]
pub enum CmpError {
    #[error("Unknown Token Encountered: ({0})")]
    UnknownToken(String),
}

/// Describes a condition bound to a specific type `T`
/// A `Conditional` can be composed of multiple
/// other `Conditionals` bound to the same type `T`.
pub trait Conditional<T>: Default {
    type Item: PartialEq + PartialOrd;
    type Error: Default; // default error?

    fn eval<F>(&self, func: F) -> bool
    where
        F: Fn(&T) -> bool;
}

pub struct Rule<T>
where
    T: PartialEq + PartialEq,
{
    conditions: Vec<fn(T) -> bool>,
    actions: Vec<fn()>,
    memory: Vec<T>,
    item: Option<T>,
}

impl<T> Rule<T>
where
    T: PartialEq + PartialOrd,
{
    pub fn new(item: Option<T>) -> Self {
        Rule {
            conditions: Vec::new(),
            actions: Vec::new(),
            memory: Vec::new(),
            item,
        }
    }

    pub fn with_condition(mut self, condition: fn(T) -> bool) -> Self {
        self.conditions.push(condition);

        self
    }

    pub fn with_action(mut self, action: fn()) -> Self {
        self.actions.push(action);

        self
    }

    /// match phase for the rule engine
    /// if a rule is matched, it will be added to a list
    /// that gets executed according to a priority
    pub fn matches(&self, item: T) -> Result<Vec<Self>, String> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub struct RuleEngine<T>
where
    T: PartialOrd + PartialOrd,
{
    // alpha nodes inside the rete network. they
    // contain working memory of matched facts
    // against stored condtions. Each alpha node
    // has one input and one output
    alpha: HashMap<usize, usize>,

    // beta nodes group alpha nodes together to form
    // a memory efficient representation of rules
    beta: HashMap<usize, usize>,

    graph: HashMap<usize, usize>,

    // later this should be the kind nodes, if
    // there shall be a different type being used
    rules: HashMap<usize, Rule<TypeId>>,

    // used later
    memory: Vec<T>,
}

impl<T> RuleEngine<T>
where
    T: PartialEq + PartialOrd,
{
    /// This inserts a rule into the rete. A rule consists of multiple
    /// conditions, and associated action(s), that are being triggered, if each
    /// of the containing condition is being matched. A rule can be named, but
    /// the choice is optional. If no name is given, the rule will have a
    /// generic name.
    ///
    /// future optimization might involve, that the rule might trigger dependening
    /// on a certain threshold.
    pub fn insert_rule(self, rule: Rule<T>, name: Option<String>) -> Self {
        let name = name.unwrap_or_else(|| {
            let size = core::mem::size_of_val(&rule);
            String::new()
        });

        // let next = self
        //     .pool
        //     .pop()
        //     .or_else(|| Some(self.next.fetch_add(1, Ordering::Acquire)))
        // //     .unwrap();
        // let next = 0;
        // let rules = &mut self.rules;
        // rules.insert(next, rule);

        self
    }

    /// Evaluates, if there is a production for given item of type `T`
    /// Returns an Error, if not rule is matching
    pub fn eval(&self, item: &T) -> Result<Vec<()>, Box<dyn std::error::Error>> {
        // for (_, c) in &self. {
        //     if !c(item) {
        //         return Err("".into());
        //     }
        // }

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {

    // TODO: you see this, you remove this
    #[allow(unused_imports)]
    use super::*;

    #[derive(Default)]
    struct SnapshotHandler;

    #[test]
    #[ignore]
    fn test_match_rules() {
        // Ideas
        //
        // functions can be decorated by a proc_macro_attribute
        // that accepts a function to intercept the execution of the function.

        let snapshot_handler = SnapshotHandler::default();

        // let mut rule = RuleEngine::default();

        // rule.insert(rule! {
        //     snapshot_handler
        // });

        let source = b"/source/path";
        let destination = b"/destination/path";

        // let client_paths = map![ {b"" : b""}, {b"", b""}];

        // snapshot_handler.synchronize();
    }
}
