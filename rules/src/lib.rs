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

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

pub mod types;

use core::convert::{TryFrom, TryInto};
use std::collections::HashMap;
use thiserror::Error as DeriveError;
use types::Count;

// impl tuple count fn
macros::impl_count_tuples!(26);

pub enum Cmp {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterEquals,
    LessEquals,
    Any,
}

#[derive(Debug, DeriveError)]
pub enum CmpError {
    #[error("Unknown Token Encountered: ({0})")]
    UnknownToken(String),
}

impl TryFrom<&str> for Cmp {
    type Error = CmpError;

    fn try_from(s: &str) -> Result<Cmp, Self::Error> {
        let c = match s {
            "=" => Cmp::Equal,
            "!=" => Cmp::NotEqual,
            ">" => Cmp::Greater,
            ">=" => Cmp::GreaterEquals,
            "<" => Cmp::Less,
            "<=" => Cmp::LessEquals,
            "*" => Cmp::Any,
            _ => return Err(CmpError::UnknownToken(s.to_string())),
        };
        Ok(c)
    }
}

pub trait Conditional {
    type Item: PartialEq + PartialOrd;
    type Error: Default; // default error?

    /// Constructs a new condition with a lazy function
    fn with_function<F>(func: F) -> Self
    where
        F: Fn(Self::Item) -> Result<bool, Self::Error>;

    /// Constructs a new condition with an item
    fn with_item(item: Self::Item) -> Self;

    fn function<F>(&self) -> Result<F, Self::Error>
    where
        F: Fn(Self::Item);

    /// returns the working item of the condition
    fn item(&self) -> Result<Self::Item, Self::Error>;

    /// Evaluates a fact
    fn test<C>(&self, other: &Self::Item, cmp: C) -> Result<bool, Self::Error>
    where
        C: TryInto<Cmp>,
    {
        if let Ok(cmp) = cmp.try_into() {
            let result = match cmp {
                Cmp::Equal => self.item()?.eq(other),
                Cmp::NotEqual => self.item()?.ne(other),
                Cmp::Greater => self.item()?.gt(other),
                Cmp::Less => self.item()?.lt(other),
                Cmp::GreaterEquals => self.item()?.ge(other),
                Cmp::LessEquals => self.item()?.le(other),
                Cmp::Any => true,
            };

            return Ok(result);
        }

        return Err(Self::Error::default());
    }
}

pub struct Rule<'a, C, P, T>
where
    C: Fn(&T) -> bool,
    P: Fn(),
    T: PartialEq + PartialEq,
{
    conditions: Vec<&'a C>,
    actions: Vec<&'a P>,
    memory: Vec<T>,
    item: Option<T>,
}

impl<'a, C, A, T> Rule<'a, C, A, T>
where
    C: Fn(&T) -> bool,
    A: Fn(),
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

    pub fn insert(mut self, condition: &'a C, action: &'a A) -> Self {
        self.conditions.push(condition);
        self.actions.push(action);

        self
    }
}

impl<'a, C, A, T> Conditional for Rule<'a, C, A, T>
where
    C: Fn(&T) -> bool,
    A: Fn(),
    T: PartialEq + PartialOrd,
{
    type Item = T;
    type Error = String; // rework this

    fn with_function<F>(func: F) -> Self
    where
        F: Fn(Self::Item) -> Result<bool, Self::Error>,
    {
        todo!()
    }

    fn with_item(item: Self::Item) -> Self {
        todo!()
    }

    fn function<F>(&self) -> Result<F, Self::Error>
    where
        F: Fn(Self::Item),
    {
        todo!()
    }

    fn item(&self) -> Result<Self::Item, Self::Error> {
        todo!()
    }
}

#[derive(Default)]
pub struct RuleEngine<'a, C, P, T>
where
    C: Fn(&T) -> bool,
    P: Fn(),
    T: PartialOrd + PartialOrd,
{
    graph: HashMap<usize, usize>,

    rules: HashMap<usize, Rule<'a, C, P, T>>,

    // used later
    conditions: HashMap<usize, C>,
    productions: HashMap<usize, P>,
    memory: Vec<T>,
}

impl<'a, C, P, T> RuleEngine<'a, C, P, T>
where
    C: Fn(&T) -> bool,
    P: Fn(),
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
    pub fn insert_rule(mut self, rule: Rule<'a, C, P, T>, name: Option<String>) -> Self {
        let name = name.unwrap_or_else(|| {
            let size = core::mem::size_of_val(&rule);
            String::new()
        });

        // let next = self
        //     .pool
        //     .pop()
        //     .or_else(|| Some(self.next.fetch_add(1, Ordering::Acquire)))
        //     .unwrap();
        let next = 0;
        let rules = &mut self.rules;
        rules.insert(next, rule);

        self
    }

    /// Evaluates, if there is a production for given item of type `T`
    /// Returns an Error, if not rule is matching
    pub fn eval(&self, item: &T) -> Result<Vec<&P>, Box<dyn std::error::Error>> {
        for (_, c) in &self.conditions {
            if !c(item) {
                return Err("".into());
            }
        }

        Ok(self.productions.values().collect())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[ignore]
    fn test_tuple_count() {
        assert_eq!((1, 2, 3, 4).count(), 4);
        assert_eq!((1, 2, 3, 4, "string").count(), 5);
        assert_eq!((1, 2, 3, 4, 232.32, 34, 'a', "other string").count(), 8);
    }

    #[test]
    #[ignore]
    fn test_match_rules() {}
}
