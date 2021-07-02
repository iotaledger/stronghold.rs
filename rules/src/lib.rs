// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rules Engine
//!
//! A Rules Engine for Stronghold.

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

mod types;

use core::convert::{TryFrom, TryInto};
use std::collections::{HashMap, HashSet};
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

pub trait Condition {
    type Item: PartialEq + PartialOrd;
    type Error: Default; // default error?

    /// Constructs a new condition with an item
    fn with_item(item: Self::Item) -> Self;

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

pub struct Rule<'a, P, C, T>
where
    C: Fn(T) -> bool,
    P: Fn(),
    T: PartialEq + PartialEq,
{
    conditions: Vec<&'a C>,
    actions: Vec<&'a P>,
    memory: Vec<T>,
}

// #[derive(Default)]
pub struct RuleEngine<'a, P, C, T>
where
    C: Fn(T) -> bool,
    P: Fn(),
    T: PartialOrd + PartialOrd,
{
    rules: HashSet<Rule<'a, P, C, T>>,
    conditions: HashMap<usize, C>,
    productions: HashMap<usize, P>,
    memory: Vec<T>,
}

impl<'a, P, C, T> RuleEngine<'a, P, C, T>
where
    C: Fn(T) -> bool,
    P: Fn(),
    T: PartialEq + PartialOrd,
{
    pub fn new() -> Self {
        Self {
            rules: HashSet::new(),
            conditions: HashMap::new(),
            productions: HashMap::new(),
            memory: Vec::new(),
        }
    }

    pub fn create_rule(&mut self, pattern: C, procedure: P) {
        let rule = Rule::<P, C, T> {
            conditions: Vec::new(),
            actions: Vec::new(),
            memory: Vec::new(),
        };

        self.conditions.insert(0, pattern);
        self.productions.insert(0, procedure);

        // todo!()
    }

    /// Evaluates, if there is a production for given item of type `T`
    /// Returns an Error, if not rule is matching
    pub fn eval(&self, item: T) -> Result<Vec<P>, Box<dyn std::error::Error>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tuple_count() {
        assert_eq!((1, 2, 3, 4).count(), 4);
        assert_eq!((1, 2, 3, 4, "string").count(), 5);
        assert_eq!((1, 2, 3, 4, 232.32, 34, 'a', "other string").count(), 8);
    }

    #[test]
    fn test_match_rules() {
        let mut re = RuleEngine::new();

        re.create_rule(|a| true, || {});

        assert!(re.eval("").is_ok());
    }
}
