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
//!
//! TODO: Focus implementation of rule engine for one type

#![allow(clippy::all)]
#![allow(dead_code, unused_variables)]

pub mod types;

use thiserror::Error as DeriveError;
use types::{AnyMap, Count};

// impl tuple count fn
macros::impl_count_tuples!(26);

#[derive(Debug, DeriveError)]
pub enum PolicyError {
    #[error("Denied Execution: ({0})")]
    Denied(String),
}

/// Provides fine grained control over behaviors
pub struct PolicyEngine {
    /// Storage for all policies
    policies: AnyMap<String>,
}

impl PolicyEngine {
    pub fn eval(&self) -> Result<(), PolicyError> {
        todo!()
    }
}
