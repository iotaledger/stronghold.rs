// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::hash::Hash;

use crate::types::Cardinality;
use macros::Cardinality;
pub use rand::{distributions::Standard, prelude::Distribution};

/// This enum defines a list of access variants to be used inside a policy
#[derive(Clone, Cardinality, PartialEq, Eq, Hash, Debug)]
pub enum Access {
    // Allows a remote peer to access the complete state to
    // a mapped client
    All,

    // Allows only certain portions to be exported
    Read,

    // Allows remote peers to write into the current client's state
    Write,

    // Allows only certain portions of the stored secrets to be run by
    // procedures
    Execute,

    // Deny all access
    NoAccess,
}

impl Distribution<Access> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Access {
        let cardinality = Access::cardinality();

        match rng.gen_range(0usize..cardinality) {
            0 => Access::All,
            1 => Access::Read,
            2 => Access::Write,
            3 => Access::Execute,
            _ => Access::NoAccess,
        }
    }
}
