// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![no_std]

//! Stronghold Protected-access Memory Runtime.
//!
//! These modules contain an interface for allocating and protecting
//! the memory of secrets in Stronghold.  Data is protected from being accessed
//! outside of a limited scope. Instead it must be accessed via the
//! provided interfaces.
//!
//! Memory allocations are protected by guard pages before and after the
//! allocation, an underflow canary, and are zeroed out when freed.

mod boxed;
mod guarded;
mod guarded_vec;
mod types;

pub use guarded::Guarded;
pub use guarded_vec::GuardedVec;
pub use types::Bytes;
