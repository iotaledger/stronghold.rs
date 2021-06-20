// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Synchronization module for stronghold

// !!! IMPORTANT USE GUARDED VEC!!!

#![allow(dead_code, unused_variables)]

use std::path::Path;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Fail")]
    Fail,
}

/// The snapshot file consists of
/// header
/// magic 5 bytes
/// version 2 bytes
/// x25519 pub key length: 32
/// xchacha20poly usize
/// residual

pub struct Chunk<'this, T> {
    data: &'this [u8],

    // remove this, when T is needed
    _phantom: std::marker::PhantomData<T>,
}

/// Synchronization of two snapshots.

pub fn sync<P>(a: P, b: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    Ok(())
}

#[cfg(test)]
mod tests {}
