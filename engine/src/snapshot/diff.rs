// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Snapshot difference module
//!
//! This module provides the ability to synchronized local snapshots, and
//! remote snapshots. While synchronizing local snapshots is trivial,
//! synchronizing remote snapshots must involve a more elaborated set of
//! permissions. Care must also be taken, if the data to be synchronized
//! needs
//!
//! Synchronizing two snapshots can be done easily
//! ``` no_run
//! ```
#![allow(dead_code, unused_variables)]

use runtime::GuardedVec;
use std::io::Read;
use thiserror::Error as DeriveError;

// re-export diff
pub use myers_diff::*;

#[derive(DeriveError, Debug)] // is [`Debug`] safe here?
#[non_exhaustive]
pub enum DiffError {
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Synchronization Error: {0}")]
    SynchronizationError(String),
}

/// Diff trait
pub trait Diff: Sized {
    type Error;

    /// Tries to calculate an applyable difference from source and destination.
    /// The returned impl. Diff can then be used to [`Diff#apply`]
    fn sync_from_read<R>(source: R, destination: R) -> Result<Self, Self::Error>
    where
        R: Read;

    ///
    fn sync_from_bytes(source: &[u8], destination: &[u8]) -> Result<Self, Self::Error>;

    ///
    fn apply(&self) -> Result<GuardedVec<u8>, Self::Error>;
}

/// Module for Eugene W. Myers Longet Common Subsequence Algorithm
mod myers_diff {

    use super::*;

    /// Reference implementation for Myers Longest Common Subsequence (LCS)
    ///
    /// You can obtain a reference to [`Synchronize`] via two loader methods,
    /// calling [`Self::apply()`] to apply the difference to destination.
    ///
    /// This struct implements the LCS from [Eugene W. Myers](http://www.xmailserver.org/diff2.pdf)
    pub struct MyersDiff {
        source: Vec<u8>,
        destination: Vec<u8>,
    }

    impl Diff for MyersDiff {
        type Error = DiffError;

        fn sync_from_read<R>(source: R, destination: R) -> Result<Self, Self::Error>
        where
            R: Read,
        {
            todo!()
        }

        fn sync_from_bytes(source: &[u8], destination: &[u8]) -> Result<Self, Self::Error> {
            let n = source.len();
            let m = source.len();
            let max = n + m;

            let _v = vec![0isize; (2 * max) - 1];

            todo!()
        }

        fn apply(&self) -> Result<GuardedVec<u8>, Self::Error> {
            todo!()
        }
    }
}
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sync_from_read() {
        let source = b"abcdefbcbdc";
        let destination = b"ccsbsba";

        let diff = MyersDiff::sync_from_read(&source[..], &destination[..]).unwrap();
        assert!(diff.apply().is_ok())
    }

    #[test]
    fn test_sync_from_bytes() {
        let source = b"abcdefbcbdc";
        let destination = b"ccsbsba";

        let diff = MyersDiff::sync_from_bytes(source, destination).unwrap();
        assert!(diff.apply().is_ok())
    }
}
