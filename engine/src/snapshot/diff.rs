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

use thiserror::Error as DeriveError;

// re-export diff
pub use lcs::*;

#[derive(DeriveError, Debug)]
#[non_exhaustive]
pub enum DiffError {
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Synchronization Error: {0}")]
    SynchronizationError(String),
}

/// Diff trait
pub trait Diff<T: PartialEq + Clone>: Sized {
    type Error;

    /// Returns the applyable difference from source to destination
    fn sync(src: Vec<T>, dst: Vec<T>) -> Self;

    /// Applies the calculated edit difference, and returns the result
    fn apply(&mut self, source: Vec<T>, destination: Vec<T>) -> Result<Vec<T>, Self::Error>;
}

pub enum DiffOperation {
    Delete { src: Option<usize> },
    Insert { src: Option<usize>, dst: Option<usize> },
    Equal { src: Option<usize>, dst: Option<usize> },
}

/// Module for Longest Common Subsequence Algorithm
mod lcs {

    use super::*;
    use core::cmp::max;

    /// Implementation for  Longest Common Subsequence (LCS)
    ///
    /// You can obtain a reference to [`Lcs`] via [`Self::sync()`],
    /// calling [`Self::apply()`] to apply the difference to destination.
    pub struct Lcs {
        edit: Vec<DiffOperation>,
    }

    impl<T> Diff<T> for Lcs
    where
        T: PartialEq + Clone,
    {
        type Error = DiffError;

        fn sync(src: Vec<T>, dst: Vec<T>) -> Self {
            // let as_string = |u: u8| -> String { String::from_utf8(vec![u]).unwrap() };

            let mut edit = vec![];
            let src_length = src.len();
            let dst_length = dst.len();

            // build a matrix of prefix.len - (n.len - suffix.len)
            let build_matrix = |src: Vec<T>, dst: Vec<T>| -> Vec<Vec<usize>> {
                let dst_len = dst.len();
                let src_len = src.len();

                // we create a lookup matrix, that contains one more row and column
                let mut matrix = vec![vec![0; src_len + 1]; dst_len + 1];

                // process row
                for i in (0..dst_len).rev() {
                    matrix[i][src_len] = 0;

                    // process columns
                    for j in (0..src_len).rev() {
                        let eq = dst[i] == src[j];

                        matrix[i][j] = match eq {
                            true => matrix[i + 1][j + 1] + 1,
                            false => max(matrix[i + 1][j], matrix[i][j + 1]),
                        };
                    }
                }
                matrix
            };

            if src_length > 0 && dst_length > 0 {
                let mut s = 0;
                let mut d = 0;

                let prefix: Vec<(T, T)> = src
                    .iter()
                    .zip(dst.clone())
                    .take_while(|(s, d)| *s == d)
                    .map(|(s, d)| (s.clone(), d))
                    .collect();

                let suffix: Vec<(T, T)> = src
                    .iter()
                    .rev()
                    .zip(dst.iter().rev())
                    .take(src_length.min(dst_length) - prefix.len())
                    .take_while(|(s, d)| s == d)
                    .map(|(a, b)| (a.clone(), b.clone()))
                    .collect();

                // build lookup table for matches
                let lut = build_matrix(
                    (&src[prefix.len()..(src.len() - suffix.len())]).to_vec(),
                    (&dst[prefix.len()..(dst.len() - suffix.len())]).to_vec(),
                );

                // get actual indices for unequal items
                let dst_length = dst.len() - prefix.len() - suffix.len();
                let src_length = src.len() - prefix.len() - suffix.len();

                // restore prefix
                (0..prefix.len()).for_each(|i| {
                    edit.push(DiffOperation::Equal {
                        dst: Some(i),
                        src: Some(i),
                    })
                });

                // iterate over `inner` body of data,
                // handle all three cases: equality, insertions, deletions
                loop {
                    if d >= dst_length || s >= src_length {
                        break;
                    }

                    let dst_index = d + prefix.len();
                    let src_index = s + prefix.len();

                    // check equality
                    if dst[dst_index] == src[src_index] {
                        edit.push(DiffOperation::Equal {
                            dst: Some(dst_index),
                            src: Some(src_index),
                        });

                        d += 1;
                        s += 1;
                    } else if lut[d + 1][s] >= lut[d][s + 1] {
                        edit.push(DiffOperation::Insert {
                            dst: Some(dst_index),
                            src: None,
                        });
                        d += 1;
                    } else {
                        edit.push(DiffOperation::Delete { src: Some(src_index) });
                        s += 1;
                    }
                }

                (d..dst_length).for_each(|index| {
                    edit.push(DiffOperation::Insert {
                        dst: Some(index + prefix.len()),
                        src: None,
                    })
                });

                (s..src_length).for_each(|index| {
                    edit.push(DiffOperation::Delete {
                        src: Some(index + prefix.len() - 1),
                    });
                });

                (0..suffix.len()).for_each(|index| {
                    edit.push(DiffOperation::Equal {
                        src: Some(index + src_length + prefix.len()),
                        dst: Some(index + dst_length + prefix.len()),
                    })
                });

                return Lcs { edit };
            }

            if dst_length == 0 {
                (0..src_length).for_each(|index| {
                    edit.push(DiffOperation::Delete { src: Some(index) });
                });

                return Lcs { edit };
            }

            (0..dst_length).for_each(|index| {
                edit.push(DiffOperation::Insert {
                    src: None,
                    dst: Some(index),
                });
            });

            Lcs { edit }
        }

        fn apply(&mut self, source: Vec<T>, destination: Vec<T>) -> Result<Vec<T>, Self::Error> {
            Ok(self
                .edit
                .iter()
                .filter_map(|op| match op {
                    DiffOperation::Insert { src, dst } => Some(destination[dst.unwrap()].clone()),
                    DiffOperation::Equal { src, dst } => Some(source[src.unwrap()].clone()),
                    _ => None,
                })
                .collect())
        }
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use std::error::Error;

    type Data = (Vec<u8>, Vec<u8>, Vec<u8>);

    fn create_test_table() -> Vec<Data> {
        vec![
            (
                b"helkao, world new".to_vec(),
                b"hello, new world".to_vec(),
                b"hello, new world".to_vec(),
            ),
            (
                b"feature #4 flag 43: has been disabled".to_vec(),
                b"feuture #3 flag 42: has been enabled".to_vec(),
                b"feuture #3 flag 42: has been enabled".to_vec(),
            ),
            (
                "ääs76%4..-MNbchsdcsuh..cldc::..975§$5456576c".as_bytes().to_vec(),
                b"".to_vec(),
                b"".to_vec(),
            ),
            (
                "".as_bytes().to_vec(),
                "ääs76%4..-MNbchsdcsuh..cldc::..975§$5456576c".as_bytes().to_vec(),
                "ääs76%4..-MNbchsdcsuh..cldc::..975§$5456576c".as_bytes().to_vec(),
            ),
        ]
    }

    #[test]
    fn test_sync() -> Result<(), Box<dyn Error>> {
        let matrix = create_test_table();

        for entry in matrix {
            let mut edit = Lcs::sync(entry.0.clone(), entry.1.clone());
            let result = edit.apply(entry.0, entry.1)?;
            let actual = String::from_utf8(result)?;
            let expected = String::from_utf8(entry.2.to_vec())?;

            assert_eq!(actual, expected);
        }

        Ok(())
    }
}
