// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    fmt::{Debug, Display},
};

#[derive(Debug)]
pub enum ReplError<D>
where
    D: Display,
{
    /// The selected command is invalid
    Invalid(D),

    /// The selected command is not present
    Unknown(D),

    /// Reading a line from stdin failed
    LineError,
}

impl<D> Display for ReplError<D>
where
    D: Display + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<E> From<E> for ReplError<String>
where
    E: Error + ToString,
{
    fn from(error: E) -> Self {
        Self::Invalid(error.to_string())
    }
}
