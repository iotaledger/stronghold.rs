// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub enum ReplError {
    /// The selected command is invalid
    InvalidContext,

    /// The selected command is not present
    UnknownContext,

    /// The selected action is invalid
    InvalidAction,

    /// The selected action is not present
    UnknownAction,

    /// Reading a line from stdin failed
    LineError,

    /// A value to be parsed is unknown
    UnknownValue,
}
