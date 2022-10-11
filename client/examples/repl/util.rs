// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ReplError;
use std::{fmt::Display, io::Write};

/// Helper function to write something to stdout without line ending and flush it directly
pub fn print<D>(writable: D)
where
    D: Display,
{
    print!("{}", writable);
    flush();
}

/// Helper function to write something to stdout with line ending and flush it directly
pub fn println<D>(writable: D)
where
    D: Display,
{
    println!("{}", writable);
    flush()
}

pub fn flush() {
    let _ = std::io::stdout().flush();
}

pub fn read_line() -> Result<String, ReplError> {
    let stdin = std::io::stdin();
    let mut input = String::new();

    stdin.read_line(&mut input).map_err(|_| ReplError::LineError)?;
    Ok(input)
}

pub fn draw_caret() {
    print("> ");
}
