// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ReplError;
use iota_stronghold::procedures::{KeyType, MnemonicLanguage};
use std::{fmt::Display, io::Write};

#[inline(always)]
fn flush() {
    let _ = std::io::stdout().flush();
}

/// Reads a line from stdio
pub fn readline() -> Result<String, ReplError<String>> {
    let stdin = std::io::stdin();
    let mut input = String::new();
    stdin.read_line(&mut input).map_err(|_| ReplError::LineError)?;
    input = input.trim().to_string();

    Ok(input)
}

pub struct Tokenizer {
    command: String,
    parameter: Vec<String>,
}

impl TryFrom<String> for Tokenizer {
    type Error = ReplError<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match tokenize(value) {
            t if t.is_empty() => Err(ReplError::Invalid("No Command present".to_string())),
            t => Ok(Self {
                command: t[0].clone(),
                parameter: t[1..].to_vec(),
            }),
        }
    }
}

impl Tokenizer {
    pub fn command(&self) -> &String {
        &self.command
    }

    pub fn parameter(&self) -> &Vec<String> {
        &self.parameter
    }
}

/// Tokenizes a string from stdin discarding any delimiting characters.
pub fn tokenize(input: String) -> Vec<String> {
    let mut result = Vec::new();
    let mut token = String::new();

    for rune in input.chars() {
        match rune {
            ' ' | '"' | '\'' => {
                if !token.is_empty() {
                    result.push(token.clone());
                    token.clear();
                }
            }
            _ => token.push(rune),
        }
    }

    if !token.is_empty() {
        result.push(token);
    }

    result
}

/// Draws a prompt with an optional prefix
pub fn prompt<D>(prefix: Option<D>)
where
    D: Display + Default,
{
    let _d = Defer::from(|| {
        flush();
    });
    print!("{}> ", prefix.unwrap_or_default());
}

/// Parses a [`KeyType`] from a String
pub fn parse_keytype(value: &str) -> Result<KeyType, ReplError<String>> {
    match value.to_lowercase().as_str() {
        "ed25519" => Ok(KeyType::Ed25519),
        "x25519" => Ok(KeyType::X25519),
        _ => Err(ReplError::Invalid("Key Type".to_string())),
    }
}

/// Returns the [`MnemonicLanguage`]
pub fn parse_lang(value: &String) -> Result<MnemonicLanguage, ReplError<String>> {
    match value.as_str() {
        "japanese" | "jp" => Ok(MnemonicLanguage::Japanese),
        "english" | "en" => Ok(MnemonicLanguage::English),
        _ => Err(ReplError::Unknown(format!("Unknown language: {}", value))),
    }
}

struct Defer<F>
where
    F: Fn(),
{
    f: F,
}
impl<F> From<F> for Defer<F>
where
    F: Fn(),
{
    fn from(f: F) -> Self {
        Self { f }
    }
}

impl<F> Drop for Defer<F>
where
    F: Fn(),
{
    fn drop(&mut self) {
        (self.f)()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tokenize() {
        let input = r#"command "arg1" arg2          numeric 0 '1'"#;
        let tokenized = tokenize(input.to_string());
        let expected = vec!["command", "arg1", "arg2", "numeric", "0", "1"];

        assert_eq!(tokenized, expected);
    }
}
