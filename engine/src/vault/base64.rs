// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
#[error("Base 64 Error")]
pub struct Base64Error;

/// a [`Base64`] encoder and decoder used in the Vault.
pub struct Base64;
impl Base64 {
    /// base64 padding character
    const PADDING: u8 = b'=';

    /// encode a [`&[u8]`] using a base64 uri-safe character set.
    pub fn encode_data(data: &[u8]) -> String {
        // encode data
        let mut base = Vec::new();
        for chunk in data.chunks(3) {
            let num: usize = [16, 8, 0]
                .iter()
                .zip(chunk.iter())
                .fold(0, |acc, (s, b)| acc + ((*b as usize) << *s));
            [18usize, 12, 6, 0]
                .iter()
                .map(|s| (num >> s) & 0b0011_1111)
                .for_each(|b| base.push(Self::encode_byte(b)));
        }

        // apply padding
        let to_pad = match data.len() % 3 {
            2 => 1,
            1 => 2,
            _ => 0,
        };
        base.iter_mut().rev().take(to_pad).for_each(|b| *b = Self::PADDING);

        match String::from_utf8(base) {
            Ok(s) => s,
            Err(e) => {
                let error = e.utf8_error();
                let valid_up_to = error.valid_up_to();
                let error_msg = format!("Fail encoding to base64: valid_up_to({})", valid_up_to);
                panic!("{}", error_msg)
            }
        }
    }

    /// decode a [`&[u8]`] from base64 based off of the URI safe character set
    pub fn decode_data(base: &[u8]) -> Result<Vec<u8>, Base64Error> {
        // find and remove padding.
        let (padded, base) = match base.iter().rev().take_while(|b| **b == Self::PADDING).count() {
            _ if base.len() % 4 != 0 => return Err(Base64Error),
            padded if padded > 2 => return Err(Base64Error),
            padded => (padded, &base[..base.len() - padded]),
        };

        // decode the data.
        let mut data = Vec::new();
        for chunk in base.chunks(4) {
            let num: usize = [18usize, 12, 6, 0]
                .iter()
                .zip(chunk.iter())
                .try_fold(0, |acc, (s, b)| Self::decode_byte(*b).map(|b| acc + (b << *s)))?;
            [16, 8, 0].iter().map(|s| (num >> s) as u8).for_each(|b| data.push(b));
        }

        // remove any trailing padding related zeroes
        data.truncate(data.len() - padded);
        Ok(data)
    }

    /// encode a single byte
    fn encode_byte(b: usize) -> u8 {
        match b {
            b @ 0..=25 => (b as u8) + b'A',
            b @ 26..=51 => (b as u8 - 26) + b'a',
            b @ 52..=61 => (b as u8 - 52) + b'0',
            62 => b'-',
            63 => b'_',
            _ => panic!("{:?} ({})", Base64Error, b),
        }
    }

    /// decode a single byte
    fn decode_byte(b: u8) -> Result<usize, Base64Error> {
        match b {
            b @ b'A'..=b'Z' => Ok((b - b'A') as usize),
            b @ b'a'..=b'z' => Ok((b - b'a') as usize + 26),
            b @ b'0'..=b'9' => Ok((b - b'0') as usize + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(Base64Error),
        }
    }
}

/// a trait to make types base64 encodable
pub trait Base64Encodable {
    fn base64(&self) -> String;
}

/// a trait to make types base64 decodable
pub trait Base64Decodable: Sized {
    type Error;
    fn from_base64(base: impl AsRef<[u8]>) -> Result<Self, Self::Error>;
}

impl<T: AsRef<[u8]>> Base64Encodable for T {
    fn base64(&self) -> String {
        Base64::encode_data(self.as_ref())
    }
}

impl Base64Decodable for Vec<u8> {
    type Error = Base64Error;
    fn from_base64(base: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        Base64::decode_data(base.as_ref())
    }
}
