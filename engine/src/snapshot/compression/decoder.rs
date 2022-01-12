// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
#[error("Lz4 Decode Failed: {0}")]
pub struct Lz4DecodeError(String);

/// Public function to decompress some data into an output.
pub fn decompress_into(input: &[u8], output: &mut Vec<u8>) -> Result<(), Lz4DecodeError> {
    Lz4Decoder {
        input,
        output,
        token: 0,
    }
    .complete()?;

    Ok(())
}

/// Decompress data using an LZ4 Algorithm.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, Lz4DecodeError> {
    let mut vec = Vec::with_capacity(4096);

    decompress_into(input, &mut vec)?;

    Ok(vec)
}

/// Lz4Decoder implementation.
struct Lz4Decoder<'a> {
    input: &'a [u8],
    output: &'a mut Vec<u8>,
    token: u8,
}

impl<'a> Lz4Decoder<'a> {
    fn take(&mut self, size: usize) -> Result<&[u8], Lz4DecodeError> {
        Self::take_internal(&mut self.input, size)
    }

    #[inline]
    fn take_internal(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], Lz4DecodeError> {
        if input.len() < size {
            Err(Lz4DecodeError("Unexpected End".into()))
        } else {
            let res = Ok(&input[..size]);

            *input = &input[size..];

            res
        }
    }

    fn output(output: &mut Vec<u8>, buf: &[u8]) {
        output.extend_from_slice(&buf[..buf.len()]);
    }

    fn duplicate(&mut self, start: usize, length: usize) {
        for i in start..start + length {
            let b = self.output[i];
            self.output.push(b);
        }
    }

    #[inline]
    fn read_int(&mut self) -> Result<usize, Lz4DecodeError> {
        let mut size = 0;

        loop {
            let extra = self.take(1)?[0];
            size += extra as usize;

            if extra != 0xFF {
                break;
            }
        }

        Ok(size)
    }

    fn read_u16(&mut self) -> Result<u16, Lz4DecodeError> {
        let bytes = self.take(2)?.try_into().expect("Conversion can never fail.");
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_literal(&mut self) -> Result<(), Lz4DecodeError> {
        let mut literal = (self.token >> 4) as usize;

        if literal == 15 {
            literal += self.read_int()?;
        }

        Self::output(self.output, Self::take_internal(&mut self.input, literal)?);

        Ok(())
    }

    fn read_duplicate(&mut self) -> Result<(), Lz4DecodeError> {
        let offset = self.read_u16()?;

        let mut length = (4 + (self.token & 0xF)) as usize;

        if length == 4 + 15 {
            length += self.read_int()?;
        }

        let start = self.output.len().wrapping_sub(offset as usize);

        if start < self.output.len() {
            self.duplicate(start, length);

            Ok(())
        } else {
            Err(Lz4DecodeError("Invalid Duplicate".into()))
        }
    }

    #[inline]
    fn complete(&mut self) -> Result<(), Lz4DecodeError> {
        while !self.input.is_empty() {
            self.token = self.take(1)?[0];

            self.read_literal()?;

            if self.input.is_empty() {
                break;
            }

            self.read_duplicate()?;
        }

        Ok(())
    }
}
