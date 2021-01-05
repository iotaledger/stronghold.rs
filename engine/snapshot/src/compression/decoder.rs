// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

pub fn decompress_into(input: &[u8], output: &mut Vec<u8>) -> crate::Result<()> {
    LZ4Decoder {
        input,
        output,
        token: 0,
    }
    .complete()?;

    Ok(())
}

pub fn decompress(input: &[u8]) -> crate::Result<Vec<u8>> {
    let mut vec = Vec::with_capacity(4096);

    decompress_into(input, &mut vec)?;

    Ok(vec)
}

struct LZ4Decoder<'a> {
    input: &'a [u8],
    output: &'a mut Vec<u8>,
    token: u8,
}

impl<'a> LZ4Decoder<'a> {
    fn take(&mut self, size: usize) -> crate::Result<&[u8]> {
        Self::take_internal(&mut self.input, size)
    }

    #[inline]
    fn take_internal(input: &mut &'a [u8], size: usize) -> crate::Result<&'a [u8]> {
        if input.len() < size {
            Err(crate::Error::LZ4Error("Unexpected End".into()))
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
    fn read_int(&mut self) -> crate::Result<usize> {
        let mut size = 0;

        while {
            let extra = self.take(1)?[0];
            size += extra as usize;

            extra == 0xFF
        } {}

        Ok(size)
    }

    fn read_u16(&mut self) -> crate::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes(bytes.try_into()?))
    }

    fn read_literal(&mut self) -> crate::Result<()> {
        let mut literal = (self.token >> 4) as usize;

        if literal == 15 {
            literal += self.read_int()?;
        }

        Self::output(&mut self.output, Self::take_internal(&mut self.input, literal)?);

        Ok(())
    }

    fn read_duplicate(&mut self) -> crate::Result<()> {
        let offset = self.read_u16()?;

        let mut length = (4 + (self.token & 0xF)) as usize;

        if length == 4 + 15 {
            length += self.read_int()?;
        }

        let start = self.output.len().wrapping_sub(offset as usize);

        if start < self.output.len() {
            // Write the duplicate segment to the output buffer.
            self.duplicate(start, length);

            Ok(())
        } else {
            Err(crate::Error::LZ4Error("Invalid Duplicate".into()))
        }
    }

    #[inline]
    fn complete(&mut self) -> crate::Result<()> {
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
