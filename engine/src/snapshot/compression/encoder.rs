// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Block, Duplicate};
use std::convert::TryInto;

/// Dictionary size.
const DICT_SIZE: usize = 4096;

/// Public function for compression some input into an output buffer.
pub fn compress_into(input: &[u8], output: &mut Vec<u8>) {
    Lz4Encoder {
        input,
        output,
        cursor: 0,
        dict: [!0; DICT_SIZE],
    }
    .complete();
}

/// Compress data using an LZ4 Algorithm.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut vec = Vec::with_capacity(input.len());

    compress_into(input, &mut vec);

    vec
}

/// Lz4Encoder implementation.
struct Lz4Encoder<'a> {
    input: &'a [u8],
    output: &'a mut Vec<u8>,
    cursor: usize,
    dict: [usize; DICT_SIZE],
}

impl<'a> Lz4Encoder<'a> {
    fn step_forward(&mut self, steps: usize) -> bool {
        for _ in 0..steps {
            self.insert_cursor();

            self.cursor += 1;
        }

        self.cursor <= self.input.len()
    }

    fn insert_cursor(&mut self) {
        if self.remaining() {
            self.dict[self.get_cursor_hash()] = self.cursor;
        }
    }

    fn remaining(&self) -> bool {
        self.cursor + 4 < self.input.len()
    }

    fn get_cursor_hash(&self) -> usize {
        let mut x = self.get_at_cursor().wrapping_mul(0xa4d94a4f);
        let a = x >> 16;
        let b = x >> 30;
        x ^= a >> b;
        x = x.wrapping_mul(0xa4d94a4f);

        x as usize % DICT_SIZE
    }

    fn get(&self, n: usize) -> u32 {
        debug_assert!(self.remaining(), "Reading a partial batch.");

        let bytes = self.input[n..n + 4].try_into().expect("Conversion can never fail.");
        u32::from_ne_bytes(bytes)
    }

    fn get_at_cursor(&self) -> u32 {
        self.get(self.cursor)
    }

    fn find_duplicate(&self) -> Option<Duplicate> {
        if !self.remaining() {
            return None;
        }

        let candidate = self.dict[self.get_cursor_hash()];

        if candidate != !0 && self.get(candidate) == self.get_at_cursor() && self.cursor - candidate <= 0xFFFF {
            let padding = self.input[self.cursor + 4..]
                .iter()
                .zip(&self.input[candidate + 4..])
                .take_while(|&(a, b)| a == b)
                .count();

            Some(Duplicate {
                offset: (self.cursor - candidate) as u16,
                padding,
            })
        } else {
            None
        }
    }

    fn write_int(&mut self, mut n: usize) {
        while n >= 0xFF {
            n -= 0xFF;
            self.output.push(0xFF);
        }

        self.output.push(n as u8);
    }

    fn pop_block(&mut self) -> Block {
        let mut lit = 0;

        loop {
            if let Some(duplicates) = self.find_duplicate() {
                self.step_forward(duplicates.padding + 4);

                return Block {
                    literal_length: lit,
                    duplicates: Some(duplicates),
                };
            }

            if !self.step_forward(1) {
                return Block {
                    literal_length: lit,
                    duplicates: None,
                };
            }

            lit += 1;
        }
    }

    fn complete(&mut self) {
        loop {
            let start = self.cursor;

            let block = self.pop_block();

            let mut token = if block.literal_length < 0xF {
                (block.literal_length as u8) << 4
            } else {
                0xF0
            };

            let dup_extra_len = block.duplicates.map_or(0, |x| x.padding);
            token |= if dup_extra_len < 0xF { dup_extra_len as u8 } else { 0xF };

            self.output.push(token);

            if block.literal_length >= 0xF {
                self.write_int(block.literal_length - 0xF);
            }

            self.output
                .extend_from_slice(&self.input[start..start + block.literal_length]);

            if let Some(Duplicate { offset, .. }) = block.duplicates {
                self.output.push(offset as u8);
                self.output.push((offset >> 8) as u8);

                if dup_extra_len >= 0xF {
                    self.write_int(dup_extra_len - 0xF);
                }
            } else {
                break;
            }
        }
    }
}
