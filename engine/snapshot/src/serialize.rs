// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::{collections::HashMap, convert::TryInto};

/// helpers to work with hashmaps in the snapshot. Serialize and Deserialize a HashMap of data.

/// serialize a hashmap
pub fn serialize_map(map: &HashMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    map.iter().fold(Vec::new(), |mut acc, (k, v)| {
        acc.extend(&k.len().to_le_bytes());
        acc.extend(k.as_slice());
        acc.extend(&v.len().to_le_bytes());
        acc.extend(v.as_slice());
        acc
    })
}

// deseralize a hashmap
pub fn deserialize_buffer(bytes: &[u8]) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut map = HashMap::new();

    let mut left = &bytes[..];
    while !left.is_empty() {
        let k = read_buffer(&mut left);
        let v = read_buffer(&mut left);
        map.insert(k, v);
    }

    map
}

/// read the buffer.
fn read_buffer(input: &mut &[u8]) -> Vec<u8> {
    let (len, rest) = input.split_at(std::mem::size_of::<usize>());
    let len = usize::from_le_bytes(len.try_into().unwrap());
    let (v, rest) = rest.split_at(len);
    *input = rest;
    v.to_vec()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let mut map = HashMap::new();
        map.insert(vec![32, 1, 53], vec![39, 43, 5]);
        map.insert(vec![52, 13, 53, 53], vec![31, 1]);
        map.insert(vec![142], vec![1, 0, 125, 82, 13, 54, 69]);

        let buf = serialize_map(&map);
        let recovered = deserialize_buffer(&buf);

        println!("{:?}, {:?}", buf, recovered);

        assert_eq!(map, recovered);
    }
}
