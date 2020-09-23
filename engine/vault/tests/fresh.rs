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

use rand::Rng;
use std::iter::repeat;

use vault::RecordHint;

pub fn data() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let l = rng.gen_range(0, 3)*rng.gen_range(1, 28);
    let mut bs: Vec<u8> = repeat(0u8).take(l).collect();
    rng.fill(&mut bs[..]);
    bs
}

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
    bs.into()
}
