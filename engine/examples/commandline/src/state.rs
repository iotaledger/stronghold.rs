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

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use engine::vault::Kind;

use crate::line_error;

// lazy static macro
#[macro_export]
macro_rules! lazy_static {
    ($init:expr => $type:ty) => {{
        static mut VALUE: Option<$type> = None;
        static INIT: std::sync::Once = std::sync::Once::new();

        INIT.call_once(|| unsafe { VALUE = Some($init) });
        unsafe { VALUE.as_ref() }.expect(line_error!())
    }};
}

pub struct State;
impl State {
    // lazy static global hashmap
    pub fn storage_map() -> Arc<RwLock<HashMap<(Kind, Vec<u8>), Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<HashMap<(Kind, Vec<u8>), Vec<u8>>>>
        )
        .clone()
    }

    // offload the hashmap data.
    pub fn offload_data() -> HashMap<(Kind, Vec<u8>), Vec<u8>> {
        let mut map: HashMap<(Kind, Vec<u8>), Vec<u8>> = HashMap::new();
        State::storage_map()
            .write()
            .expect("failed to read map")
            .clone()
            .into_iter()
            .for_each(|(k, v)| {
                map.insert(k, v);
            });

        map
    }

    // upload data to the hashmap.
    pub fn upload_data(map: HashMap<(Kind, Vec<u8>), Vec<u8>>) {
        map.into_iter().for_each(|(k, v)| {
            State::storage_map().write().expect("couldn't open map").insert(k, v);
        });
    }
}
