// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use engine::vault::Kind;

use crate::line_error;

type StateHashMap = HashMap<(Kind, Vec<u8>), Vec<u8>>;

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
    pub fn storage_map() -> Arc<RwLock<StateHashMap>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<StateHashMap>>
        )
        .clone()
    }

    // offload the hashmap data.
    pub fn offload_data() -> StateHashMap {
        let mut map: StateHashMap = HashMap::new();
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
    pub fn upload_data(map: StateHashMap) {
        map.into_iter().for_each(|(k, v)| {
            State::storage_map().write().expect("couldn't open map").insert(k, v);
        });
    }
}
