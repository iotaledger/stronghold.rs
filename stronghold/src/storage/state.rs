use std::collections::HashMap;

use std::sync::{Arc, RwLock};

use crate::line_error;

/// lazy static macro
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
    pub fn storage_map() -> Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>
        )
        .clone()
    }

    // offload the hashmap data.
    pub fn offload_data() -> HashMap<Vec<u8>, Vec<u8>> {
        let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
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
    pub fn upload_data(map: HashMap<Vec<u8>, Vec<u8>>) {
        map.into_iter().for_each(|(k, v)| {
            State::storage_map().write().expect("couldn't open map").insert(k, v);
        });
    }
}
