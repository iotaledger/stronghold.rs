use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

macro_rules! lazy_static {
    ($init:expr => $type:ty) => {{
        static mut VAL: Option<$type> = None;
        static INIT: std::sync::Once = std::sync::Once::new();

        INIT.call_once(|| unsafe { VAL = Some($init) });
        unsafe { VAL.as_ref() }.expect(line_error!())
    }};
}

pub struct Env;

impl Env {
    pub fn get_storage() -> Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>
        )
        .clone()
    }
}
