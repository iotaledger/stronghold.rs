use std::collections::HashMap;

use std::sync::{Arc, RwLock};

use crate::line_error;

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
    pub fn backup_map() -> Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>
        )
        .clone()
    }
}
