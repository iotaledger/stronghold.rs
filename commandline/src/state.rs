use std::collections::HashMap;

use crate::line_error;

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
    pub fn storage_channel() -> HashMap<Vec<u8>, Vec<u8>> {
        lazy_static!(
            HashMap::new() => HashMap<Vec<u8>, Vec<u8>>
        )
        .clone()
    }
}
