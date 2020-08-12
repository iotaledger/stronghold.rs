use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SubAccount {
    label: String,
    receive_addresses_counter: usize,
    change_addresses_counter: usize,
    transactions: Vec<String>//maybe TODO: Improve performance using TryteBuff instead String
}

impl SubAccount {
    pub fn new(label: String) -> Self {
        Self {
            label,
            receive_addresses_counter: 0,
            change_addresses_counter: 0,
            transactions: Vec::new()
        }
    }
}
