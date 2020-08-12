use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Subaccount {
    label: String,
    receive_addresses_counter: usize,
    change_addresses_counter: usize
    //transactions: Vec<Transaction>
}

impl Subaccount {
    pub fn new(label: String) -> Self {
        Self {
            label,
            receive_addresses_counter: 0,
            change_addresses_counter: 0
        }
    }
}
