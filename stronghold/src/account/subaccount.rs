use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SubAccount {
    label: String,
    receive_addresses_counter: usize,
    change_addresses_counter: usize
}

impl SubAccount {
    pub fn new(label: String) -> Self {
        Self {
            label,
            receive_addresses_counter: 0,
            change_addresses_counter: 0
        }
    }

    pub fn addresses_increase_counter(&mut self, internal: bool) -> usize {
        if internal {
            self.change_addresses_counter = self.change_addresses_counter + 1;
            return self.change_addresses_counter;
        }else{
            self.receive_addresses_counter = self.receive_addresses_counter + 1;
            return self.receive_addresses_counter;
        }
    }
}
