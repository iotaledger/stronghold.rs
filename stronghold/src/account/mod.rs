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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

mod dummybip39;
use bee_signing_ext::{binary::ed25519, Signer};
use dummybip39::{dummy_derive_into_address, dummy_mnemonic_to_ed25_seed};

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    id: String,
    external: bool,
    created_at: u128,
    last_updated_on: u128,
    bip39_mnemonic: String,
    bip39_passphrase: Option<String>,
    sub_accounts: Vec<SubAccount>,
}

pub(in crate) fn generate_id(bip39_mnemonic: &str, bip39_passphrase: &Option<String>) -> String {
    // Account ID generation: 1/2 : Derive seed into the first address
    let seed;
    if let Some(bip39_passphrase) = bip39_passphrase {
        seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, &bip39_passphrase);
    } else {
        seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, "");
    }
    let privkey =
        ed25519::Ed25519PrivateKey::generate_from_seed(&seed, "M/44H/4218H/0H/0H").expect("Error deriving seed");
    let address = dummy_derive_into_address(privkey);

    // Account ID generation: 2/2 : Hash generated address in order to get ID
    let mut hasher = Sha256::new();
    hasher.input(address);
    hex::encode(&hasher.result())
}

impl Account {
    pub fn new(bip39_passphrase: Option<String>) -> Account {
        // Mnemonic generation
        let bip39_mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English);

        // ID generation
        let id = generate_id(&bip39_mnemonic.phrase(), &bip39_passphrase);

        Account {
            id,
            external: false,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis(),
            last_updated_on: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis(),
            bip39_mnemonic: String::from(
                bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English).phrase(),
            ),
            bip39_passphrase,
            sub_accounts: Vec::new(),
        }
    }

    pub fn import(
        created_at: u128,
        last_updated_on: u128,
        bip39_mnemonic: String,
        bip39_passphrase: Option<String>,
        sub_accounts: Vec<SubAccount>,
    ) -> Account {
        bip39::Mnemonic::from_phrase(&bip39_mnemonic, bip39::Language::Spanish).expect("Invalid mnemonic");
        // ID generation
        let id = generate_id(&bip39_mnemonic, &bip39_passphrase);
        Account {
            id,
            external: true,
            created_at,
            last_updated_on,
            bip39_mnemonic,
            bip39_passphrase,
            sub_accounts,
        }
    }

    fn get_seed(&self) -> ed25519::Ed25519Seed {
        let bip39_passphrase = match &self.bip39_passphrase {
            Some(x) => x,
            None => "",
        };
        dummy_mnemonic_to_ed25_seed(&self.bip39_mnemonic, &bip39_passphrase)
    }

    pub fn add_subaccount(&mut self, label: String) {
        self.sub_accounts.push(SubAccount::new(label))
    }

    fn get_privkey(&self, derivation_path: String) -> ed25519::Ed25519PrivateKey {
        let seed = self.get_seed();
        ed25519::Ed25519PrivateKey::generate_from_seed(&seed, &derivation_path).expect("Error deriving seed")
    }

    pub fn get_address(&self, derivation_path: String) -> String {
        let privkey = self.get_privkey(derivation_path);
        dummy_derive_into_address(privkey)
    }

    pub fn sign_message(&self, message: &[u8], derivation_path: String) -> [u8; 64] {
        let privkey = self.get_privkey(derivation_path);
        privkey.sign(message).to_bytes()
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn add_sub_account(&mut self, sub_account: SubAccount) {
        self.sub_accounts.push(sub_account);
    }

    pub fn get_sub_account(&mut self, index: usize) -> &mut SubAccount {
        &mut self.sub_accounts[index]
    }

    pub fn last_updated_on(&mut self, update: bool) -> &u128 {
        if update {
            self.last_updated_on = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis()
        };
        &self.last_updated_on
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubAccount {
    label: String,
    receive_addresses_counter: usize,
    change_addresses_counter: usize,
    visible: bool,
}

impl SubAccount {
    pub fn new(label: String) -> Self {
        Self {
            label,
            receive_addresses_counter: 0,
            change_addresses_counter: 0,
            visible: true,
        }
    }

    pub fn addresses_increase_counter(&mut self, internal: bool) -> usize {
        if internal {
            self.change_addresses_counter += 1;
            self.change_addresses_counter
        } else {
            self.receive_addresses_counter += 1;
            self.receive_addresses_counter
        }
    }

    pub fn set_display(&mut self, visible: bool) {
        self.visible = visible;
    }
}
