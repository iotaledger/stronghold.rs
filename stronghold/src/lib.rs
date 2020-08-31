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

//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage; // storage will be saving records with accounts as jsons
use storage::Storage;
pub use storage::{Base64Decodable, Id};

use account::{Account, SubAccount};
use bee_signing_ext::{binary::ed25519, Signature, Verifier};
use std::{path::Path, str};

/// Stronghold doc com
#[derive(Default)]
pub struct Stronghold {
    storage: Storage,
}

impl Stronghold {
    pub fn new<P: AsRef<Path>>(snapshot_path: P) -> Self {
        Self {
            storage: Storage::new(snapshot_path),
        }
    }

    // Decode record into account
    fn account_from_json(&self, decrypted: &str) -> Account {
        let x: Account = serde_json::from_str(&decrypted).expect("Error reading record from snapshot");
        x
    }

    // Get account by account id
    fn account_get_by_id(&self, account_id: &str, snapshot_password: &str) -> Account {
        let index = self.storage.get_index(snapshot_password);
        let account: Option<Account>;
        let record_id = self.record_get_by_account_id(account_id, snapshot_password);
        let decrypted = self.storage.read(record_id, snapshot_password);
        self.account_from_json(&decrypted)
    }

    // Get account by record id
    fn account_get_by_record_id(&self, record_id: &storage::Id, snapshot_password: &str) -> Account {
        let decrypted = self.storage.read(*record_id, snapshot_password);
        self.account_from_json(&decrypted)
    }

    // Remove existent account
    pub fn account_remove(&self, account_id: &str, snapshot_password: &str) {
        let record_id = self.record_get_by_account_id(account_id, snapshot_password);
        let account = self.account_get_by_record_id(&record_id, snapshot_password);
        self.storage.revoke(record_id, snapshot_password);
        self.storage.garbage_collect_vault(snapshot_password);
    }

    // Save account in a new record
    fn account_save(&self, account: &Account, snapshot_password: &str) -> storage::Id {
        let account_serialized = serde_json::to_string(account).expect("Error saving account in snapshot");
        self.storage
            .encrypt(&account.id(), &account_serialized, snapshot_password)
    }

    // List ids of accounts
    pub fn account_index_get(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec<String> {
        let mut account_ids = Vec::new();
        for (i, (_, account_id)) in self.storage.get_index(snapshot_password).into_iter().enumerate() {
            if i < skip {
                continue;
            }
            if i >= limit {
                break;
            }
            account_ids.push(format!("{:?}", account_id));
        }
        account_ids
    }

    // List accounts
    pub fn account_list(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec<Account> {
        let mut accounts = Vec::new();
        for (i, (record_id, _)) in self.storage.get_index(snapshot_password).into_iter().enumerate() {
            if i < skip {
                continue;
            }
            if i >= limit {
                break;
            }
            accounts.push(self.account_get_by_record_id(&record_id, snapshot_password));
        }
        accounts
    }

    // Create new account saving it
    pub fn account_create(&self, bip39_passphrase: Option<String>, snapshot_password: &str) -> Account {
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: Password is missing");
        }
        let account = Account::new(bip39_passphrase);
        self.account_save(&account, snapshot_password);
        account
    }

    // Import new account saving it
    pub fn account_import(
        &self,
        created_at: u128,
        last_updated_on: u128,
        bip39_mnemonic: String,
        bip39_passphrase: Option<&str>,
        snapshot_password: &str,
        sub_accounts: Vec<SubAccount>,
    ) -> Account {
        if bip39_mnemonic.is_empty() {
            panic!("Invalid parameters: bip39_mnemonic is missing");
        }
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: password is missing");
        }

        let bip39_passphrase = match bip39_passphrase {
            Some(x) => Some(String::from(x)),
            None => None,
        };

        let account = Account::import(
            created_at,
            last_updated_on,
            bip39_mnemonic,
            bip39_passphrase,
            sub_accounts,
        );

        self.account_save(&account, snapshot_password);

        account
    }

    // Returns an account by account id (increases the stored export counter)
    pub fn account_export(&self, account_id: &str, snapshot_password: &str) -> Account {
        self.account_get_by_id(account_id, snapshot_password)
    }

    // Updates an account migrating its record
    pub fn account_update(&self, account: &mut Account, snapshot_password: &str) -> storage::Id {
        let record_id = self.record_get_by_account_id(&account.id(), &snapshot_password);
        self.record_remove(record_id, &snapshot_password);
        account.last_updated_on(true);
        self.account_save(&account, &snapshot_password)
    }

    // Adds subaccount updating an account
    pub fn subaccount_add(&self, label: &str, account_id: &str, snapshot_password: &str) -> storage::Id {
        let mut account = self.account_get_by_id(&account_id, snapshot_password);
        let subaccount = SubAccount::new(String::from(label));
        account.add_sub_account(subaccount);
        self.account_update(&mut account, snapshot_password)
    }

    // Show/Hide subaccount
    pub fn subaccount_hide(&self, account_id: &str, sub_account_index: usize, visible: bool, snapshot_password: &str) {
        let mut account = self.account_get_by_id(&account_id, snapshot_password);
        let sub_account = &mut account.get_sub_account(sub_account_index);
        sub_account.set_display(visible);
        self.account_update(&mut account, snapshot_password);
    }

    // Returns a new address and updates the account
    pub fn address_get(
        &self,
        account_id: &str,
        sub_account_index: usize,
        internal: bool,
        snapshot_password: &str,
    ) -> String {
        let mut account = self.account_get_by_id(account_id, snapshot_password);
        let sub_account = &mut account.get_sub_account(sub_account_index);
        let index = sub_account.addresses_increase_counter(internal);
        let address = account.get_address(format!(
            "m/44'/4218'/{}'/{}'/{}'",
            sub_account_index, !internal as u32, index
        ));
        self.account_update(&mut account, snapshot_password);
        address
    }

    // Signs a message
    pub fn signature_make(
        &self,
        message: &[u8],
        account_id: &str,
        sub_account_index: usize,
        internal: bool,
        index: usize,
        snapshot_password: &str,
    ) -> String {
        let account = self.account_get_by_id(account_id, snapshot_password);
        let signature: Vec<u8> = account
            .sign_message(
                message,
                format!("m/44'/4218'/{}'/{}'/{}'", sub_account_index, !internal as u32, index),
            )
            .to_vec();
        base64::encode(signature)
    }

    // Verify a signature
    pub fn signature_verify(&self, address: &str, message: &str, signature: &str) {
        // signature treatment
        let bytes = base64::decode(message).expect("Error decoding base64");
        let signature = ed25519::Ed25519Signature::from_bytes(&bytes).expect("Error decoding bytes into signature");

        // address treatment
        let (hrp, data_u5) = bech32::decode(address).expect("Invalid address");
        let mut data = bech32::convert_bits(data_u5.as_ref(), 5, 8, true).expect("Error decoding bech32");
        let address_type = data.remove(0);
        if address_type == 0 {
            panic!("ed25519 version address expected , WOTS version address found");
        };
        if address_type != 1 {
            panic!("ed25519 address expected , unknown version address found");
        };
        let public_key =
            ed25519::Ed25519PublicKey::from_bytes(data.as_ref()).expect("Error decoding data into public key");

        // verification
        public_key
            .verify(&bytes, &signature)
            .expect("Error verifying signature")
    }

    // Save custom data in as a new record from the snapshot
    pub fn record_create(&self, label: &str, data: &str, snapshot_password: &str) -> storage::Id {
        self.storage.encrypt(label, data, snapshot_password)
    }

    // Get record by id
    pub fn record_read(&self, record_id: &storage::Id, snapshot_password: &str) -> String {
        self.storage.read(*record_id, snapshot_password)
    }

    // Find record id by account id
    fn record_get_by_account_id(&self, account_id_target: &str, snapshot_password: &str) -> storage::Id {
        let index = self.storage.get_index(snapshot_password);
        for (record_id, account_id) in index {
            if format!("{:?}", account_id) == account_id_target {
                return record_id;
            }
        }
        panic!("Unable to find record id with specified account id");
    }

    // Removes record from storage by record id
    pub fn record_remove(&self, record_id: storage::Id, snapshot_password: &str) {
        self.storage.revoke(record_id, snapshot_password);
        self.storage.garbage_collect_vault(snapshot_password);
    }

    // pub fn message_decrypt() {
    //
    // }
}

#[cfg(test)]
pub mod test_utils {
    use engine::snapshot::snapshot_dir;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::path::PathBuf;

    pub fn with_snapshot<F: FnOnce(&PathBuf)>(cb: F) {
        let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
        let snapshot_path = snapshot_dir()
            .expect("failed to get snapshot dir")
            .join(snapshot_filename);
        cb(&snapshot_path);
        let _ = std::fs::remove_file(snapshot_path);
    }
}

#[cfg(test)]
mod tests {
    use super::Stronghold;

    #[test]
    fn create_record() {
        super::test_utils::with_snapshot(|path| {
            let stronghold = Stronghold::new(path);
            let value = "value_to_encrypt";
            let id = stronghold.record_create("", value, "password");

            let read = stronghold.record_read(&id, "password");
            assert_eq!(read, value);
        });
    }
}
