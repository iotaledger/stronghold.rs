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

//! ## Introduction
//!
//! IOTA Stronghold is a secure software implementation with the sole purpose of isolating digital secrets from exposure
//! to hackers and accidental leaks. It uses versioned snapshots with double-encryption that can be easily backed up and
//! securely shared between devices. Written in stable rust, it has strong guarantees of memory safety and process
//! integrity. The high-level developer-friendly libraries will integrate the IOTA protocol and serve as a reference
//! implementation for anyone looking for inspiration or best-in-class tooling.
//!
//! ## WARNING
//!
//! This library has not yet been audited for security, so use at your own peril. Until a formal third-party security
//! audit has taken place, the IOTA Foundation makes no guarantees to the fitness of this library for any purposes.
//!
//! As such they are to be seen as experimental and not ready for real-world applications.
//!
//! Nevertheless, we are very interested in feedback about the design and implementation, and encourage you to reach out
//! with any concerns or suggestions you may have.

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]
mod account;

mod storage;
use engine::vault::Base64Encodable;
use storage::Storage;
pub use storage::{Base64Decodable, Id};

use account::{Account, SubAccount};

use bee_signing_ext::{binary::ed25519, Signature, Verifier};
use std::{path::Path, str};

/// Stronghold struct: Instantiation is required.
#[derive(Default)]
pub struct Stronghold {
    storage: Storage,
}

/// Main stronghold implementation
impl Stronghold {
    /// Instantiates Stronghold
    ///
    /// Use `snapshot_path` to set the snapshot file path
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// ```
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

    /// Removes an existing account from the snapshot.
    ///
    /// Given the `account id` of the account to remove and the `snapshot password` needed for decrypt the snapshot,
    /// searches and removes it from the snapshot file.
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// stronghold.account_remove(
    ///     "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1",
    ///     "c/7f5cf@faaf$e2c%c588d",
    /// );
    /// ```
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

    /// Lists ids of accounts.
    ///
    /// Given the `snapshot password` to decrypt the snapshot, and `skip` and `limit` parameters to efficiently
    /// paginate results.
    ///
    /// `skip` is used to avoid retrieving ids from the start.
    ///
    /// `limit` is used to avoid retrieving the entire list of ids until the end.
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let index: Vec<String> = stronghold.index_get("c/7f5cf@faaf$e2c%c588d", 0, 30);
    /// ```
    pub fn index_get(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec<String> {
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

    /// Lists accounts
    ///
    /// Given the `snapshot password` to decrypt the snapshot, and `skip` and `limit` parameters to efficiently
    /// paginate results.
    ///
    /// `skip` is used to avoid retrieving ids from the start.
    ///
    /// `limit` is used to avoid retrieving the entire list of ids until the end.
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let index: Vec<String> = stronghold.index_get("c/7f5cf@faaf$e2c%c588d", 0, 30);
    /// ```
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

    /// Creates new account saving it
    ///
    /// Given an optional `bip39 passphrase` and a required `snapshot password`, creates a new account saving it in the
    /// snapshot file.
    ///
    /// If you use `bip39 passphrase`, it will salt the generated mnemonic according to BIP39.
    ///
    /// `snapshot password` will be used for decrypt/encrypt the data in the snapshot file.
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let bip39_passphrase = Some(String::from("ieu73jdumf"));
    /// let snapshot_password = "c/7f5cf@faaf$e2c%c588d";
    /// let account = stronghold.account_create(bip39_passphrase, &snapshot_password);
    /// ```
    pub fn account_create(&self, bip39_passphrase: Option<String>, snapshot_password: &str) -> Account {
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: Password is missing");
        }
        let account = Account::new(bip39_passphrase);
        self.account_save(&account, snapshot_password);
        account
    }

    /// Imports an existing external account to the snapshot file
    ///
    /// # Some data is required:
    ///
    /// `created_data` date and time in unix epoch in ms of when the account was created.
    ///
    /// `last_updated_on` date and time in unix epoch in ms of when the account had its last update.
    ///
    /// `bip39_mnemonic` word list that is space separated.
    ///
    /// `bip39_passphrase` used to salt the master seed generation. Optional parameter but essential if you had a
    /// passphrase, otherwise you won't be able to correctly access your wallet.
    ///
    /// `snapshot_password` password required for decrypt/encrypt the snapshot file.
    ///
    /// `sub_accounts` set of SubAccounts belonging to the account
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let mnemonic = String::from("gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding");
    /// let snapshot_password = "i:wj38siqo378e54e$";
    /// let sub_accounts = Vec::new();
    /// let account = stronghold.account_import(1598890069000, 1598890070000, mnemonic, None, &snapshot_password, sub_accounts);
    /// ```
    pub fn account_import(
        // todo: reorder params , ¿what if try to add an account by second time?
        &self,
        created_at: u128,      // todo: maybe should be optional
        last_updated_on: u128, // todo: maybe should be optional
        bip39_mnemonic: String,
        bip39_passphrase: Option<&str>,
        snapshot_password: &str,
        sub_accounts: Vec<SubAccount>, // todo: maybe should be optional?
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

    /// Returns an account by its id
    ///
    /// `account_id` account id to export
    ///
    /// `snapshot_password` required to decrypt the snapshot file
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let account_id = "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1";
    /// let snapshot_password = "su3jA8kdD4nf:83";
    /// let account = stronghold.account_export(&account_id, &snapshot_password);
    /// ```
    pub fn account_export(&self, account_id: &str, snapshot_password: &str) -> Account {
        // todo: maybe should be renamed to account_get(): an export process has a destiny, this function not
        self.account_get_by_id(account_id, snapshot_password)
    }

    /// Updates an account
    pub fn account_update(&self, account: &mut Account, snapshot_password: &str) -> storage::Id {
        // todo: switch to private fn
        let record_id = self.record_get_by_account_id(&account.id(), &snapshot_password);
        self.record_remove(record_id, &snapshot_password);
        account.last_updated_on(true);
        self.account_save(&account, &snapshot_password)
    }

    /// Adds a subaccount to an account
    ///
    /// Specify the stored account with its id (`account_id`) , `snapshot_password` is required to decrypt/encrypt the
    /// snapshot file.
    ///
    /// `label` the name that you want to call it, only for anecdotal purpose
    ///
    /// `account_id` id of the account to which a subaccount will be added
    ///
    /// `snapshot_password` password required for decrypt/encrypt snapshot file
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// stronghold.subaccount_add(
    ///     "savings",
    ///     "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1",
    ///     "suHyeJdnJuJNU34;23",
    /// );
    /// ```
    pub fn subaccount_add(&self, label: &str, account_id: &str, snapshot_password: &str) -> storage::Id {
        // todo: remove return
        let mut account = self.account_get_by_id(&account_id, snapshot_password);
        let subaccount = SubAccount::new(String::from(label));
        account.add_sub_account(subaccount);
        self.account_update(&mut account, snapshot_password)
    }

    /// Switches the visibility of a subaccount
    ///
    /// The subaccount won't be erased.
    ///
    /// `account_id` id of the account, is required to identify the stored account.
    ///
    /// `sub_account_index` subaccount number, required in order to identify which subaccount
    ///
    /// `visible` if the subaccount should be visible or not
    ///
    /// `snapshot_password` password required to decrypt/encrypt the snapshot file
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let account_id = "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1";
    /// let sub_account_index = 1;
    /// let visible = false;
    /// let snapshot_password = "duajwYh442875";
    /// stronghold.subaccount_hide(&account_id, sub_account_index, visible, &snapshot_password);
    /// ```
    pub fn subaccount_hide(&self, account_id: &str, sub_account_index: usize, visible: bool, snapshot_password: &str) {
        let mut account = self.account_get_by_id(&account_id, snapshot_password);
        let sub_account = &mut account.get_sub_account(sub_account_index);
        sub_account.set_display(visible);
        self.account_update(&mut account, snapshot_password);
    }

    /// Get an address
    ///
    /// Given an account id (`account_id`) and a derivation path (composed by `sub_account_index` and `internal`)
    /// returns an address and its index.
    ///
    /// `account_id` id of the account to which the address has to belong
    ///
    /// `sub_account_index` number of subaccount to which the address has to belong
    ///
    /// `internal` chain to which the address has to belong (internal:false for receiving address and external:true
    /// to change addresses)
    ///
    /// `snapshot_password` password required to decrypt/encrypt the snapshot file
    ///
    /// For additional check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" for a master seed and "subaccount" for a bip39 account)
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let address = stronghold.address_get(
    ///     "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1",
    ///     1,
    ///     true,
    ///     "si/(3jfiudmeiKSie",
    /// );
    /// ```
    pub fn address_get(
        // todo: rename to address_get_new?
        // todo: having to indicate the derivation path maybe is a much too low
        // level thing
        &self,
        account_id: &str,
        sub_account_index: usize,
        internal: bool,
        snapshot_password: &str,
    ) -> (usize, String) {
        let mut account = self.account_get_by_id(account_id, snapshot_password);
        let sub_account = &mut account.get_sub_account(sub_account_index);
        let index = sub_account.addresses_increase_counter(internal);
        let address = account.get_address(format!(
            "m/44'/4218'/{}'/{}'/{}'",
            sub_account_index, !internal as u32, index
        ));
        self.account_update(&mut account, snapshot_password);
        (index, address)
    }

    /// Signs a message
    ///
    /// Given the certain details of the private key to be used for signing, returns the message signature
    ///
    /// `message` message to sign
    ///
    /// `account_id` id of the account which the private key that has to belong
    ///
    /// `sub_account_index` number of subaccount to which the private key has to belong
    ///
    /// `internal` chain to which the private key has to belong
    ///
    /// `index` number of address that has to be
    ///
    /// For additional check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" a master seed and "subaccount" a bip39 account)
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let message = "With this signed message you can verify my address ownership".as_bytes();
    /// let account_id = "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1";
    /// let sub_account_index = 0;
    /// let internal = false;
    /// let index = 0;
    /// let snapshot_password = "iKuwjMdnwI";
    /// let signature = stronghold.signature_make(
    ///     &message,
    ///     &account_id,
    ///     sub_account_index,
    ///     internal,
    ///     index,
    ///     snapshot_password,
    /// );
    /// ```
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

    /// Verifies a signature
    ///
    /// Given a `signature` you can verify if a `message` belongs to an identity (`address`)
    ///
    /// `address` the address to which the signature is supposed to belong
    ///
    /// `message` the message to which the signature is supposed to belong
    ///
    /// `signature` the signature to verify
    ///
    /// # Example
    /// ```
    /// use stronghold::Stronghold;
    /// let address = "iot1q8knfu2rq8k9tlasfqrh38zmvfqhx5zvm9ehtzmdz3zg7yqv9kllywktkn3";
    /// let message = "With this signed message you can verify my address ownership";
    /// let signature = "nd2oqe4wRhnqsckDZGZQPkpR0nC+jxQQiVjrFvfLfskCk9MItvrommcz5tkhq94Lx+Z1eZleV3pZtChhnWfNAA==";
    /// let is_legit = Stronghold::signature_verify(&address, &message, &signature);
    /// ```
    pub fn signature_verify(address: &str, message: &str, signature: &str) {
        // signature treatment
        let signature_bytes = base64::decode(signature).expect("Error decoding base64");
        let signature =
            ed25519::Ed25519Signature::from_bytes(&signature_bytes).expect("Error decoding bytes into signature");

        // address treatment
        let (hrp, bech32_data_u5) = bech32::decode(address).expect("Invalid address");
        let mut bech32_data_bytes =
            bech32::convert_bits(bech32_data_u5.as_ref(), 5, 8, false).expect("Error decoding bech32");
        let address_type = bech32_data_bytes.remove(0);
        if address_type == 0 {
            panic!("ed25519 version address expected , WOTS version address found");
        };
        if address_type != 1 {
            panic!("ed25519 address expected , unknown version address found");
        };
        let public_bytes = bech32_data_bytes.as_ref();
        let public_key =
            ed25519::Ed25519PublicKey::from_bytes(public_bytes).expect("Error decoding data into public key");

        // verification
        public_key
            .verify(message.as_bytes(), &signature)
            .expect("Error verifying signature")
    }

    /// Saves custom data as a new record from the snapshot
    ///
    /// `label`: a name for handling and anecdotal purposes
    ///
    /// `data`: data that will contain the record
    ///
    /// `snapshot_password` password required to decrypt/encrypt the snapshot file
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let label = "colors";
    /// let data = "red,white,violet";
    /// let snapshot_password = "uJsuMnwUIoLkdmw";
    /// let record_id = stronghold.record_create(&label, &data, &snapshot_password);
    /// ```
    pub fn record_create(&self, label: &str, data: &str, snapshot_password: &str) -> storage::Id {
        self.storage.encrypt(label, data, snapshot_password)
    }

    /// Get record by record id
    ///
    /// `record_id` id of the record to read
    ///
    /// `snapshot_password` required password to decrypt snapshot file
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let label = "colors";
    /// let data = "red,white,violet";
    /// let snapshot_password = "uJsuMnwUIoLkdmw";
    /// let record_id = stronghold.record_create(&label, &data, &snapshot_password);
    ///
    /// let record = stronghold.record_read(&record_id, &snapshot_password);
    /// ```
    pub fn record_read(&self, record_id: &storage::Id, snapshot_password: &str) -> String {
        self.storage.read(*record_id, snapshot_password)
    }

    /// Searches record id by account id
    ///
    /// `account_id_target` the id of the account to search
    ///
    /// `snapshot_password` password required to decrypt/encrypt the snapshot file
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let id = stronghold.record_get_by_account_id(
    ///     "7c1a5ce9cc8f57f8739634aefbafda9eba6a02f82e3a4ab825ed296274e3aca1",
    ///     "suEu38kQmsn$eu",
    /// );
    /// ```
    pub fn record_get_by_account_id(&self, account_id_target: &str, snapshot_password: &str) -> storage::Id {
        let account_id_target = account_id_target.as_bytes().base64();
        // todo: rename account_id_target to just account_id
        let index = self.storage.get_index(snapshot_password);
        for (record_id, account_id) in index {
            if format!("{:?}", account_id) == account_id_target {
                return record_id;
            }
        }
        panic!("Unable to find record id with specified account id");
    }

    /// Removes record from storage by record id
    ///
    /// `record_id` id of the record to remove
    ///
    /// `snapshot_password` password required to decrypt/encrypt the snapshot file
    ///
    /// # Example
    /// ```no_run
    /// use stronghold::Stronghold;
    /// let stronghold = Stronghold::new("savings.snapshot");
    /// let label = "colors";
    /// let data = "red,white,violet";
    /// let snapshot_password = "uJsuMnwUIoLkdmw";
    /// let id = stronghold.record_create(&label, &data, &snapshot_password);
    /// stronghold.record_remove(id, &snapshot_password);
    /// ```
    pub fn record_remove(&self, record_id: storage::Id, snapshot_password: &str) {
        self.storage.revoke(record_id, snapshot_password);
        self.storage.garbage_collect_vault(snapshot_password);
    }

    // todo: add fn record_read(enum storage id or label)
    // todo: add fn record_update()

    // pub fn message_decrypt() {
    //
    // }
}

#[cfg(test)]
pub mod test_utils {
    use engine::snapshot::snapshot_dir;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
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
