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
pub use account::Account;
use anyhow::{anyhow, Context, Result};
use bee_signing_ext::{binary::ed25519, Signature, Verifier};
pub use engine::crypto::Error as CryptoError;
pub use engine::snapshot::Error as SnapshotError;
pub use engine::vault::Error as VaultError;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::BTreeMap, path::Path, str};
use storage::Storage;
pub use storage::{Base64Decodable, RecordHint, RecordId};

static INDEX_HINT: &str = "index";

/// Stronghold struct: Instantiation is required.
#[derive(Default)]
pub struct Stronghold {
    storage: Storage,
    snapshot_password: Arc<Lazy<Mutex<(String, Option<u64>)>>>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
/// Stronghold index;
pub struct Index(BTreeMap<String, RecordId>);

impl Index {
    fn new() -> Self {
        Default::default()
    }

    fn includes(&self, account_id: &[u8; 32]) -> bool {
        self.0.contains_key(&hex::encode(account_id))
    }

    fn add_account(&mut self, account_id: &[u8; 32], record_id: RecordId) {
        self.0.insert(hex::encode(account_id), record_id);
    }

    // Changes the record_id of a given account id in the index
    fn update_account(&mut self, account_id: &[u8; 32], new_record_id: RecordId) {
        if let Some(account_id) = self.0.get_mut(&hex::encode(account_id)) {
            *account_id = new_record_id;
        };
    }

    fn remove_account(&mut self, account_id: &[u8; 32]) {
        self.0.remove(&hex::encode(account_id));
    }
}

/// Main stronghold implementation
impl Stronghold {
    /// Instantiates Stronghold
    ///
    /// Use `snapshot_path` to set the snapshot file path
    ///
    /// # Parameters
    ///
    /// `snapshot_path`: Location in the file system.
    ///
    /// `snapshot_create`: Should be true if want to create a new empty snapshot or false if you are opening an existing one.
    ///
    /// `snapshot_password`: Password to use for encrypt/decrypt the snapshot file.
    ///
    /// `snapshot_password_timeout`: How much time (in seconds) should be the password persisted in memory.
    ///
    /// `None` will make persist the password without timeout.
    ///
    /// With `Some(0)` password will erase the password instantly.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let create = true;
    /// let snapshot_password = "8V(#!2_%AHD]j%53";
    /// let snapshot_password_timeout = None;
    ///
    /// let stronghold = Stronghold::new(&snapshot_path, create, snapshot_password.to_string(), snapshot_password_timeout).unwrap();
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn new<P: AsRef<Path>>(
        snapshot_path: P,
        create: bool,
        snapshot_password: String,
        snapshot_password_timeout: Option<u64>,
    ) -> Result<Self> {
        if snapshot_password.is_empty() {
            return Err(anyhow!("Invalid parameters: password is missing"));
        };
        let storage = Storage::new(snapshot_path);
        if create {
            if storage.exists() {
                return Err(anyhow!("Cannot create a new snapshot: There is an existing one"));
            } else {
                let index = Index::default();
                let index_serialized = serde_json::to_string(&index).unwrap();
                storage
                    .encrypt(
                        &index_serialized,
                        Some(RecordHint::new(INDEX_HINT).unwrap()),
                        &snapshot_password,
                    )
                    .unwrap();
            }
        } else {
            storage.get_index(&snapshot_password).unwrap();
        };
        let _snapshot_password: Arc<Lazy<Mutex<(String, Option<u64>)>>> = Default::default();
        let mut data = _snapshot_password.lock().unwrap();
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs();
        if let Some(timeout) = snapshot_password_timeout {
            if timeout == 0 {
                *data = ("".to_string(), Some(time_now + timeout));
            } else {
                *data = (snapshot_password, Some(time_now + timeout));
            }
        } else {
            *data = (snapshot_password, None);
        };
        let __snapshot_password = Arc::clone(&_snapshot_password);
        let handle = thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            let mut data = __snapshot_password.lock().unwrap();
            if let Some(timeout) = (*data).1 {
                let time_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                if time_now > timeout {
                    (*data).0.clear(); //todo: zeroise this
                }
            }
        });

        Ok(Self {
            storage,
            snapshot_password: Arc::clone(&_snapshot_password),
        })
    }
    /// Loads the snapshot password and its timeout
    ///
    /// When the password expires you can use this for renew it
    ///
    /// # Parameters
    ///
    /// `snapshot_password`: Password to use for encrypt/decrypt the snapshot file.
    ///
    /// `snapshot_password_timeout`: How much time (in seconds) should be the password persisted in memory.
    ///
    /// `None` value will make persist the password without timeout.
    ///
    /// With `Some(0)` password will erase the password instantly.
    ///
    /// # Examples
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let snapshot_password = "8V(#!2_%AHD]j%53";
    /// let snapshot_password_timeout = Some(0); // The password will be erased instantly
    ///
    /// let stronghold = Stronghold::new(&snapshot_path, true, snapshot_password.to_string(), snapshot_password_timeout).unwrap();
    /// stronghold.snapshot_password(snapshot_password.to_string(), snapshot_password_timeout);// We put the password again in memory
    /// stronghold.account_create(None).unwrap();
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    /// Otherwise, it will panic
    /// ```should_panic
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let password = "8V(#!2_%AHD]j%53";
    /// let timeout = Some(0); // The password will be erased instantly
    /// let stronghold = Stronghold::new(&snapshot_path, true, password.to_string(), timeout).unwrap();
    /// stronghold.account_create(None).unwrap(); // We are trying to use the snapshot without password
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn snapshot_password(&self, password: String, timeout: Option<u64>) {
        let mut data = self.snapshot_password.lock().unwrap();

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        if let Some(timeout) = timeout {
            *data = (password, Some(time_now + timeout));
        } else {
            *data = (password, None);
        };
    }

    // Saves an index in the snapshot
    fn index_save(&self, index: &Index) -> Result<RecordId> {
        let index_serialized = serde_json::to_string(&index).unwrap();
        self.storage.encrypt(
            &index_serialized,
            Some(RecordHint::new(INDEX_HINT).unwrap()),
            &self.snapshot_password.lock().unwrap().0,
        )
    }

    // In the snapshot, removes the old index and saves the newest one
    fn index_update(&self, old_index_record_id: RecordId, new_index: Index) -> Result<RecordId> {
        self._record_remove(old_index_record_id).unwrap();
        self.index_save(&new_index)
    }

    // Decode record into account
    fn account_from_json(&self, decrypted: &str) -> Result<Account> {
        let x: Account = serde_json::from_str(&decrypted).context("Error reading record from snapshot")?;
        Ok(x)
    }

    /// Returns an account by its identifier
    ///
    /// # Parameters
    ///
    /// `account_id`: each account has an unique and deterministic generated identifier, use it for reference the account that you need.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();// We create an account
    /// let account_id = &account.id();// We get its identifier
    ///
    /// let account = stronghold.account_get_by_id(account_id).unwrap();// We re-get the account using its identifier
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_get_by_id(&self, account_id: &[u8; 32]) -> Result<Account> {
        let (record_id, account) = self
            ._account_get_by_id(account_id)
            .context("Cannot find specified account")?;
        Ok(account)
    }

    fn _account_get_by_id(&self, account_id: &[u8; 32]) -> Result<(RecordId, Account)> {
        let account: Option<Account>;
        let record_id = self.record_get_by_account_id(account_id)?;
        let decrypted = self
            .storage
            .read(record_id, &self.snapshot_password.lock().unwrap().0)?;
        Ok((record_id, self.account_from_json(&decrypted)?))
    }

    // Get account by record id
    fn account_get_by_record_id(&self, record_id: &RecordId) -> Result<Account> {
        let decrypted = self
            .storage
            .read(*record_id, &self.snapshot_password.lock().unwrap().0)?;
        Ok(self.account_from_json(&decrypted)?)
    }

    /// Removes an existing account from the snapshot.
    ///
    /// Given an account identifier removes the account from the snapshot.
    ///
    /// # Parameters
    ///
    /// `account_id`: each account has an unique and deterministic generated identifier, use it for reference the account that you need remove.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();// We create an account
    /// let account_id = &account.id();// We get its identifier
    /// let account = stronghold.account_remove(account_id).unwrap();// We re-get the account using its identifier
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_remove(&self, account_id: &[u8; 32]) -> Result<()> {
        let record_id = self.record_get_by_account_id(account_id)?;
        let account = self.account_get_by_record_id(&record_id);
        self.storage
            .revoke(record_id, &self.snapshot_password.lock().unwrap().0)
            .unwrap();
        let (index_record_id, mut index) = self.index_get(None, None).context("failed to get index")?;
        index.remove_account(account_id);
        self.index_update(index_record_id, index).unwrap();
        self.storage
            .garbage_collect_vault(&self.snapshot_password.lock().unwrap().0)
            .unwrap();
        Ok(())
    }

    // Save a new account in a new record
    fn account_save(&self, account: &Account, rewrite: bool) -> Result<RecordId> {
        let (index_record_id, mut index) = self.index_get(None, None).context("Error getting stronghold index")?;
        if rewrite == false {
            let (_, index) = self.index_get(None, None).context("Error getting stronghold index")?;
            if index.includes(account.id()) {
                return Err(anyhow!("Account already imported"));
            };
        }
        let account_serialized = serde_json::to_string(account).context("Error saving account in snapshot")?;
        let record_id = self
            .storage
            .encrypt(&account_serialized, None, &self.snapshot_password.lock().unwrap().0)?;
        index.add_account(account.id(), record_id);
        self.index_update(index_record_id, index).unwrap();
        Ok(record_id)
    }

    /// Lists account identifiers.
    ///
    /// Can get all the account identifiers in the snapshot.
    ///
    /// # Parameters
    ///
    /// `skip`: should be used for prune the results in its start.
    ///
    /// `limit`: should be used to set the results total.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();
    ///
    /// let list = stronghold.account_list_ids(None, None);
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_list_ids(&self, skip: Option<usize>, limit: Option<usize>) -> Result<Vec<String>> {
        let (record_id, index) = self.index_get(skip, limit).context("Error getting stronghold index")?;
        Ok(index.0.keys().map(|k| k.to_string()).collect())
    }

    fn index_get(&self, skip: Option<usize>, limit: Option<usize>) -> Result<(RecordId, Index)> {
        if self.storage.exists() {
            let storage_index = self.storage.get_index(&self.snapshot_password.lock().unwrap().0)?;
            let index_hint = RecordHint::new(INDEX_HINT).context("invalid INDEX_HINT")?;
            let (index_record_id, mut index): (RecordId, Index) = storage_index
                .iter()
                .find(|(record_id, record_hint)| record_hint == &index_hint)
                .map(|(record_id, record_hint)| {
                    let index_json = self
                        .storage
                        .read(*record_id, &self.snapshot_password.lock().unwrap().0)
                        .unwrap();
                    let index: Index = serde_json::from_str(&index_json).expect("Cannot decode stronghold index");
                    (*record_id, index)
                })
                .unwrap_or_else(|| {
                    let index = Index::default();
                    let record_id = self.index_save(&index).unwrap();
                    (record_id, index)
                });

            let skip = if let Some(skip) = skip {
                if skip > index.0.len() - 1 {
                    index.0.len() - 1
                } else {
                    skip
                }
            } else {
                0
            };

            let limit = if let Some(limit) = limit {
                if limit > index.0.len() - skip {
                    index.0.len()
                } else {
                    limit
                }
            } else {
                index.0.len()
            };

            index.0 = index
                .0
                .into_iter()
                .enumerate()
                .filter_map(|(i, e)| if i >= skip && i <= limit + skip { Some(e) } else { None })
                .collect();

            Ok((index_record_id, index))
        } else {
            let index = Index::default();
            let record_id = self.index_save(&index)?;
            Ok((record_id, index))
        }
    }

    /// Lists accounts
    ///
    /// # Parameters
    ///
    /// `skip`: should be used for prune the results in its start.
    ///
    /// `limit`: should be used to set the results total.
    ///
    /// # Example
    /// ```no_run
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();
    /// let account = stronghold.account_create(None).unwrap();
    ///
    /// let list = stronghold.account_list(Some(0), Some(30));
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_list(&self, skip: Option<usize>, limit: Option<usize>) -> Result<Vec<Account>> {
        let (index_record_id, index) = self
            .index_get(skip, limit)
            .context("Snapshot file maybe isnt initialized")?;
        let mut accounts = Vec::new();
        for (i, (_, record_id)) in index.0.into_iter().enumerate() {
            accounts.push(self.account_get_by_record_id(&record_id)?);
        }
        Ok(accounts)
    }

    /// Creates a new account saving it in the snapshot file.
    ///
    /// # Parameters
    ///
    /// `bip39_passphrase`: Optional bip39 passphrase
    /// If you use `bip39_passphrase`, it will salt the generated mnemonic according to bip39 spec.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let bip39_passphrase = Some(String::from("ieu73jdumf"));
    ///
    /// let account = stronghold.account_create(bip39_passphrase);
    ///
    /// /// For additional info check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" to the master seed and "subaccount" to a bip39 account)
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_create(&self, bip39_passphrase: Option<String>) -> Result<Account> {
        Ok(self._account_create(bip39_passphrase)?.1)
    }

    fn _account_create(&self, bip39_passphrase: Option<String>) -> Result<(RecordId, Account)> {
        let (index_record_id, index) = self
            .index_get(None, None)
            .context("Index maybe not initialized in snapshot file")?;
        let all_accounts = self.account_list(None, None).context("failed to list accounts")?;
        let account = Account::new(bip39_passphrase)?;
        let record_id = self.account_save(&account, false)?;
        Ok((record_id, account))
    }

    /// Imports an existing external account to the snapshot file
    ///
    /// # Parameters
    ///
    /// `created_data`: date and time in unix epoch in ms of when the account was created.
    ///
    /// `last_updated_on`: date and time in unix epoch in ms of when the account had its last update.
    ///
    /// `bip39_mnemonic`: word list that is space separated.
    ///
    /// `bip39_passphrase`: used to salt the master seed generation. Optional parameter but essential if you had a passphrase, otherwise you won't be able to correctly access your wallet.
    ///
    /// For additional info check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" to the master seed and "subaccount" to a bip39 account)
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let mnemonic = String::from("gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding");
    /// let created_at = Some(1598890069000);
    /// let last_updated_on = Some(1598890070000);
    /// let account = stronghold.account_import(0, created_at, last_updated_on, mnemonic, None);
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_import(
        // todo: reorder params , ¿what if try to add an account by second time?
        &self,
        created_at: Option<u128>,
        last_updated_on: Option<u128>,
        bip39_mnemonic: String,
        bip39_passphrase: Option<&str>,
    ) -> Result<Account> {
        Ok(self
            ._account_import(created_at, last_updated_on, bip39_mnemonic, bip39_passphrase)?
            .1)
    }

    fn _account_import(
        // todo: reorder params , ¿what if try to add an account by second time?
        &self,
        created_at: Option<u128>,
        last_updated_on: Option<u128>,
        bip39_mnemonic: String,
        bip39_passphrase: Option<&str>,
    ) -> Result<(RecordId, Account)> {
        if bip39_mnemonic.is_empty() {
            return Err(anyhow!("Invalid parameters: bip39_mnemonic is missing"));
        }

        let bip39_passphrase = match bip39_passphrase {
            Some(x) => Some(String::from(x)),
            None => None,
        };

        let account = Account::import(created_at, last_updated_on, bip39_mnemonic, bip39_passphrase)?;

        let record_id = self.account_save(&account, false)?;

        Ok((record_id, account))
    }

    /// Updates an account
    ///
    /// Given an account automatically find and replace it in the snapshot file.
    ///
    /// # Parameters:
    ///
    /// `account`: Updated Account instance that will replace the already stored.
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let mnemonic = String::from("gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding");
    /// let created_at = Some(1598890069000);
    /// let last_updated_on = Some(1598890070000);
    /// let mut account = stronghold.account_import(0, created_at, last_updated_on, mnemonic, None).unwrap();
    /// account.last_updated_on(true);
    ///
    /// stronghold.account_update(&mut account);
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn account_update(&self, account: &mut Account) {
        self._account_update(account).unwrap();
    }

    fn _account_update(&self, account: &mut Account) -> Result<RecordId> {
        // todo: switch to private fn
        let record_id = self.record_get_by_account_id(account.id())?;
        self._record_remove(record_id).unwrap();
        account.last_updated_on(true);
        let record_id = self.account_save(&account, true)?;
        let (index_record_id, mut index) = self.index_get(None, None).context("Error getting account index")?;
        index.update_account(account.id(), record_id);
        self.index_update(index_record_id, index)?;
        Ok(record_id)
    }

    /// Get an address
    ///
    /// Given an account id (`account_id`) and a derivation path (composed by `address_index` and `internal`) returns an address.
    ///
    /// # Parameters:
    ///
    /// `account_id`: id of the account to which the address has to belong
    ///
    /// `subaccount`: bip39 account which the private key has to belong (if None, bip39 account 0 will be used)
    ///
    /// `address_index`: index of the address to generate
    ///
    /// `internal`: chain to which the address has to belong (internal:false for receiving address and external:true
    /// to change addresses)
    ///
    /// `snapshot_password`: password required to decrypt/encrypt the snapshot file
    ///
    /// For additional info check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" to the master seed and "subaccount" to a bip39 account)
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let mnemonic = String::from("gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding");
    /// let created_at = Some(1598890069000);
    /// let last_updated_on = Some(1598890070000);
    /// let account = stronghold.account_import(0, created_at, last_updated_on, mnemonic, None).unwrap();
    /// let subaccount = None;
    ///
    ///
    /// let address = stronghold.address_get(
    ///     account.id(),
    ///     subaccount,
    ///     1,
    ///     true
    /// );
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn address_get(
        &self,
        account_id: &[u8; 32],
        subaccount: Option<usize>,
        address_index: usize,
        internal: bool,
    ) -> Result<String> {
        let subaccount = if let Some(subaccount) = subaccount {
            subaccount
        } else {
            0
        };
        let account = self.account_get_by_id(&account_id)?;
        Ok(account.get_address(format!(
            "m/44H/4218H/{}H/{}H/{}H",
            subaccount, !internal as u32, address_index
        ))?)
    }

    /// Signs a message
    ///
    /// Given the certain details of the private key to be used for signing, returns the message signature
    ///
    /// `message` message to sign
    ///
    /// `account_id` identifier of the account which the private key that has to belong
    ///
    /// `subaccount`: bip39 account which the private key has to belong (if None, bip39 account 0 will be used)
    ///
    /// `internal` chain to which the private key has to belong
    ///
    /// `index` number of address that has to be
    ///
    /// For additional check bip39 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (note: for practical purposes in this library we are calling "account" a master seed and "subaccount" a bip39 account)
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let mnemonic = String::from("gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding");
    /// let created_at = Some(1598890069000);
    /// let last_updated_on = Some(1598890070000);
    /// let account = stronghold.account_import(0, created_at, last_updated_on, mnemonic, None).unwrap();
    ///
    /// let message = "With this signed message you can verify my address ownership".as_bytes();
    /// let internal = false;
    /// let index = 0;
    /// let subaccount = None;
    ///
    /// let signature = stronghold.signature_make(&message, account.id(), subaccount, internal, index);
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn signature_make(
        &self,
        message: &[u8],
        account_id: &[u8; 32],
        subaccount: Option<usize>,
        internal: bool,
        index: usize,
    ) -> Result<String> {
        let account = self.account_get_by_id(account_id)?;
        let subaccount = if let Some(subaccount) = subaccount {
            subaccount
        } else {
            0
        };
        let signature: Vec<u8> = account
            .sign_message(
                message,
                format!("m/44'/4218'/{}'/{}'/{}'", subaccount, !internal as u32, index),
            )?
            .to_vec();
        Ok(base64::encode(signature))
    }

    /// Verifies a signature
    ///
    /// Given a `signature` you can verify if a `message` belongs to an identity (`address`)
    ///
    /// # Parameters
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
    pub fn signature_verify(address: &str, message: &str, signature: &str) -> Result<()> {
        // signature treatment
        let signature_bytes = base64::decode(signature).context("Error decoding base64")?;
        let signature =
            ed25519::Ed25519Signature::from_bytes(&signature_bytes).context("Error decoding bytes into signature")?;

        // address treatment
        let (hrp, bech32_data_u5) = bech32::decode(address).context("Invalid address")?;
        let mut bech32_data_bytes =
            bech32::convert_bits(bech32_data_u5.as_ref(), 5, 8, false).context("Error decoding bech32")?;
        let address_type = bech32_data_bytes.remove(0);
        if address_type == 0 {
            return Err(anyhow!("ed25519 version address expected , WOTS version address found"));
        };
        if address_type != 1 {
            return Err(anyhow!("ed25519 address expected , unknown version address found"));
        };
        let public_bytes = bech32_data_bytes.as_ref();
        let public_key =
            ed25519::Ed25519PublicKey::from_bytes(public_bytes).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // verification
        Ok(public_key
            .verify(message.as_bytes(), &signature)
            .context("Error verifying signature")?)
    }

    /// Saves custom data as a new record from the snapshot
    ///
    /// # Parameters
    ///
    /// `label`: a name for handling and anecdotal purposes
    ///
    /// `data`: data that will contain the record
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// # let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    ///
    /// let data = "my deepest secrets";
    /// let record_id = stronghold.record_create(&data);
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn record_create(&self, data: &str) -> Result<RecordId> {
        self.storage
            .encrypt(data, None, &self.snapshot_password.lock().unwrap().0)
    }

    /// Saves custom data as a new record with hint
    pub fn record_create_with_hint(&self, data: &str, hint: RecordHint) -> Result<RecordId> {
        self.storage
            .encrypt(data, Some(hint), &self.snapshot_password.lock().unwrap().0)
    }

    /// Get record by record id
    ///
    /// # Parameters
    ///
    /// `record_id` id of the record to read
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// # let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let data = "my deepest secrets";
    /// let record_id = stronghold.record_create(&data).unwrap();
    /// let record = stronghold.record_read(&record_id).unwrap();
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn record_read(&self, record_id: &RecordId) -> Result<String> {
        self.storage.read(*record_id, &self.snapshot_password.lock().unwrap().0)
    }

    // Searches record id by account id
    fn record_get_by_account_id(&self, account_id: &[u8; 32]) -> Result<RecordId> {
        let (_, index) = self.index_get(None, None).context("Error getting index")?;
        if let Some(record_id) = index.0.get(&hex::encode(account_id)) {
            Ok(*record_id)
        } else {
            Err(anyhow!("Unable to find record id with specified account id"))
        }
    }

    /// List records stored in snapshot
    ///
    /// It will include index record and account records
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// # let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let data = "my deepest secrets";
    /// let record_list = stronghold.record_list();
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn record_list(&self) -> Result<Vec<(RecordId, RecordHint)>> {
        self.storage.get_index(&self.snapshot_password.lock().unwrap().0)
    }

    /// Removes record from storage by record id
    ///
    /// # Parameters
    ///
    /// `record_id`: identifier of the record to remove
    ///
    /// # Example
    /// ```
    /// # use engine::snapshot::snapshot_dir;
    /// # use rand::{distributions::Alphanumeric, thread_rng, Rng};
    /// # use std::path::PathBuf;
    /// # use stronghold::Stronghold;
    /// let snapshot_path = "example.snapshot";
    /// # let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// # let snapshot_path = snapshot_dir().unwrap().join(snapshot_filename);
    /// # let stronghold = Stronghold::new(&snapshot_path, true, "password".to_string(), None).unwrap();
    /// let data = "my deepest secrets";
    /// let record_id = stronghold.record_create(&data).unwrap();
    /// stronghold.record_remove(record_id).unwrap();
    ///
    /// # let _ = std::fs::remove_file(snapshot_path);
    /// ```
    pub fn record_remove(&self, record_id: RecordId) -> Result<()> {
        let (index_record_id, _) = self.index_get(None, None).unwrap();
        if record_id == index_record_id {
            return Err(anyhow!("Error removing record: you can't remove index record"));
        };

        if self.account_get_by_record_id(&record_id).is_ok() {
            return Err(anyhow!(
                "Error removing record: if you are trying to remove an account record please use account_remove()"
            ));
        };

        self._record_remove(record_id)
    }

    fn _record_remove(&self, record_id: RecordId) -> Result<()> {
        self.storage
            .revoke(record_id, &self.snapshot_password.lock().unwrap().0)?;
        self.storage
            .garbage_collect_vault(&self.snapshot_password.lock().unwrap().0)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test_utils {
    use engine::snapshot::snapshot_dir;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use std::path::PathBuf;

    pub fn with_snapshot<F: FnOnce(&PathBuf)>(cb: F) {
        let snapshot_filename: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let snapshot_path = snapshot_dir()
            .expect("failed to get snapshot dir")
            .join(snapshot_filename);
        cb(&snapshot_path);
        let _ = std::fs::remove_file(snapshot_path);
    }
    pub static SNAPSHOT_PASSWORD: &str = "password";
}

#[cfg(test)]
mod tests {
    use super::test_utils::{with_snapshot, SNAPSHOT_PASSWORD};
    use super::Stronghold;

    #[test]
    fn create_record() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let value = "value_to_encrypt";
            let id = stronghold.record_create(value).unwrap();

            let read = stronghold.storage.read(id, &SNAPSHOT_PASSWORD).unwrap();
            assert_eq!(read, value);
        });
    }

    #[test]
    fn create_account() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(record_id, account_record_id_from_index);

            let accounts = stronghold.account_list(None, None).unwrap();
            // println!("{}",serde_json::to_string(&accounts[0]).unwrap());
            // todo: add more controls
            assert_eq!(accounts.len(), 1);
            let (record_id, index) = stronghold.index_get(None, None).unwrap();
            assert_eq!(index.0.len(), 1);
        });
    }

    #[test]
    fn remove_account() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(record_id, account_record_id_from_index);

            stronghold.account_remove(&account.id()).unwrap();
            let accounts = stronghold.account_list(None, None).unwrap();
            assert_eq!(accounts.len(), 0);

            let (record_id, index) = stronghold.index_get(None, None).unwrap();
            assert_eq!(index.0.len(), 0);
        });
    }

    #[test]
    fn update_account() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(record_id, account_record_id_from_index);

            let last_updated_on = account.last_updated_on(true);
            let new_record_id = stronghold._account_update(account).unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(&new_record_id, account_record_id_from_index);

            let _account = stronghold.account_get_by_id(account.id()).unwrap();
            assert_eq!(
                serde_json::to_string(account).unwrap(),
                serde_json::to_string(&_account).unwrap()
            );
        });
    }

    #[test]
    fn import_account() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold
                ._account_import(
                    0,
                    Some(1599580138000),
                    Some(1599580138000),
                    "slight during hamster song old retire flock mosquito people mirror fruit among name common know"
                        .to_string(),
                    None,
                )
                .unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(record_id, account_record_id_from_index);
        });
    }

    #[test]
    #[should_panic]
    fn import_account_twice() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold
                ._account_import(
                    0,
                    Some(1599580138000),
                    Some(1599580138000),
                    "slight during hamster song old retire flock mosquito people mirror fruit among name common know"
                        .to_string(),
                    None,
                )
                .unwrap();
            let (record_id, account) = &mut stronghold
                ._account_import(
                    0,
                    Some(1599580138000),
                    Some(1599580138000),
                    "slight during hamster song old retire flock mosquito people mirror fruit among name common know"
                        .to_string(),
                    None,
                )
                .unwrap();
        });
    }

    #[test]
    fn list_accounts_ids() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();
            let (record_id, account) = &mut stronghold._account_create(None).unwrap();

            let ids = stronghold.account_list_ids(None, None).unwrap();
            assert_eq!(ids.len(), 3);
        });
    }

    #[test]
    fn save_and_read_custom_data() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let data_to_save = "testing text";
            let record_id = stronghold.record_create(data_to_save).unwrap();
            let data_read = stronghold.record_read(&record_id).unwrap();
            assert_eq!(data_read, data_to_save);
        });
    }

    #[test]
    fn save_and_remove_custom_data() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let data_to_save = "testing text";
            let record_id = stronghold.record_create(data_to_save).unwrap();
            let data_read = stronghold.record_read(&record_id).unwrap();
            println!("{}", data_read);
            assert_eq!(data_read, data_to_save);

            let record_list = stronghold.record_list().unwrap(); // todo: add skip limit and filter in order to avoid index and account records
            assert_eq!(record_list.len(), 2);

            stronghold.record_remove(record_id).unwrap();
            let record_list = stronghold.record_list().unwrap();
            assert_eq!(record_list.len(), 1);
        });
    }

    #[test]
    fn get_address() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold
                ._account_import(
                    0,
                    Some(1599580138000),
                    Some(1599580138000),
                    "slight during hamster song old retire flock mosquito people mirror fruit among name common know"
                        .to_string(),
                    None,
                )
                .unwrap();
            let (_, index) = stronghold.index_get(None, None).unwrap();
            let account_record_id_from_index = index.0.get(&hex::encode(account.id())).unwrap();
            assert_eq!(record_id, account_record_id_from_index);

            let address = stronghold.address_get(account.id(), None, 0, false).unwrap();
            assert_eq!(
                address,
                "iota1qye70q4wmhx8ys5rgsaw80g32cqlaa9ec50a8lpt88f5g033sw98s2ee8ve"
            );

            let account = stronghold.account_get_by_id(account.id());
        });
    }

    #[test]
    fn sign() {
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), None).unwrap();
            let (record_id, account) = &mut stronghold
                ._account_import(
                    0,
                    Some(1599580138000),
                    Some(1599580138000),
                    "slight during hamster song old retire flock mosquito people mirror fruit among name common know"
                        .to_string(),
                    None,
                )
                .unwrap();

            let message = "With this signed message you can verify my address ownership".as_bytes();
            let internal = false;
            let index = 0;
            let signature = stronghold
                .signature_make(&message, &account.id(), None, internal, index)
                .unwrap();

            assert_eq!(
                signature,
                "w2NnP8rZuyOBW5rR3/NjteGuOse6ZwyQ2za66ebyL7+opgDzXV/X1i9IzXBTgmvYJMY+Aoq+mdGRmj2Dni4VBA=="
            );
        });
    }

    #[test]
    fn verify_signature() {
        with_snapshot(|path| {
            let address = "iota1q8knfu2rq8k9tlasfqrh38zmvfqhx5zvm9ehtzmdz3zg7yqv9klly26fhca";
            let message = "With this signed message you can verify my address ownership";
            let signature = "nd2oqe4wRhnqsckDZGZQPkpR0nC+jxQQiVjrFvfLfskCk9MItvrommcz5tkhq94Lx+Z1eZleV3pZtChhnWfNAA==";
            let is_legit = Stronghold::signature_verify(&address, &message, &signature).unwrap();

            assert_eq!(is_legit, ());
        });
    }

    #[test]
    fn snapshot_password_timeout() {
        use std::thread;
        use std::time::Duration;
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), Some(10)).unwrap();
            thread::sleep(Duration::from_secs(5));
            stronghold.account_create(None).unwrap();
        });
    }

    #[test]
    #[should_panic]
    fn snapshot_password_timeout_panic() {
        use std::thread;
        use std::time::Duration;
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), Some(1)).unwrap();
            thread::sleep(Duration::from_secs(2));
            stronghold.account_create(None).unwrap();
        });
    }

    #[test]
    fn snapshot_password_timeout_renew() {
        use std::thread;
        use std::time::Duration;
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), Some(1)).unwrap();
            thread::sleep(Duration::from_secs(2));
            stronghold.snapshot_password(SNAPSHOT_PASSWORD.to_string(), Some(10));
            stronghold.account_create(None).unwrap();
        });
    }

    #[test]
    #[should_panic]
    fn snapshot_password_timeout_renew_panic() {
        use std::thread;
        use std::time::Duration;
        with_snapshot(|path| {
            let stronghold = Stronghold::new(path, true, SNAPSHOT_PASSWORD.to_string(), Some(1)).unwrap();
            thread::sleep(Duration::from_secs(2));
            stronghold.snapshot_password(SNAPSHOT_PASSWORD.to_string(), Some(1));
            thread::sleep(Duration::from_secs(2));
            stronghold.account_create(None).unwrap();
        });
    }
}
