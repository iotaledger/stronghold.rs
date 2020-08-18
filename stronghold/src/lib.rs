//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage;//storage will be saving records with accounts as jsons

use account::{Account,AccountToCreate,AccountToImport,SubAccount};
use std::str;
use serde_json;
use base64;

/// Stronghold doc com
struct Stronghold;

impl Stronghold {

    // Find record id by account id
    fn record_get_by_account_id(&self, account_id_target: &str, snapshot_password: &str) -> storage::Id {
        let index = storage::get_index(snapshot_password);
        for (record_id,account_id) in index {
            if format!("{:?}",account_id) == account_id_target {
                return record_id;
            }
        };
        panic!("Unable to find record id with specified account id");
    }

    // Removes record from storage by record id
    fn record_remove(&self, record_id: storage::Id, snapshot_password: &str) {
        storage::revoke(record_id, snapshot_password);
        storage::garbage_collect_vault(snapshot_password);
    }

    // Decode record into account
    fn record_decode(&self, decrypted: &str) -> Account {
        let x: Account = serde_json::from_str(&decrypted).expect("Error reading record from snapshot");
        x
    }

    // Get account by account id
    pub fn account_get_by_id(&self, account_id: &str, snapshot_password: &str) -> Account {
        let index = storage::get_index(snapshot_password);
        let account: Option<Account>;
        let record_id = self.record_get_by_account_id(account_id, snapshot_password);
        let decrypted = storage::read(record_id, snapshot_password);
        self.record_decode(&decrypted)
    }

    // Get account by record id
    fn account_get_by_record_id(&self, record_id: &storage::Id, snapshot_password: &str) -> Account {
        let decrypted = storage::read(*record_id, snapshot_password);
        self.record_decode(&decrypted)
    }

    // Remove existent account
    pub fn account_remove(&self, account_id: &str, snapshot_password: &str) -> Account {
        let record_id = self.record_get_by_account_id(account_id, snapshot_password);
        let account = self.account_get_by_record_id(&record_id,snapshot_password);
        storage::revoke(record_id, snapshot_password);
        storage::garbage_collect_vault(snapshot_password);
        account
    }

    // Save account in a new record
    pub fn account_save(&self, account: &Account, snapshot_password: &str) -> storage::Id {
        let account_serialized = serde_json::to_string(account).expect("Error saving account in snapshot");
        storage::encrypt(&account.id, &account_serialized, snapshot_password)
    }

    // List ids of accounts
    pub fn account_index_get(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< String >  {
        let mut account_ids = Vec::new();
        for (i, (_ , account_id)) in storage::get_index(snapshot_password).into_iter().enumerate() {
            if i+1 <= skip {
                continue;
            }
            if i+1 > limit {
                break;
            }
            account_ids.push(format!("{:?}",account_id));
        }
        account_ids
    }
    
    // List accounts
    pub fn account_list(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< Account >  {
        let mut accounts = Vec::new();
        for (i, (record_id , _)) in storage::get_index(snapshot_password).into_iter().enumerate() {
            if i+1 <= skip {
                continue;
            }
            if i+1 > limit {
                break;
            }
            accounts.push(self.account_get_by_record_id(&record_id,snapshot_password));
        }
        accounts
    }
    
    // Create new account saving it
    pub fn account_create(&self, bip39_passphrase: Option<String>, snapshot_password: &str) -> Account {
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: Password is missing");
        }
        let account = Account::new(AccountToCreate {bip39_passphrase});
        self.account_save(&account,snapshot_password);
        account
    }

    // Import new account saving it
    pub fn account_import(
        &self,
        created_at: u128,
        bip39_mnemonic: &str,
        bip39_passphrase: Option<&str>,
        snapshot_password: &str,
        subaccounts: Vec<SubAccount>
    ) -> Account {
        if bip39_mnemonic.is_empty() {
            panic!("Invalid parameters: bip39_mnemonic is missing");
        }
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: password is missing");
        }
        let account: Account = AccountToImport {
            created_at,
            bip39_mnemonic: String::from(bip39_mnemonic),
            bip39_passphrase: match bip39_passphrase {
                Some(x) => Some(String::from(x)),
                None => None
            },
            subaccounts

        }.into();

        self.account_save(&account,snapshot_password);

        account
    }

    // Returns an account by account id (increases the stored export counter)
    pub fn account_export(&self, account_id: &str, snapshot_password: &str) -> Account {
        self.account_get_by_id(account_id, snapshot_password)
    }

    // Updates an account migrating its record
    pub fn account_update(&self, account: Account, snapshot_password: &str) -> storage::Id {
        let record_id = self.record_get_by_account_id(&account.id, &snapshot_password);
        self.record_remove(record_id, &snapshot_password);
        self.account_save(&account, &snapshot_password)
    }

    // Adds subaccount updating an account
    pub fn subaccount_add(&self, label: &str, account_id: &str, snapshot_password: &str) -> storage::Id {
        let mut account = self.account_get_by_id(&account_id,snapshot_password);
        let subaccount = SubAccount::new(String::from(label));
        account.subaccounts.push(subaccount);
        self.account_update(account,snapshot_password)
    }

    // Returns a new address and updates the account
    pub fn address_get(&self, account_id: &str, sub_account_index: usize, internal: bool, snapshot_password: &str) -> String {
        let mut account = self.account_get_by_id(account_id, snapshot_password);
        let sub_account = &mut account.subaccounts[sub_account_index];
        let index = sub_account.addresses_increase_counter(internal);
        let address = account.get_address(format!("m/44'/4218'/{}'/{}'/{}'", sub_account_index, !internal as u32, index));
        self.account_update(account,snapshot_password);
        address
    }

    // Signs a message
    pub fn message_sign(&self, message: &str, account_id: &str, sub_account_index: usize, internal: bool, index: usize, snapshot_password: &str) -> String {
        let account = self.account_get_by_id(account_id, snapshot_password);
        let signature: Vec<u8> = account.sign_message(message.as_bytes(), format!("m/44'/4218'/{}'/{}'/{}'", sub_account_index, !internal as u32, index)).to_vec();
        base64::encode(signature)
    }

    /*
    pub fn transaction_sign() {

    }

    pub fn message_decrypt() {

    }
    */
}