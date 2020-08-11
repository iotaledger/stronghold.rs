//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage;

use account::{Account,AccountToCreate,AccountToImport};
use std::str;
use serde_json;

/// Stronghold doc com
struct Stronghold;

impl Stronghold {

    fn find_record_id(&self, account_id_target: &str, snapshot_password: &str) -> storage::Id {
        let index = storage::get_index(snapshot_password);
        for (record_id,account_id) in index {
            if format!("{:?}",account_id) == account_id_target {
                return record_id;
            }
        };
        panic!("Unable to find record id with specified account id");
    }

    pub fn get_account(&self, account_id: &str, snapshot_password: &str) -> Account {
        let index = storage::get_index(snapshot_password);
        let account: Option<Account>;
        let record_id = self.find_record_id(account_id, snapshot_password);
        let decrypted = storage::read(record_id, snapshot_password);
        self.decode_record(&decrypted)
    }

    fn decode_record(&self, decrypted: &str) -> Account {
        let x: Account = serde_json::from_str(&decrypted).expect("Error reading record from snapshot");
        x
    }

    fn get_account_by_record_id(&self, record_id: storage::Id, snapshot_password: &str) -> Account {
        let decrypted = storage::read(record_id, snapshot_password);
        self.decode_record(&decrypted)
    }

    pub fn remove_account(&self, account_id: &str, snapshot_password: &str) -> Account {
        let record_id = self.find_record_id(account_id, snapshot_password);
        let account = self.get_account_by_record_id(record_id,snapshot_password);
        storage::revoke(record_id, snapshot_password);
        storage::garbage_collect_vault(snapshot_password);
        account
    }

    pub fn save_account(&self, account: &Account, snapshot_password: &str) -> storage::Id {
        let account_serialized = serde_json::to_string(account).expect("Error saving account in snapshot");
        storage::encrypt(&account.id, &account_serialized, snapshot_password)
    }

    // List ids of accounts
    pub fn get_account_index(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< String >  {
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
    pub fn list_accounts(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< Account >  {
        let mut accounts = Vec::new();
        for (i, (record_id , _)) in storage::get_index(snapshot_password).into_iter().enumerate() {
            if i+1 <= skip {
                continue;
            }
            if i+1 > limit {
                break;
            }
            accounts.push(self.get_account_by_record_id(record_id,snapshot_password));
        }
        accounts
    }
    
    pub fn create_account(&self, bip39passphrase: Option<String>, snapshot_password: &str) -> Account {
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: Password is missing");
        }
        let account = Account::new(AccountToCreate {bip39passphrase}).unwrap();
        self.save_account(&account,snapshot_password);
        account
    }

    pub fn account_import(
        &self,
        created_at: u128,
        last_decryption: Option<usize>,
        decryption_counter: usize,
        export_counter: usize,
        bip39mnemonic: &str,
        bip39passphrase: Option<&str>,
        snapshot_password: &str
    ) -> Account {
        if bip39mnemonic.is_empty() {
            panic!("Invalid parameters: bip39mnemonic is missing");
        }
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: password is missing");
        }
        let account: Account = AccountToImport {
            created_at,
            bip39mnemonic: String::from(bip39mnemonic),
            bip39passphrase: match bip39passphrase {
                Some(x) => Some(String::from(x)),
                None => None
            }
        }.into();

        self.save_account(&account,snapshot_password);

        account
    }

    pub fn account_export(&self, account_id: &str, snapshot_password: &str) -> Account {
        self.get_account(account_id, snapshot_password)
    }

    /*
    pub fn transaction_sign() {

    }

    pub fn message_sign() {

    }

    pub fn message_decrypt() {

    }
    */
}