//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage;

use account::{Account,AccountToCreate,AccountToImport};
use std::str;
//use account::{Account, AccountToCreate, AccountToImport};
use serde_json;

/// Stronghold doc com
struct Stronghold;

//{"id":"","external":true,"created":0,"lastDecryption":0,"decryptionCounter":0,"exportCounter":0,"bip39Mnemonic":"","bip39Passphrase":""}

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

    pub fn delete_account(&self, account_id: &str, snapshot_password: &str) -> Account {
        let record_id = self.find_record_id(account_id, snapshot_password);
        let account = self.get_account_by_record_id(record_id,snapshot_password);
        storage::revoke(record_id, snapshot_password);
        storage::garbage_collect_vault(snapshot_password);
        account
    }

    pub fn save_account(&self, account: Account, snapshot_password: &str) -> storage::Id {
        let account_serialized = serde_json::to_string(&account).expect("Error saving account in snapshot");
        storage::encrypt(&account.id, &account_serialized, snapshot_password)
    }

    // List ids of accounts
    pub fn get_account_index(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< &str >  {
        let account_ids = Vec::new();
        for (i, (_ , account_id)) in storage::get_index(snapshot_password).into_iter().enumerate() {
            if i+1 <= skip {
                continue;
            }
            if i+1 > limit {
                break;
            }
            account_ids.push(format!("{:?}",account_id).as_str());
        }
        account_ids
    }
    
    // List accounts
    pub fn list_accounts(&self, snapshot_password: &str, skip: usize, limit: usize) -> Vec< Account >  {
        let accounts = Vec::new();
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
    
    pub fn create_account(&self, snapshot_password: &str) -> Account {
        if snapshot_password.is_empty() {
            panic!("Invalid parameters: Password is missing");
        }
        let account = Account::create(AccountToCreate).unwrap();
        self.save_account(account,snapshot_password);
        account
    }

    pub fn account_import(
        &self,
        created_at: u64,
        last_decryption: Option<usize>,
        decryption_counter: usize,
        export_counter: usize,
        bip39mnemonic: &str,
        snapshot_password: &str,//snapshot
    ) -> Account {
        if bip39mnemonic.is_empty() {
            return Err("Invalid parameters: bip39mnemonic is missing");
        }
        if snapshot_password.is_empty() {
            return Err("Invalid parameters: password is missing");
        }
        let account = Account::import(AccountToImport {
            created_at,
            export_counter,
            bip39mnemonic: String::from(bip39mnemonic),
            //bip39passphrase,
            //password,
        }).unwrap();

        self.save_account(account,snapshot_password);

        account
    }
    
    /*
    pub fn account_remove() {

    }

    pub fn transaction_sign() {

    }

    pub fn message_sign() {

    }

    pub fn message_decrypt() {

    }

    pub fn get_address() {

    }

    pub fn account_export() {

    }*/
}