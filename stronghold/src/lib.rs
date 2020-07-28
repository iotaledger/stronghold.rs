//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage;

use std::panic;
use account::{Account, AccountToCreate, AccountToImport};
use serde::{Serialize, Deserialize};
use serde_json;

/// Stronghold doc com
struct Stronghold;

//{"id":"","external":true,"created":0,"lastDecryption":0,"decryptionCounter":0,"exportCounter":0,"bip39Mnemonic":"","bip39Passphrase":""}

impl Stronghold {

    //proably should be moved to storage
    pub fn list_ids(&self, snapshot_password: &'static str) -> Result<Vec<storage::Id>,&'static str> {
        if storage::exists() {
            let result = panic::catch_unwind(|| {
                storage::list(snapshot_password)
            });
            if result.is_ok() {
                Ok(result.unwrap())
            }else{
                Err("Existent snapshot file cannot be read. Maybe wrong password or corrupted file")
            }
        }else{
            Err("Snapshot file not found")
        }
    }

    //the index should be in the last slot of the storage
    fn update_index(&self, stronghold_index: StrongholdIndex, snapshot_password: &'static str) {
        self.list_ids(snapshot_password);
    }

    pub fn new_snapshot(&self, /*accounts, */snapshot_password: &'static str) -> Result<Vec<storage::Id>,&'static str> {
        let stronghold_index = StrongholdIndex::new();
        let stronghold_index_serialized = serde_json::to_string(&stronghold_index).unwrap();
        let result = panic::catch_unwind(|| {
            storage::encrypt(&stronghold_index_serialized,snapshot_password);
            storage::list(snapshot_password)
        });
        if result.is_ok() {
            Ok(result.unwrap())
        }else{
            Err("Error creating snapshot")
        }
    }

    // List ids of account
    /*pub fn account_list(skip: u16, limit: u16) -> Result<Vec<Account>, &'static str>  {
        Ok(Account::new)
    }

    pub fn account_get() {

    }*/
/*
    pub fn account_create(
        //bip39passphrase: Option<String>,
        snapshot_password: String,//for snapshot
        //password: String//for account encryption
    ) -> Result<Account, &'static str> {
        if snapshot_password.is_empty() {
            return Err("Invalid parameters: Password is missing");
        }
        
        let account_to_create = AccountToCreate {
            //bip39passphrase,
            //password, //account password
        };
        
        let account = Account::create(account_to_create);
        //if ok add to snapshot
        Ok(account?)
    }

    pub fn account_import(
        created_at: u64,
        last_decryption: Option<u64>,
        decryption_counter: u32,
        export_counter: u32,
        bip39mnemonic: String,
        //bip39passphrase: Option<String>,
        snapshot_password: String,//snapshot
        //password: String//account
    ) -> Result<Account, &'static str> {
        if bip39mnemonic.is_empty() {
            return Err("Invalid parameters: bip39mnemonic is missing");
        }
        if snapshot_password.is_empty() {
            return Err("Invalid parameters: password is missing");
        }
        let account = Account::import(AccountToImport {
            created_at,
            last_decryption,
            decryption_counter,
            export_counter,
            bip39mnemonic,
            //bip39passphrase,
            //password,
        })?;

        // if is ok add to snapshot

        Ok(account)
    }
    */
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

#[derive(Serialize, Deserialize, Debug)]
struct StrongholdIndex {
    /* created_at , decryption counter, export counter , etc? */
    id: &'static str,
    ids: Vec<storage::Id>
}

impl StrongholdIndex {
    pub fn new(/* accounts */) -> Self {
        Self {
            id: "",
            ids: vec![]
        }
    }
}
