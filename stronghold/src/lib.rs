//! stronghold.rs

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

/// Stronghold Account Module
mod account;

/// Stronghold Storage Module
mod storage;

use std::panic;
//use account::{Account, AccountToCreate, AccountToImport};
use serde::{Deserialize, Serialize};
//use serde_json;

/// Stronghold doc com
struct Stronghold;

//{"id":"","external":true,"created":0,"lastDecryption":0,"decryptionCounter":0,"exportCounter":0,"bip39Mnemonic":"","bip39Passphrase":""}

impl Stronghold {
    //proably should be moved to storage
    pub fn list_ids(&self, snapshot_password: &'static str) -> Vec<storage::Id> {
        if !storage::exists() {
            panic!("Snapshot file not found")
        }
        storage::list(snapshot_password)
    }

    //the index should be in the last slot of the storage
    fn update_index(&self, snapshot_password: &'static str) -> Result<storage::Id, &'static str> {
        let (is_last, record_id, mut index) = self.get_index(snapshot_password).unwrap();//todo: handle error
        if !is_last {
            for (i,id) in self.list_ids(snapshot_password)/*TODO> check performance(called twice)*/.into_iter().enumerate().rev() {
                if id == record_id {
                    break
                }
                index.ids.push(id);
            }
            let index_serialized = serde_json::to_string(&index).unwrap();
            storage::encrypt(&index_serialized, snapshot_password);
            Ok(storage::list(snapshot_password).last().copied().unwrap())/*TODO> check performance(fn encrypt could give the id)*/
        }else{
            Err("No update needed")
        }
    }

    // after add, update or remove accounts we have to get the last index and update it
    fn get_index(&self, snapshot_password: &'static str) -> Result<(bool , storage::Id , Index), &'static str> {
        let ids = self.list_ids(snapshot_password);
        let mut index: Option<(bool , storage::Id , Index)> = None;
        let ids_len = ids.len();
        for (i,id) in ids.into_iter().enumerate().rev() {
            let content = storage::read(id,snapshot_password);//todo: handle error
            let result = panic::catch_unwind(|| {
                let _index: Index = serde_json::from_str( &content ).unwrap();//try to decode into Index
                _index
            });
            if result.is_ok() {
                let is_last: bool = ids_len == i+1;
                index = Some( ( is_last , id , result.unwrap() ) );
                break;
            }
        }
        if let Some(x) = index {
            Ok(x)
        }else{
            Err("Index not found in snapshot file")
        }
    }

    fn new_snapshot(
        &self,
        /*accounts, */ snapshot_password: &'static str,
    ) -> Vec<storage::Id> {
        let index = Index::new();
        let index_serialized = serde_json::to_string(&index).unwrap();
        storage::encrypt(&index_serialized, snapshot_password);
        storage::list(snapshot_password)
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

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
struct Index {
    /* created_at , decryption counter, export counter , etc? */
    ids: Vec<storage::Id>
}

impl Index {
    pub fn new(/* accounts */) -> Self {
        Self { ids: vec![] }
    }
}
