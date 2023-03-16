// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//#![allow(unused_imports)]
use crypto::keys::slip10::ChainCode;
use iota_stronghold::{
    procedures::{Chain, Ed25519Sign, GenerateKey, KeyType, PublicKey, Slip10Derive, Slip10Generate, WriteVault},
    Client, KeyProvider, Location, SnapshotPath, Stronghold,
};
use log::*;
use thiserror::Error as DeriveError;
use zeroize::Zeroizing;

const CLIENT_PATH: &str = "wasp";
const VAULT_PATH: &str = "wasp";
const KEY_TYPE: KeyType = KeyType::Ed25519;
const SEED_LENGTH: usize = 32;
const RECORD_PATH_SEED: &str = "seed";

pub struct StrongholdWrapper {
    snapshot_path: String,
    stronghold: Stronghold,
    client: Client,
}

#[derive(Debug, DeriveError)]
#[non_exhaustive]
pub enum WrapperError {
    #[error("Failed to open snapshot")]
    OpenSnapshot,

    #[error("Failed to commit to snapshot")]
    CommitToSnapshot,

    #[error("Failed to create client")]
    CreateClient,

    #[error("Failed to write client")]
    WriteClient,

    #[error("Failed to execute procedure: ({0})")]
    ExecuteProcedure(String),
}

impl StrongholdWrapper {
    pub fn from_file(snapshot_path: String, key_as_hash: Zeroizing<Vec<u8>>) -> Result<Self, WrapperError>
    {
        let stronghold = Stronghold::default();

        log::info!("[Rust] Loading snapshot => {}", snapshot_path);

        let commit_snapshot_path = &SnapshotPath::from_path(snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        let client = stronghold.load_client_from_snapshot(CLIENT_PATH, key_provider, commit_snapshot_path);

        let client = match client {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::OpenSnapshot),
        };

        Ok(Self {
            snapshot_path,
            stronghold,
            client,
        })
    }

    pub fn create_new(snapshot_path: String, key_as_hash: Zeroizing<Vec<u8>>) -> Result<Self, WrapperError>
    {
        let stronghold = Stronghold::default();

        let client = match stronghold.create_client(CLIENT_PATH) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::CreateClient),
        };

        let result = Self {
            snapshot_path,
            stronghold,
            client,
        };

        log::info!("[Rust] Client created");

        if let Err(_err) = result.stronghold.write_client(CLIENT_PATH) {
            return Err(WrapperError::WriteClient);
        }

        log::info!("[Rust] Client written");

        result.commit_with_key(key_as_hash)?;

        Ok(result)
    }

    fn commit_with_key(&self, key_as_hash: Zeroizing<Vec<u8>>) -> Result<bool, WrapperError>
    {
        log::info!("[Rust] Committing to snapshot");

        let commit_snapshot_path = &SnapshotPath::from_path(self.snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        match self
            .stronghold
            .commit_with_keyprovider(commit_snapshot_path, key_provider)
        {
            Err(_err) => Err(WrapperError::CommitToSnapshot),
            _ => Ok(true),
        }
    }

    pub fn get_public_key(&self, record_path: String) -> Result<Vec<u8>, WrapperError> {
        let private_key = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let public_key_procedure = PublicKey {
            ty: KEY_TYPE,
            private_key,
        };

        let procedure_result = match self.client.execute_procedure(public_key_procedure) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err))),
        };

        let output: Vec<u8> = procedure_result.into();

        Ok(output)
    }

    pub fn write_vault(&self, key_as_hash: Zeroizing<Vec<u8>>, record_path: String, data: Vec<u8>) -> Result<bool, WrapperError>
    {
        let location = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let sign_procedure = WriteVault { data, location };

        if let Err(_err) = self.client.execute_procedure(sign_procedure) {
            return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err)));
        }

        self.commit_with_key(key_as_hash)
    }

    pub fn sign(&self, record_path: String, data: Vec<u8>) -> Result<Vec<u8>, WrapperError> {
        let private_key = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let sign_procedure = Ed25519Sign { private_key, msg: data };

        let procedure_result = match self.client.execute_procedure(sign_procedure) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err))),
        };

        let signature: Vec<u8> = procedure_result.into();

        Ok(signature)
    }

    pub fn derive_seed(&self, key_as_hash: Zeroizing<Vec<u8>>, address_index: u32) -> Result<ChainCode, WrapperError>
    {
        let seed_derived_path = format!("{RECORD_PATH_SEED}.{address_index}");

        let seed_location = Location::Generic {
            record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let seed_derived_location = Location::Generic {
            record_path: seed_derived_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let chain = Chain::from_u32_hardened(vec![
            44,   // BIP-0044
            4218, // IOTA coin type
            0,    // zero account id
            0,    // public
            address_index,
        ]);

        log::info!("[Rust] Deriving Seed procedure started");

        let slip10_derive = Slip10Derive {
            chain,
            input: iota_stronghold::procedures::Slip10DeriveInput::Seed(seed_location),
            output: seed_derived_location,
        };

        let chain_code = match self.client.execute_procedure(slip10_derive) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err))),
        };

        log::info!("[Rust] Derive generated");
        log::info!("[Rust] Storing client");

        if let Err(_err) = self.stronghold.write_client(CLIENT_PATH) {
            return Err(WrapperError::WriteClient);
        }

        log::info!("[Rust] client stored");

        match self.commit_with_key(key_as_hash) {
            Err(err) => Err(err),
            _ => Ok(chain_code),
        }
    }

    pub fn generate_seed(&self, key_as_hash: Zeroizing<Vec<u8>>) -> Result<bool, WrapperError>
    {
        let output = Location::Generic {
            record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        log::info!("[Rust] Generating Seed procedure started");

        let slip10_generate = Slip10Generate {
            size_bytes: Some(SEED_LENGTH),
            output,
        };

        if let Err(_err) = self.client.execute_procedure(slip10_generate) {
            return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err)));
        }

        log::info!("[Rust] Key generated");
        log::info!("[Rust] Storing client");

        if let Err(_err) = self.stronghold.write_client(CLIENT_PATH) {
            return Err(WrapperError::WriteClient);
        }

        log::info!("[Rust] client stored");

        self.commit_with_key(key_as_hash)
    }

    pub fn generate_ed25519_keypair(&self, key_as_hash: Zeroizing<Vec<u8>>, record_path: String) -> Result<bool, WrapperError>
    {
        let output = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let generate_key_procedure = GenerateKey { ty: KEY_TYPE, output };

        log::info!("[Rust] Generating Key procedure started");

        if let Err(_err) = self.client.execute_procedure(generate_key_procedure) {
            return Err(WrapperError::ExecuteProcedure(format!("{:?}", _err)));
        }

        log::info!("[Rust] Key generated");
        log::info!("[Rust] Storing client");

        if let Err(_err) = self.stronghold.write_client(CLIENT_PATH) {
            return Err(WrapperError::WriteClient);
        }

        log::info!("[Rust] client stored");

        self.commit_with_key(key_as_hash)
    }
}
