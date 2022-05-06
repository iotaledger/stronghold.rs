//#![allow(unused_imports)]
use crypto::keys::slip10::ChainCode;
use iota_stronghold_new as stronghold;
use stronghold::procedures::{Chain, Ed25519Sign, PublicKey, Slip10Derive, Slip10Generate};
use stronghold::Client;
use stronghold::{
    procedures::{GenerateKey, KeyType},
    KeyProvider, Location, SnapshotPath, Stronghold,
};
use thiserror::Error as DeriveError;

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
    FailedToOpenSnapshot,

    #[error("Failed to commit to snapshot")]
    FailedToCommitToSnapshot,

    #[error("Failed to create client")]
    FailedToCreateClient,

    #[error("Failed to write client")]
    FailedToWriteClient,

    #[error("Failed to execute procedure")]
    FailedToExecuteProcedure,
}

impl StrongholdWrapper {
    pub fn from_file(snapshot_path: String, key_as_hash: Vec<u8>) -> Result<Self, WrapperError> {
        let stronghold = Stronghold::default();

        println!("[Rust] Loading snapshot => {}", snapshot_path);

        let commit_snapshot_path = &SnapshotPath::from_path(snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        let client = stronghold.load_client_from_snapshot(CLIENT_PATH, key_provider, commit_snapshot_path);

        let client = match client {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::FailedToOpenSnapshot),
        };

        return Ok(Self {
            snapshot_path: snapshot_path.clone(),
            stronghold,
            client,
        });
    }

    pub fn create_new(snapshot_path: String, key_as_hash: Vec<u8>) -> Result<Self, WrapperError> {
        let stronghold = Stronghold::default();

        let client = match stronghold.create_client(CLIENT_PATH) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::FailedToCreateClient),
        };

        println!("[Rust] Client created");

        match stronghold.write_client(CLIENT_PATH) {
            Err(_err) => return Err(WrapperError::FailedToWriteClient),
            _ => {}
        }

        println!("[Rust] Client written");

        println!("[Rust] Writing snapshot => {}", snapshot_path);

        let commit_snapshot_path = &SnapshotPath::from_path(snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        match stronghold.commit(commit_snapshot_path, key_provider) {
            Err(_err) => return Err(WrapperError::FailedToCommitToSnapshot),
            _ => {}
        };

        return Ok(Self {
            snapshot_path: snapshot_path.clone(),
            stronghold,
            client,
        });
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
            Err(_err) => return Err(WrapperError::FailedToExecuteProcedure),
        };

        let output: Vec<u8> = procedure_result.into();

        return Ok(output);
    }

    pub fn sign(&self, record_path: String, data: Vec<u8>) -> Result<Vec<u8>, WrapperError> {
        let output_location = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let sign_procedure = Ed25519Sign {
            private_key: output_location,
            msg: data.clone(),
        };

        let procedure_result = match self.client.execute_procedure(sign_procedure) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::FailedToExecuteProcedure),
        };

        let signature: Vec<u8> = procedure_result.into();

        return Ok(signature);
    }

    pub fn derive_seed(&self, key_as_hash: Vec<u8>, address_index: u32) -> Result<ChainCode, WrapperError> {
        let seed_derived_path = format!("{RECORD_PATH_SEED}{address_index}");

        let seed_location = Location::Generic {
            record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let seed_derived_location = Location::Generic {
            record_path: seed_derived_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let chain = Chain::from_u32_hardened(vec![address_index]);

        println!("[Rust] Deriving Seed procedure started");

        let slip10_derive = Slip10Derive {
            chain,
            input: iota_stronghold_new::procedures::Slip10DeriveInput::Seed(seed_location),
            output: seed_derived_location,
        };

        let chain_code = match self.client.execute_procedure(slip10_derive) {
            Ok(res) => res,
            Err(_err) => return Err(WrapperError::FailedToExecuteProcedure),
        };

        println!("[Rust] Derive generated");
        println!("[Rust] Storing client");

        match self.stronghold.write_client(CLIENT_PATH) {
            Err(_err) => return Err(WrapperError::FailedToWriteClient),
            _ => {}
        };

        println!("[Rust] client stored");
        println!("[Rust] Committing to snapshot");

        let commit_snapshot_path = &SnapshotPath::from_path(self.snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        match self.stronghold.commit(commit_snapshot_path, key_provider) {
            Err(_err) => return Err(WrapperError::FailedToCommitToSnapshot),
            _ => {}
        }

        println!("[Rust] Snapshot committed!");

        return Ok(chain_code);
    }

    pub fn generate_seed(&self, key_as_hash: Vec<u8>) -> Result<bool, WrapperError> {
        let output = Location::Generic {
            record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        println!("[Rust] Generating Seed procedure started");

        let slip10_generate = Slip10Generate {
            size_bytes: Some(SEED_LENGTH),
            output,
        };

        match self.client.execute_procedure(slip10_generate) {
            Err(_err) => return Err(WrapperError::FailedToExecuteProcedure),
            _ => {}
        }

        println!("[Rust] Key generated");
        println!("[Rust] Storing client");

        match self.stronghold.write_client(CLIENT_PATH) {
            Err(_err) => return Err(WrapperError::FailedToWriteClient),
            _ => {}
        };

        println!("[Rust] client stored");

        println!("[Rust] Committing to snapshot");

        let commit_snapshot_path = &SnapshotPath::from_path(self.snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        match self.stronghold.commit(commit_snapshot_path, key_provider) {
            Err(_err) => return Err(WrapperError::FailedToCommitToSnapshot),
            _ => {}
        }

        return Ok(true);
    }

    pub fn generate_ed25519_keypair(
        &self,
        key_as_hash: Vec<u8>,
        record_path: String,
    ) -> Result<bool, WrapperError> {
        let output = Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: VAULT_PATH.as_bytes().to_vec(),
        };

        let generate_key_procedure = GenerateKey { ty: KEY_TYPE, output };

        println!("[Rust] Generating Key procedure started");

        match self.client.execute_procedure(generate_key_procedure) {
            Err(_err) => return Err(WrapperError::FailedToExecuteProcedure),
            _ => {},
        }

        println!("[Rust] Key generated");
        println!("[Rust] Storing client");

        match self.stronghold.write_client(CLIENT_PATH) {
            Err(_err) => return Err(WrapperError::FailedToWriteClient),
            _ => {}
        };

        println!("[Rust] client stored");

        println!("[Rust] Committing to snapshot");

        let commit_snapshot_path = &SnapshotPath::from_path(self.snapshot_path.clone());
        let key_provider = &KeyProvider::try_from(key_as_hash).unwrap();

        match self.stronghold.commit(commit_snapshot_path, key_provider) {
            Err(_err) => return Err(WrapperError::FailedToCommitToSnapshot),
            _ => {}
        }

        println!("[Rust] Snapshot committed!");

        return Ok(true);
    }
}
