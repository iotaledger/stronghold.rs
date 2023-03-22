// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]

use std::{error::Error, hash::Hash, num::NonZeroUsize, str::FromStr};

use clap::{Parser, Subcommand};
use crypto::hashes::{blake2b::Blake2b256, Digest};
use engine::vault::RecordHint;
use iota_stronghold as stronghold;
use log::*;
use stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyProvider, Location, SnapshotPath, Store, Stronghold,
};
use stronghold_utils::random as rand;
use thiserror::Error as DeriveError;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct ChainInput {
    pub chain: Chain,
}

impl FromStr for ChainInput {
    type Err = Box<dyn Error + 'static + Send + Sync>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let re = regex::Regex::new(r#"(?P<chain_id>\d+)+"#).unwrap();
        assert!(re.is_match(input));

        let chain: Vec<u32> = re
            .captures_iter(input)
            .map(|cap| cap["chain_id"].to_string())
            .map(|s: String| s.parse().unwrap())
            .collect();

        Ok(Self {
            chain: Chain::from_u32_hardened(chain),
        })
    }
}

#[derive(Debug, Parser)]
pub struct VaultLocation {
    #[clap(long, help = "The storage location inside the vault")]
    vault_path: String,

    #[clap(long, help = "The storage location for a record inside a vault")]
    record_path: String,
}

impl VaultLocation {
    fn from(vault: String, record: String) -> Self {
        Self {
            record_path: record,
            vault_path: vault,
        }
    }

    fn to_location(&self) -> Location {
        Location::Generic {
            record_path: self.record_path.clone().into_bytes().to_vec(),
            vault_path: self.vault_path.clone().into_bytes().to_vec(),
        }
    }
}

#[derive(Debug, Parser)]
pub struct StrongholdCLI {
    #[clap(subcommand)]
    cmds: Command,
}

#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum Command {
    #[clap(about = "Generates a secret key and returns the public key, Possible values are ['Ed25519', 'X25519']")]
    GenerateKey {
        #[clap(long, help = "The key type to use. Possible values are: ['Ed25519', 'X25519']")]
        key_type: String,

        #[clap(flatten)]
        location: VaultLocation,
    },
    #[clap(about = "Writes and reads from store")]
    StoreReadWrite {
        #[clap(long, help = "The key to map the value")]
        key: String,

        #[clap(long, help = "The actual value to be stored inside the Store")]
        value: String,
    },
    #[clap(about = "Generates a BIP39 Mnemonic with an optional passphrase")]
    BIP39Generate {
        #[clap(long, help = "An optional passphrase to protect the BIP39 Mnemonic")]
        passphrase: Option<String>,

        #[clap(
            long,
            help = r#"The language of the Mnemonic to chose. Currently available are "japanese", and "english""#
        )]
        lang: MnemonicLanguage,

        #[clap(flatten)]
        location: VaultLocation,
    },
    #[clap(about = "Generates a private master key")]
    SLIP10Generate {
        #[clap(long, help = "The size of the seed, defaults to 64 bytes")]
        size: Option<NonZeroUsize>,

        #[clap(flatten)]
        location: VaultLocation,
    },

    #[clap(about = "Derives a private / public key pair from either a master key, or a BIP39 key")]
    SLIP10Derive {
        #[clap(long, help = "The chain code to derive a key from")]
        chain: ChainInput,

        #[clap(long, help = "The storage location inside the vault")]
        input_vault_path: String,

        #[clap(long, help = "The storage location for a record inside a vault")]
        input_record_path: String,

        #[clap(long, help = "The storage location inside the vault")]
        output_vault_path: String,

        #[clap(long, help = "The storage location for a record inside a vault")]
        output_record_path: String,
    },

    #[clap(
        about = "Creates a new snapshot with a newly generated ed25519 key. The password to the snapshot will be returned."
    )]
    CreateSnapshot {
        #[clap(
            long,
            help = "The path to the snapshot file. Should be absolute, otherwise only the name of the snapshot file will be taken"
        )]
        path: String,

        #[clap(long, help = "The client path to generate an internal client")]
        client_path: String,

        #[clap(flatten)]
        output: VaultLocation,

        #[clap(long, help = "The key to encrypt the snapshot from filesystem")]
        key: String,
    },

    #[clap(about = "Reads a snapshot.")]
    ReadSnapshot {
        #[clap(
            long,
            help = "The path to the snapshot file. Should be absolute, otherwise only the name of the snapshot file will be taken"
        )]
        path: String,

        #[clap(long, help = "The client path of the Client to load")]
        client_path: String,

        #[clap(long, help = "The key to decrypt the snapshot from filesystem")]
        key: String,

        #[clap(flatten)]
        private_key_location: VaultLocation,
    },

    #[clap(
        about = "Recovers the BIP39 mnemonic from a passphrase. Hint: This requires, that the secret has previously been written into a snapshot"
    )]
    Bip39Recover {
        #[clap(
            long,
            help = "The path to the snapshot file. Should be absolute, otherwise only the name of the snapshot file will be taken"
        )]
        path: String,

        #[clap(long, help = "The client path of the Client to load")]
        client_path: String,

        #[clap(long, help = "The key to decrypt the snapshot. Base64 encoded")]
        key: String,

        #[clap(
            long,
            help = "The mnemonic to recover the BIP39 Seed. If the mnemonic is procted by a passphrase you have to supply it."
        )]
        mnemonic: String,

        #[clap(long, help = "The optional passphrase, if the supplied mnemonic is protected")]
        passphrase: Option<String>,

        #[clap(flatten)]
        output: VaultLocation,
    },
}

/// Calculates the Blake2b from a String
fn hash_blake2b(input: String) -> Zeroizing<Vec<u8>> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    let mut hash = Zeroizing::new(vec![0_u8; Blake2b256::output_size()]);
    hasher.finalize_into((&mut hash[..]).into());
    hash
}

async fn command_write_and_read_from_store(key: String, value: String) -> Result<(), ClientError> {
    let client = Client::default();
    let store = client.store();

    info!(r#"Insert value into store "{}" with key "{}""#, value, key);
    store.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec(), None)?;

    info!(
        r#"Store contains key "{}" ? {}"#,
        key,
        store.contains_key(key.as_bytes())?
    );

    info!(
        r#"Value for key "{}" ? {:?}"#,
        key,
        String::from_utf8(store.get(key.as_bytes()).unwrap().unwrap().to_vec()).unwrap()
    );

    Ok(())
}

async fn command_generate_key(key_type: String, location: VaultLocation) {
    info!("Generating keys with type {}", key_type);

    let client = Client::default();
    let (vault_path, record_path) = (location.vault_path, location.record_path);

    info!(
        "Using output location: vault_path={}, record_path={}",
        vault_path, record_path
    );

    let keytype = match key_type.to_lowercase().as_str() {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        _ => {
            error!("Unknown key type: {}", key_type);
            return;
        }
    };

    let output_location =
        stronghold::Location::generic(vault_path.as_bytes().to_vec(), record_path.as_bytes().to_vec());

    let generate_key_procedure = GenerateKey {
        ty: keytype.clone(),
        output: output_location.clone(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

    info!("Key generation successful? {}", procedure_result.is_ok());

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: keytype,
        private_key: output_location,
    };

    info!("Creating public key");
    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();
    info!(r#"Public key is "{}" (Base64)"#, base64::encode(output));
}

async fn command_generate_bip39(passphrase: Option<String>, language: MnemonicLanguage, location: VaultLocation) {
    let client = Client::default();
    let (vault_path, record_path) = (location.vault_path, location.record_path);

    let output_location =
        stronghold::Location::generic(vault_path.as_bytes().to_vec(), record_path.as_bytes().to_vec());

    let bip39_procedure = BIP39Generate {
        passphrase,
        language,
        output: output_location,
    };

    let result = client.execute_procedure(bip39_procedure).unwrap();

    info!("BIP39 Mnemonic: {}", result);
}

async fn command_slip10_generate(size: Option<NonZeroUsize>, location: VaultLocation) {
    let client = Client::default();

    let (vault_path, record_path) = (location.vault_path, location.record_path);

    let output_location =
        stronghold::Location::generic(vault_path.as_bytes().to_vec(), record_path.as_bytes().to_vec());

    let slip10_generate = Slip10Generate {
        size_bytes: size.map(|nzu| nzu.get()),
        output: output_location,
    };

    info!(
        "SLIP10 seed successfully created? {}",
        client.execute_procedure(slip10_generate).is_ok()
    );
}

async fn command_slip10_derive(chain: ChainInput, input: VaultLocation, output: VaultLocation) {
    let client = Client::default();

    let output_location = input.to_location();

    let slip10_generate = Slip10Generate {
        size_bytes: None, // take default vaule
        output: output_location.clone(),
    };

    client.execute_procedure(slip10_generate).unwrap();

    info!("Deriving SLIP10 Child Secret");
    let slip10_derive = Slip10Derive {
        chain: chain.chain,
        input: Slip10DeriveInput::Seed(output_location),
        output: output.to_location(),
    };

    info!(
        "Derivation Sucessful? {}",
        client.execute_procedure(slip10_derive).is_ok()
    );
}

async fn command_create_snapshot(path: String, client_path: String, output: VaultLocation, key: String) {
    let stronghold = Stronghold::default();

    let client_path = client_path.as_bytes().to_vec();

    let client = stronghold
        .create_client(client_path.clone())
        .expect("Cannot creat client");

    let output_location = output.to_location();

    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location,
    };

    client
        .execute_procedure(generate_key_procedure)
        .expect("Running procedure failed");

    stronghold
        .write_client(client_path)
        .expect("Store client state into snapshot state failed");

    // calculate hash from key
    let key = hash_blake2b(key);
    info!(
        "Snapshot created successully? {}",
        stronghold
            .commit_with_keyprovider(&SnapshotPath::from_path(path), &KeyProvider::try_from(key).unwrap())
            .is_ok()
    );
}

async fn command_read_snapshot(path: String, client_path: String, key: String, private_key_location: VaultLocation) {
    let stronghold = Stronghold::default();
    let client_path = client_path.as_bytes().to_vec();
    let snapshot_path = SnapshotPath::from_path(path);

    // calculate hash from key
    let key = hash_blake2b(key);
    let keyprovider = KeyProvider::try_from(key).expect("Failed to load key");

    info!("Loading snapshot");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .expect("Could not load client from Snapshot");

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: KeyType::Ed25519,
        private_key: private_key_location.to_location(),
    };

    info!("Creating public key");
    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();
    info!(r#"Public key is "{}" (Base64)"#, base64::encode(output));
}

async fn command_bip39_recover(
    path: String,
    client_path: String,
    key: String,
    mnemonic: String,
    output: VaultLocation,
    passphrase: Option<String>,
) {
    let stronghold = Stronghold::default();
    let client_path = client_path.as_bytes().to_vec();

    let snapshot_path = SnapshotPath::from_path(path);

    // calculate hash from key
    let key = hash_blake2b(key);
    let keyprovider = KeyProvider::try_from(key).expect("Failed to load key");

    info!("Loading snapshot");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .expect("Could not load client from Snapshot");

    // get the public key
    let procedure_bip39_recover = stronghold::procedures::BIP39Recover {
        passphrase,
        mnemonic,
        output: output.to_location(),
    };

    info!("Recovering BIP39");
    let procedure_result = client.execute_procedure(StrongholdProcedure::BIP39Recover(procedure_bip39_recover));

    info!(r#"BIP39 Recovery successful? {}"#, procedure_result.is_ok());
}

#[tokio::main]
async fn main() {
    let _logger = env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Debug)
        .try_init();

    let cli = StrongholdCLI::parse();

    match cli.cmds {
        Command::GenerateKey { key_type, location } => {
            command_generate_key(key_type, location).await;
        }
        Command::StoreReadWrite { key, value } => {
            command_write_and_read_from_store(key, value).await.unwrap();
        }
        Command::BIP39Generate {
            passphrase,
            lang,
            location,
        } => command_generate_bip39(passphrase, lang, location).await,
        Command::SLIP10Generate { size, location } => command_slip10_generate(size, location).await,
        Command::SLIP10Derive {
            chain,
            input_record_path,
            input_vault_path,
            output_record_path,
            output_vault_path,
        } => {
            command_slip10_derive(
                chain,
                VaultLocation::from(input_vault_path, input_record_path),
                VaultLocation::from(output_vault_path, output_record_path),
            )
            .await
        }
        Command::CreateSnapshot {
            path,
            client_path,
            output,
            key,
        } => command_create_snapshot(path, client_path, output, key).await,
        Command::ReadSnapshot {
            path,
            client_path,
            key,
            private_key_location,
        } => command_read_snapshot(path, client_path, key, private_key_location).await,
        Command::Bip39Recover {
            path,
            mnemonic,
            output,
            passphrase,
            client_path,
            key,
        } => command_bip39_recover(path, client_path, key, mnemonic, output, passphrase).await,
    }
}
