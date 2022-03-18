// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_imports)]

use clap::{Parser, Subcommand};
use engine::vault::RecordHint;
use iota_stronghold_new as stronghold;
use log::*;
use stronghold::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    Client, ClientError, ClientVault, Store,
};

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
        #[clap(long)]
        key_type: String,

        #[clap(long)]
        vault_path: String,

        #[clap(long)]
        record_path: String,
    },
    #[clap(about = "Writes and reads from store")]
    StoreReadWrite {
        #[clap(long)]
        key: String,

        #[clap(long)]
        value: String,
    },
}

async fn command_write_and_read_from_store(key: String, value: String) -> Result<(), ClientError> {
    let client = Client::default();
    let store = client.store().await;

    info!(r#"Insert value into store "{}" with key "{}""#, value, key);
    store.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec(), None)?;

    info!(
        r#"Store containts key "{}" ? {}"#,
        key,
        store.contains_key(key.as_bytes().to_vec())?
    );

    info!(
        r#"Value for key "{}" ? {:?}"#,
        key,
        String::from_utf8(store.get(key.as_bytes().to_vec()).unwrap().deref().unwrap().to_vec()).unwrap()
    );

    Ok(())
}

async fn command_generate_key(key_type: String, vault_path: String, record_path: String) {
    info!("Generating keys with type {}", key_type);

    let client = Client::default();

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
        hint: RecordHint::new(b"").unwrap(),
    };

    let procedure_result = client
        .execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure))
        .await;

    info!("Key generation successful? {}", procedure_result.is_ok());

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: keytype,
        private_key: output_location,
    };

    info!("Creating public key");
    let procedure_result = client
        .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
        .await;

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();
    info!(r#"Public key is "{}" (Base64)"#, base64::encode(output));
}

#[tokio::main]
async fn main() {
    let _logger = env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Debug)
        .try_init();

    let cli = StrongholdCLI::parse();

    match cli.cmds {
        Command::GenerateKey {
            key_type,
            vault_path,
            record_path,
        } => {
            command_generate_key(key_type, vault_path, record_path).await;
        }
        Command::StoreReadWrite { key, value } => {
            command_write_and_read_from_store(key, value).await.unwrap();
        }
    }
}
