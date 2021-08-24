// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{BuildProcedure, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor};
use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode},
    },
    signatures::ed25519::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, RecordId, VaultId},
};
use std::convert::TryFrom;
use stronghold_derive::{proc_fn, ExecProcedure};

// ==========================
// Primitive Proc
// ==========================

pub struct ProcOutput<DOut> {
    pub write_vault: Vec<u8>,
    pub return_value: DOut,
}

pub trait Parser<In, Out> {
    fn parse(self, data: In) -> Result<Out, engine::Error>;
}

pub trait Generate<In, Out> {
    fn generate(self, data: In) -> Result<ProcOutput<Out>, engine::Error>;
}

pub trait Process<In, Out> {
    fn process(self, data: In, guard: GuardedVec<u8>) -> Result<ProcOutput<Out>, engine::Error>;
}

pub trait Sink<In, Out> {
    fn sink(self, data: In, guard: GuardedVec<u8>) -> Result<Out, engine::Error>;
}

// ==========================
// Helper Procs
// ==========================

pub struct Data<Out> {
    pub data: Out,
}

#[proc_fn]
impl<Out> Parser<(), Out> for Data<Out> {
    fn parse(self, _: ()) -> Result<Out, engine::Error> {
        Ok(self.data)
    }
}

pub struct CreateVault {
    vault_id: VaultId,
}

impl ExecProc for CreateVault {
    type InData = ();
    type OutData = ();

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, _: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        executor.create_vault(self.vault_id);
        Ok(())
    }
}

#[derive(ExecProcedure)]
pub struct Slip10Generate {
    pub size_bytes: usize,

    #[target_location]
    pub location: (VaultId, RecordId, RecordHint),
}

#[proc_fn]
impl Generate<(), ()> for Slip10Generate {
    fn generate(self, _: ()) -> Result<ProcOutput<()>, engine::Error> {
        let mut seed = vec![0u8; self.size_bytes];
        fill(&mut seed)?;
        Ok(ProcOutput {
            write_vault: seed,
            return_value: (),
        })
    }
}

#[derive(ExecProcedure)]
pub struct SLIP10Derive {
    pub chain: Chain,

    #[source_location]
    pub input: (VaultId, RecordId),

    #[target_location]
    pub output: (VaultId, RecordId, RecordHint),
}

#[proc_fn]
impl Process<(), ChainCode> for SLIP10Derive {
    fn process(self, _: (), guard: GuardedVec<u8>) -> Result<ProcOutput<ChainCode>, engine::Error> {
        let parent = slip10::Key::try_from(&*guard.borrow()).unwrap();
        let dk = parent.derive(&self.chain).unwrap();
        let write_vault: Vec<u8> = dk.into();
        Ok(ProcOutput {
            write_vault,
            return_value: dk.chain_code(),
        })
    }
}

#[derive(ExecProcedure)]
pub struct BIP39Generate {
    pub passphrase: String,

    #[target_location]
    pub output: (VaultId, RecordId, RecordHint),
}

#[proc_fn]
impl Generate<(), ()> for BIP39Generate {
    fn generate(self, _: ()) -> Result<ProcOutput<()>, engine::Error> {
        let mut entropy = [0u8; 32];
        fill(&mut entropy)?;

        let mnemonic = bip39::wordlist::encode(
            &entropy,
            &bip39::wordlist::ENGLISH, // TODO: make this user configurable
        )
        .unwrap();

        let mut seed = [0u8; 64];
        bip39::mnemonic_to_seed(&mnemonic, &self.passphrase, &mut seed);

        Ok(ProcOutput {
            write_vault: seed.to_vec(),
            return_value: (),
        })
    }
}

#[derive(ExecProcedure)]
pub struct BIP39Recover {
    pub mnemonic: String,
    pub passphrase: String,

    #[target_location]
    pub output: (VaultId, RecordId, RecordHint),
}

#[proc_fn]
impl Generate<(), ()> for BIP39Recover {
    fn generate(self, _: ()) -> Result<ProcOutput<()>, engine::Error> {
        let mut seed = [0u8; 64];
        bip39::mnemonic_to_seed(&self.mnemonic, &self.passphrase, &mut seed);
        Ok(ProcOutput {
            write_vault: seed.to_vec(),
            return_value: (),
        })
    }
}

#[derive(ExecProcedure)]
pub struct Ed25519PublicKey {
    #[source_location]
    pub private_key: (VaultId, RecordId),
}

#[proc_fn]
impl Sink<(), [u8; PUBLIC_KEY_LENGTH]> for Ed25519PublicKey {
    fn sink(self, _: (), guard: GuardedVec<u8>) -> Result<[u8; PUBLIC_KEY_LENGTH], engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();
        if raw.len() <= 32 {
            // the client actor will interupt the control flow
            // but could this be an option to return an error
            let e = engine::Error::CryptoError(crypto::Error::BufferSize {
                has: raw.len(),
                needs: 32,
                name: "data buffer",
            });
            return Err(e);
        }
        raw.truncate(32);
        let mut bs = [0; 32];
        bs.copy_from_slice(&raw);

        let sk = ed25519::SecretKey::from_bytes(bs);
        let pk = sk.public_key();

        Ok(pk.to_bytes())
    }
}

#[derive(ExecProcedure)]
pub struct Ed25519Sign {
    #[source_location]
    pub private_key: (VaultId, RecordId),
}

#[proc_fn]
impl Sink<Vec<u8>, [u8; SIGNATURE_LENGTH]> for Ed25519Sign {
    fn sink(self, data: Vec<u8>, guard: GuardedVec<u8>) -> Result<[u8; SIGNATURE_LENGTH], engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();

        if raw.len() <= 32 {
            let e = engine::Error::CryptoError(crypto::Error::BufferSize {
                has: raw.len(),
                needs: 32,
                name: "data buffer",
            });
            return Err(e);
        }
        raw.truncate(32);
        let mut bs = [0; 32];
        bs.copy_from_slice(&raw);

        let sk = ed25519::SecretKey::from_bytes(bs);

        let sig = sk.sign(&data);
        Ok(sig.to_bytes())
    }
}
