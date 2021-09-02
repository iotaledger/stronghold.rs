// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Location, SLIP10DeriveInput};

use super::{BuildProc, ComplexProc, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor};
use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode, Curve, Seed},
    },
    signatures::ed25519::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use stronghold_derive::{proc_fn, Procedure};

// ==========================
// Primitive Proc
// ==========================

pub struct ProcOutput<T> {
    pub write_vault: Vec<u8>,
    pub return_value: T,
}

pub trait Generate {
    type OutData;
    fn generate(self) -> Result<ProcOutput<Self::OutData>, engine::Error>;
}

pub trait Process {
    type OutData;
    fn process(self, guard: GuardedVec<u8>) -> Result<ProcOutput<Self::OutData>, engine::Error>;
}

pub trait Sink {
    type OutData;
    fn sink(self, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error>;
}

// ==========================
// Helper Procs
// ==========================

#[derive(Clone, Procedure)]
pub struct Input<T> {
    pub data: T,
}

impl<T> ExecProc for Input<T> {
    type InData = ();
    type OutData = T;

    fn exec<X: ProcExecutor>(self, _: &mut X, _: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        Ok(self.data)
    }
}

impl<T> From<T> for Input<T> {
    fn from(data: T) -> Self {
        Input { data }
    }
}

#[derive(Procedure, Serialize, Deserialize)]
pub struct WriteVault {
    #[input]
    pub data: Vec<u8>,
    #[target_location]
    pub output: (Location, RecordHint),
}

#[proc_fn]
impl Generate for WriteVault {
    type OutData = ();

    fn generate(self) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        Ok(ProcOutput {
            write_vault: self.data,
            return_value: (),
        })
    }
}

// ==========================
// Old Procs
// ==========================

#[derive(Procedure, Serialize, Deserialize)]
pub struct Slip10Generate {
    pub size_bytes: Option<usize>,

    #[target_location]
    pub output: (Location, RecordHint),
}

#[proc_fn]
impl Generate for Slip10Generate {
    type OutData = ();

    fn generate(self) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        let size_bytes = self.size_bytes.unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        Ok(ProcOutput {
            write_vault: seed,
            return_value: (),
        })
    }
}

#[derive(Procedure, Serialize, Deserialize)]
pub struct SLIP10Derive {
    #[input]
    pub chain: Chain,

    pub input: SLIP10DeriveInput,

    #[target_location]
    pub output: (Location, RecordHint),
}

impl GetSourceVault for SLIP10Derive {
    fn get_source(&self) -> Location {
        match self.input.clone() {
            SLIP10DeriveInput::Key(parent) => parent,
            SLIP10DeriveInput::Seed(seed) => seed,
        }
    }
}

#[proc_fn]
impl Process for SLIP10Derive {
    type OutData = ChainCode;

    fn process(self, guard: GuardedVec<u8>) -> Result<ProcOutput<ChainCode>, engine::Error> {
        let dk = match self.input {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            SLIP10DeriveInput::Seed(_) => Seed::from_bytes(&guard.borrow()).derive(Curve::Ed25519, &self.chain),
        }?;
        Ok(ProcOutput {
            write_vault: dk.into(),
            return_value: dk.chain_code(),
        })
    }
}

#[derive(Procedure, Serialize, Deserialize)]
pub struct BIP39Generate {
    pub passphrase: Option<String>,

    #[target_location]
    pub output: (Location, RecordHint),
}

#[proc_fn]
impl Generate for BIP39Generate {
    type OutData = ();

    fn generate(self) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        let mut entropy = [0u8; 32];
        fill(&mut entropy)?;

        let mnemonic = bip39::wordlist::encode(
            &entropy,
            &bip39::wordlist::ENGLISH, // TODO: make this user configurable
        )
        .unwrap();

        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

        Ok(ProcOutput {
            write_vault: seed.to_vec(),
            return_value: (),
        })
    }
}

#[derive(Procedure, Serialize, Deserialize)]
pub struct BIP39Recover {
    pub passphrase: Option<String>,

    #[input]
    pub mnemonic: String,

    #[target_location]
    pub output: (Location, RecordHint),
}

#[proc_fn]
impl Generate for BIP39Recover {
    type OutData = ();

    fn generate(self) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&self.mnemonic, &passphrase, &mut seed);
        Ok(ProcOutput {
            write_vault: seed.to_vec(),
            return_value: (),
        })
    }
}

#[derive(Clone, Procedure, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    #[source_location]
    pub private_key: Location,
}

#[proc_fn]
impl Sink for Ed25519PublicKey {
    type OutData = [u8; PUBLIC_KEY_LENGTH];

    fn sink(self, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();
        if raw.len() < 32 {
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

#[derive(Procedure, Serialize, Deserialize)]
pub struct Ed25519Sign {
    #[input]
    pub msg: Vec<u8>,

    #[source_location]
    pub private_key: Location,
}

#[proc_fn]
impl Sink for Ed25519Sign {
    type OutData = [u8; SIGNATURE_LENGTH];

    fn sink(self, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();

        if raw.len() < 32 {
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

        let sig = sk.sign(&self.msg);
        Ok(sig.to_bytes())
    }
}
