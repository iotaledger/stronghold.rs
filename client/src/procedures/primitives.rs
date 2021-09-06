// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Location, SLIP10DeriveInput};

use super::{
    BuildProc, ComplexProc, DataKey, ExecProc, InputDataInfo, OutputDataInfo, ProcExecutor, ProcState, SourceVaultInfo,
    TargetVaultInfo,
};
use crypto::{
    hashes::sha::{SHA256, SHA256_LEN},
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode, Curve, Seed},
    },
    signatures::ed25519::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use std::convert::TryFrom;
use stronghold_derive::{proc_fn, Procedure};
use stronghold_utils::test_utils::fresh::{bytestring, string};

// ==========================
// Primitive Proc
// ==========================

pub struct ProcOutput<T> {
    pub write_vault: Vec<u8>,
    pub return_value: T,
}

trait Parse {
    type InData;
    type OutData;

    fn parse(self, input: Self::InData) -> Result<Self::OutData, engine::Error>;
}

trait Generate {
    type InData;
    type OutData;

    fn generate(self, input: Self::InData) -> Result<ProcOutput<Self::OutData>, engine::Error>;
}

trait Process {
    type InData;
    type OutData;

    fn process(self, input: Self::InData, guard: GuardedVec<u8>) -> Result<ProcOutput<Self::OutData>, engine::Error>;
}

trait Sink {
    type InData;
    type OutData;

    fn sink(self, input: Self::InData, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error>;
}

// ==========================
// Helper Procs
// ==========================

#[derive(Procedure)]
pub struct WriteVault {
    #[input_data]
    data: InputData<Vec<u8>>,
    #[target_location]
    output: (Location, RecordHint, bool),
}

impl WriteVault {
    pub fn new(data: Vec<u8>, target: Location, hint: RecordHint) -> Self {
        WriteVault {
            data: InputData::Value(data),
            output: (target, hint, false),
        }
    }
    pub fn new_dyn(data_key: DataKey, target: Location, hint: RecordHint) -> Self {
        let input = InputData::Key {
            key: data_key,
            convert: |v| Ok(v),
        };
        WriteVault {
            data: input,
            output: (target, hint, false),
        }
    }
}

#[proc_fn]
impl Generate for WriteVault {
    type InData = Vec<u8>;
    type OutData = ();

    fn generate(self, input: Self::InData) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        Ok(ProcOutput {
            write_vault: input,
            return_value: (),
        })
    }
}

// ==========================
// Old Procs
// ==========================

#[derive(Clone)]
pub enum InputData<T> {
    Key {
        key: DataKey,
        convert: fn(Vec<u8>) -> Result<T, anyhow::Error>,
    },
    Value(T),
}

#[derive(Procedure)]
pub struct Slip10Generate {
    size_bytes: Option<usize>,

    #[target_location]
    output: (Location, RecordHint, bool),
}

impl Slip10Generate {
    pub fn new(size_bytes: Option<usize>) -> Self {
        let location = Location::generic(bytestring(), bytestring());
        let hint = RecordHint::new("").unwrap();
        Slip10Generate {
            size_bytes,
            output: (location, hint, true),
        }
    }
}

#[proc_fn]
impl Generate for Slip10Generate {
    type InData = ();
    type OutData = ();

    fn generate(self, _: Self::InData) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        let size_bytes = self.size_bytes.unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        Ok(ProcOutput {
            write_vault: seed,
            return_value: (),
        })
    }
}

#[derive(Procedure)]
pub struct SLIP10Derive {
    #[input_data]
    chain: InputData<Chain>,

    #[output_key]
    output_key: (DataKey, bool),

    #[source_location]
    input: SLIP10DeriveInput,

    #[target_location]
    output: (Location, RecordHint, bool),
}

impl SLIP10Derive {
    pub fn new_from_seed(seed: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Seed(seed))
    }

    pub fn new_from_key(parent: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Key(parent))
    }

    fn new(chain: Chain, source: SLIP10DeriveInput) -> Self {
        let location = Location::generic(bytestring(), bytestring());
        let hint = RecordHint::new("").unwrap();
        SLIP10Derive {
            chain: InputData::Value(chain),
            input: source,
            output: (location, hint, true),
            output_key: (DataKey::new(string()), true),
        }
    }
}

#[proc_fn]
impl Process for SLIP10Derive {
    type InData = Chain;
    type OutData = ChainCode;

    fn process(self, chain: Self::InData, guard: GuardedVec<u8>) -> Result<ProcOutput<ChainCode>, engine::Error> {
        let dk = match self.input {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&chain))
            }
            SLIP10DeriveInput::Seed(_) => Seed::from_bytes(&guard.borrow()).derive(Curve::Ed25519, &chain),
        }?;
        Ok(ProcOutput {
            write_vault: dk.into(),
            return_value: dk.chain_code(),
        })
    }
}

#[derive(Procedure)]
pub struct BIP39Generate {
    passphrase: Option<String>,

    #[target_location]
    output: (Location, RecordHint, bool),
}

impl BIP39Generate {
    pub fn new(passphrase: Option<String>) -> Self {
        let location = Location::generic(bytestring(), bytestring());
        let hint = RecordHint::new("").unwrap();
        BIP39Generate {
            passphrase,
            output: (location, hint, true),
        }
    }
}

#[proc_fn]
impl Generate for BIP39Generate {
    type InData = ();
    type OutData = ();

    fn generate(self, _: Self::InData) -> Result<ProcOutput<Self::OutData>, engine::Error> {
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

#[derive(Procedure)]
pub struct BIP39Recover {
    passphrase: Option<String>,

    #[input_data]
    mnemonic: InputData<String>,

    #[target_location]
    output: (Location, RecordHint, bool),
}

impl BIP39Recover {
    pub fn new(passphrase: Option<String>, mnemonic: String) -> Self {
        let location = Location::generic(bytestring(), bytestring());
        let hint = RecordHint::new("").unwrap();
        BIP39Recover {
            passphrase,
            mnemonic: InputData::Value(mnemonic),
            output: (location, hint, true),
        }
    }

    pub fn new_dyn(passphrase: Option<String>, mnemonic_key: DataKey) -> Self {
        let location = Location::generic(bytestring(), bytestring());
        let hint = RecordHint::new("").unwrap();
        let convert = |k: Vec<u8>| String::from_utf8(k).map_err(|e| anyhow::anyhow!("Invalid input: {}", e));
        let input = InputData::Key {
            key: mnemonic_key,
            convert,
        };
        BIP39Recover {
            passphrase,
            mnemonic: input,
            output: (location, hint, true),
        }
    }
}

#[proc_fn]
impl Generate for BIP39Recover {
    type InData = String;
    type OutData = ();

    fn generate(self, mnemonic: Self::InData) -> Result<ProcOutput<Self::OutData>, engine::Error> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);
        Ok(ProcOutput {
            write_vault: seed.to_vec(),
            return_value: (),
        })
    }
}

#[derive(Clone, Procedure)]
pub struct Ed25519PublicKey {
    #[source_location]
    private_key: Location,

    #[output_key]
    output_key: (DataKey, bool),
}

impl Ed25519PublicKey {
    pub fn new(private_key: Location) -> Self {
        Ed25519PublicKey {
            private_key,
            output_key: (DataKey::new(string()), true),
        }
    }
}

#[proc_fn]
impl Sink for Ed25519PublicKey {
    type InData = ();
    type OutData = [u8; PUBLIC_KEY_LENGTH];

    fn sink(self, _: Self::InData, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error> {
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

#[derive(Procedure)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source_location]
    private_key: Location,

    #[output_key]
    output_key: (DataKey, bool),
}

impl Ed25519Sign {
    pub fn new(private_key: Location, msg: Vec<u8>) -> Self {
        Ed25519Sign {
            msg: InputData::Value(msg),
            private_key,
            output_key: (DataKey::new(string()), true),
        }
    }
    pub fn new_dyn(private_key: Location, msg_key: DataKey) -> Self {
        let input = InputData::Key {
            key: msg_key,
            convert: |v| Ok(v),
        };
        Ed25519Sign {
            msg: input,
            private_key,
            output_key: (DataKey::new(string()), true),
        }
    }
}

#[proc_fn]
impl Sink for Ed25519Sign {
    type InData = Vec<u8>;
    type OutData = [u8; SIGNATURE_LENGTH];

    fn sink(self, msg: Self::InData, guard: GuardedVec<u8>) -> Result<Self::OutData, engine::Error> {
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

        let sig = sk.sign(&msg);
        Ok(sig.to_bytes())
    }
}

#[derive(Procedure)]
pub struct SHA256Digest {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: (DataKey, bool),
}

impl SHA256Digest {
    pub fn new(msg: Vec<u8>) -> Self {
        SHA256Digest {
            msg: InputData::Value(msg),
            output_key: (DataKey::new(string()), true),
        }
    }

    pub fn new_dyn(msg_key: DataKey) -> Self {
        let input = InputData::Key {
            key: msg_key,
            convert: |v| Ok(v),
        };
        SHA256Digest {
            msg: input,
            output_key: (DataKey::new(string()), true),
        }
    }
}

impl Parse for SHA256Digest {
    type InData = Vec<u8>;
    type OutData = [u8; SHA256_LEN];

    fn parse(self, input: Self::InData) -> Result<Self::OutData, engine::Error> {
        let mut digest = [0; SHA256_LEN];
        SHA256(&input, &mut digest);
        Ok(digest)
    }
}
