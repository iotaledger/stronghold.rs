// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{enum_from_inner, Location};

use super::*;
use crypto::{
    ciphers::traits::consts::Unsigned,
    hashes::{
        blake2b::Blake2b256,
        sha::{Sha256, Sha384, Sha512},
        Digest,
    },
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode, Curve, Seed},
    },
    macs::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512},
    signatures::ed25519::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use stronghold_derive::{execute_procedure, Procedure};

// ==========================
// Helper Procedures
// ==========================

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum PrimitiveProcedure {
    Helper(HelperProcedure),
    Crypto(CryptoProcedure),
}

impl ProcedureStep for PrimitiveProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        match self {
            PrimitiveProcedure::Helper(proc) => proc.execute(runner, state),
            PrimitiveProcedure::Crypto(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum HelperProcedure {
    WriteVault(WriteVault),
}

impl ProcedureStep for HelperProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        match self {
            HelperProcedure::WriteVault(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum CryptoProcedure {
    Slip10Generate(Slip10Generate),
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),
    BIP39Recover(BIP39Recover),
    Ed25519PublicKey(Ed25519PublicKey),
    Ed25519Sign(Ed25519Sign),
    Hash(Hash),
    Hmac(Hmac),
}

impl ProcedureStep for CryptoProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        use CryptoProcedure::*;
        match self {
            Slip10Generate(proc) => proc.execute(runner, state),
            Slip10Derive(proc) => proc.execute(runner, state),
            BIP39Generate(proc) => proc.execute(runner, state),
            BIP39Recover(proc) => proc.execute(runner, state),
            Ed25519PublicKey(proc) => proc.execute(runner, state),
            Ed25519Sign(proc) => proc.execute(runner, state),
            Hash(proc) => proc.execute(runner, state),
            Hmac(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct WriteVault {
    #[input_data]
    data: InputData<Vec<u8>>,
    #[target]
    target: InterimProduct<Target>,
}

impl WriteVault {
    pub fn new(data: Vec<u8>, location: Location, hint: RecordHint) -> Self {
        WriteVault {
            data: InputData::Value(data),
            target: InterimProduct {
                target: Target { location, hint },
                is_temp: false,
            },
        }
    }
    pub fn dynamic(data_key: OutputKey, target: Location, hint: RecordHint) -> Self {
        WriteVault {
            data: InputData::Key(data_key),
            target: InterimProduct {
                target: Target { location: target, hint },
                is_temp: false,
            },
        }
    }
}

#[execute_procedure]
impl Generate for WriteVault {
    type Input = Vec<u8>;
    type Output = ();

    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
        Ok(Products {
            secret: input,
            output: (),
        })
    }
}

// === implement From Traits from inner types to wrapper enums

enum_from_inner!(PrimitiveProcedure::Helper from HelperProcedure);
enum_from_inner!(PrimitiveProcedure::Helper, HelperProcedure::WriteVault from WriteVault);

enum_from_inner!(PrimitiveProcedure::Crypto  from CryptoProcedure);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Slip10Generate from Slip10Generate);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Slip10Derive from Slip10Derive);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::BIP39Generate from BIP39Generate);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::BIP39Recover from BIP39Recover);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Ed25519PublicKey from Ed25519PublicKey);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Ed25519Sign from Ed25519Sign);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash from Hash);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac from Hmac);

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Slip10Generate {
    size_bytes: Option<usize>,

    #[target]
    target: InterimProduct<Target>,
}

impl Slip10Generate {
    pub fn new(size_bytes: Option<usize>) -> Self {
        Slip10Generate {
            size_bytes,
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Generate for Slip10Generate {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
        let size_bytes = self.size_bytes.unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        Ok(Products {
            secret: seed,
            output: (),
        })
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    chain: Chain,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    #[source]
    source: SLIP10DeriveInput,

    #[target]
    target: InterimProduct<Target>,
}

impl Slip10Derive {
    pub fn new_from_seed(seed: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Seed(seed))
    }

    pub fn new_from_key(parent: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Key(parent))
    }

    fn new(chain: Chain, source: SLIP10DeriveInput) -> Self {
        Slip10Derive {
            chain,
            source,
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Process for Slip10Derive {
    type Input = ();
    type Output = ChainCode;

    fn process(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, engine::Error> {
        let dk = match self.source {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            SLIP10DeriveInput::Seed(_) => Seed::from_bytes(&guard.borrow()).derive(Curve::Ed25519, &self.chain),
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase) and store them in the `output` location
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    passphrase: Option<String>,

    #[target]
    target: InterimProduct<Target>,
}

impl BIP39Generate {
    pub fn new(passphrase: Option<String>) -> Self {
        BIP39Generate {
            passphrase,
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Generate for BIP39Generate {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
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

        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }
}

/// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
/// a BIP39 seed and store it in the `output` location
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct BIP39Recover {
    passphrase: Option<String>,

    #[input_data]
    mnemonic: InputData<String>,

    #[target]
    target: InterimProduct<Target>,
}

impl BIP39Recover {
    pub fn new(passphrase: Option<String>, mnemonic: String) -> Self {
        BIP39Recover {
            passphrase,
            mnemonic: InputData::Value(mnemonic),
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
        }
    }

    pub fn dynamic(passphrase: Option<String>, mnemonic_key: OutputKey) -> Self {
        BIP39Recover {
            passphrase,
            mnemonic: InputData::Key(mnemonic_key),
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Generate for BIP39Recover {
    type Input = String;
    type Output = ();

    fn generate(self, mnemonic: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);
        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    #[source]
    private_key: Location,

    #[output_key]
    output_key: InterimProduct<OutputKey>,
}

impl Ed25519PublicKey {
    pub fn new(private_key: Location) -> Self {
        Ed25519PublicKey {
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Utilize for Ed25519PublicKey {
    type Input = ();
    type Output = [u8; PUBLIC_KEY_LENGTH];

    fn utilize(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();
        if raw.len() < 32 {
            // the client actor will interrupt the control flow
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

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: InterimProduct<OutputKey>,
}

#[execute_procedure]
impl Utilize for Ed25519Sign {
    type Input = Vec<u8>;
    type Output = [u8; SIGNATURE_LENGTH];

    fn utilize(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
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

impl Ed25519Sign {
    pub fn new(msg: Vec<u8>, private_key: Location) -> Self {
        Ed25519Sign {
            msg: InputData::Value(msg),
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
    pub fn dynamic(msg_key: OutputKey, private_key: Location) -> Self {
        Ed25519Sign {
            msg: InputData::Key(msg_key),
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum HashType {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Blake2b256,
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Hash {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    ty: HashType,
}

impl Hash {
    pub fn new(msg: Vec<u8>, ty: HashType) -> Self {
        Hash {
            msg: InputData::Value(msg),
            ty,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }

    pub fn dynamic(msg_key: OutputKey, ty: HashType) -> Self {
        let input = InputData::Key(msg_key);
        Hash {
            msg: input,
            ty,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Parse for Hash {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn parse(self, input: Self::Input) -> Result<Self::Output, engine::Error> {
        fn digest<T: Digest>(msg: &[u8]) -> Vec<u8> {
            let mut digest = Vec::with_capacity(T::OutputSize::USIZE);
            for _ in 0..digest.capacity() {
                digest.push(0);
            }
            digest.copy_from_slice(&T::digest(msg));
            digest
        }

        let res = match self.ty {
            HashType::Sha2_256 => digest::<Sha256>(&input),
            HashType::Sha2_384 => digest::<Sha384>(&input),
            HashType::Sha2_512 => digest::<Sha512>(&input),
            HashType::Blake2b256 => digest::<Blake2b256>(&input),
        };
        Ok(res)
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Hmac {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    #[source]
    key: Location,

    ty: HashType,
}

impl Hmac {
    pub fn new(msg: Vec<u8>, key: Location, ty: HashType) -> Self {
        Hmac {
            msg: InputData::Value(msg),
            key,
            ty,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }

    pub fn dynamic(msg_key: OutputKey, key: Location, ty: HashType) -> Self {
        let input = InputData::Key(msg_key);
        Hmac {
            msg: input,
            key,
            ty,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl Utilize for Hmac {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn utilize(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        match self.ty {
            HashType::Sha2_256 => {
                let mut mac = [0; 32];
                HMAC_SHA256(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.into())
            }
            HashType::Sha2_384 => {
                let mut mac = [0; 48];
                HMAC_SHA384(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.into())
            }
            HashType::Sha2_512 => {
                let mut mac = [0; 64];
                HMAC_SHA512(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.into())
            }
            _ => unimplemented!("Blake2b HMACs are not supported"),
        }
    }
}
