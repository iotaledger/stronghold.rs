// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Location, SLIP10DeriveInput};

use super::*;
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
use stronghold_derive::{execute_procedure, Procedure};

// ==========================
// Helper Procedures
// ==========================

#[derive(Procedure)]
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
    pub fn new_dyn(data_key: OutputKey, target: Location, hint: RecordHint) -> Self {
        WriteVault {
            data: InputData::Key {
                key: data_key,
                convert: |v| Ok(v),
            },
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

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

#[derive(Procedure)]
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

#[derive(Procedure)]
pub struct SLIP10Derive {
    #[input_data]
    chain: InputData<Chain>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    #[source]
    source: SLIP10DeriveInput,

    #[target]
    target: InterimProduct<Target>,
}

impl SLIP10Derive {
    pub fn new_from_seed(seed: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Seed(seed))
    }

    pub fn new_from_key(parent: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Key(parent))
    }

    fn new(chain: Chain, source: SLIP10DeriveInput) -> Self {
        SLIP10Derive {
            chain: InputData::Value(chain),
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
impl Process for SLIP10Derive {
    type Input = Chain;
    type Output = ChainCode;

    fn process(self, chain: Self::Input, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, engine::Error> {
        let dk = match self.source {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&chain))
            }
            SLIP10DeriveInput::Seed(_) => Seed::from_bytes(&guard.borrow()).derive(Curve::Ed25519, &chain),
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }
}

#[derive(Procedure)]
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

#[derive(Procedure)]
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

    pub fn new_dyn(passphrase: Option<String>, mnemonic_key: OutputKey) -> Self {
        let convert = |k: Vec<u8>| String::from_utf8(k).map_err(|e| anyhow::anyhow!("Invalid input: {}", e));
        BIP39Recover {
            passphrase,
            mnemonic: InputData::Key {
                key: mnemonic_key,
                convert,
            },
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

#[derive(Clone, Procedure)]
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

#[derive(Procedure)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: InterimProduct<OutputKey>,
}

impl Ed25519Sign {
    pub fn new(private_key: Location, msg: Vec<u8>) -> Self {
        Ed25519Sign {
            msg: InputData::Value(msg),
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
    pub fn new_dyn(private_key: Location, msg_key: OutputKey) -> Self {
        let input = InputData::Key {
            key: msg_key,
            convert: |v| Ok(v),
        };
        Ed25519Sign {
            msg: input,
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
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

#[derive(Procedure)]
pub struct SHA256Digest {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,
}

impl SHA256Digest {
    pub fn new(msg: Vec<u8>) -> Self {
        SHA256Digest {
            msg: InputData::Value(msg),
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }

    pub fn new_dyn(msg_key: OutputKey) -> Self {
        let input = InputData::Key {
            key: msg_key,
            convert: |v| Ok(v),
        };
        SHA256Digest {
            msg: input,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

impl Parse for SHA256Digest {
    type Input = Vec<u8>;
    type Output = [u8; SHA256_LEN];

    fn parse(self, input: Self::Input) -> Result<Self::Output, engine::Error> {
        let mut digest = [0; SHA256_LEN];
        SHA256(&input, &mut digest);
        Ok(digest)
    }
}
