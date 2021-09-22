// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{enum_from_inner, Location};

use super::*;
use crypto::{
    ciphers::{
        aes::Aes256Gcm,
        chacha::XChaCha20Poly1305,
        traits::{consts::Unsigned, Aead, Tag},
    },
    hashes::{
        blake2b::Blake2b256,
        sha::{Sha256, Sha384, Sha512},
        Digest,
    },
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode, Curve, Seed},
    },
    signatures::ed25519::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use hmac::{
    digest::{BlockInput, FixedOutputDirty, Reset, Update},
    Mac, NewMac,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, marker::PhantomData};
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
    Hash(Hashes),
    Hmac(Hmacs),
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
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_256 from Hash<Sha256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_384 from Hash<Sha384>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_512 from Hash<Sha512>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Blake2b256 from Hash<Blake2b256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_256 from Hmac<Sha256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_384 from Hmac<Sha384>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_512 from Hmac<Sha512>);

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

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub enum Hashes {
    Sha2_256(Hash<Sha256>),
    Sha2_384(Hash<Sha384>),
    Sha2_512(Hash<Sha512>),
    Blake2b256(Hash<Blake2b256>),
}

impl ProcedureStep for Hashes {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        match self {
            Hashes::Sha2_256(proc) => proc.execute(runner, state),
            Hashes::Sha2_384(proc) => proc.execute(runner, state),
            Hashes::Sha2_512(proc) => proc.execute(runner, state),
            Hashes::Blake2b256(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Hash<T> {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    _marker: PhantomData<T>,
}

impl<T> Hash<T> {
    pub fn new(msg: Vec<u8>) -> Self {
        Hash {
            msg: InputData::Value(msg),
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }

    pub fn dynamic(msg_key: OutputKey) -> Self {
        let input = InputData::Key(msg_key);
        Hash {
            msg: input,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Digest> Parse for Hash<T> {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn parse(self, input: Self::Input) -> Result<Self::Output, engine::Error> {
        let mut digest = vec![0; T::OutputSize::USIZE];
        digest.copy_from_slice(&T::digest(&input));
        Ok(digest)
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub enum Hmacs {
    Sha2_256(Hmac<Sha256>),
    Sha2_384(Hmac<Sha384>),
    Sha2_512(Hmac<Sha512>),
}

impl ProcedureStep for Hmacs {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        match self {
            Hmacs::Sha2_256(proc) => proc.execute(runner, state),
            Hmacs::Sha2_384(proc) => proc.execute(runner, state),
            Hmacs::Sha2_512(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Hmac<T> {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    #[source]
    key: Location,

    _marker: PhantomData<T>,
}

impl<T> Hmac<T> {
    pub fn new(msg: Vec<u8>, key: Location) -> Self {
        Hmac {
            msg: InputData::Value(msg),
            key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }

    pub fn dynamic(msg_key: OutputKey, key: Location) -> Self {
        let input = InputData::Key(msg_key);
        Hmac {
            msg: input,
            key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T> Utilize for Hmac<T>
where
    T: Digest + Update + BlockInput + Reset + Default + Clone + FixedOutputDirty,
{
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn utilize(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        let mut mac = vec![0; <T as Digest>::OutputSize::USIZE];
        let mut m = hmac::Hmac::<T>::new_from_slice(&*guard.borrow()).unwrap();
        m.update(&msg);
        mac.copy_from_slice(&m.finalize().into_bytes());
        Ok(mac)
    }
}

#[derive(Clone)]
pub enum Aeads {
    Aes256Gcm(AeadProc<Aes256Gcm>),
    XChaCha20Poly1305(AeadProc<XChaCha20Poly1305>),
}

#[derive(Clone)]
pub enum AeadProc<T> {
    Encrypt(AeadEncrypt<T>),
    Decrypt(AeadDecrypt<T>),
}

#[derive(Clone)]
pub struct AeadEncrypt<T> {
    associated_data: InputData<Vec<u8>>,
    plaintext: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,

    ciphertext: InterimProduct<OutputKey>,
    tag: InterimProduct<OutputKey>,
    _marker: PhantomData<T>,
}

impl<T> AeadEncrypt<T> {
    pub fn new(
        key: Location,
        plaintext: InputData<Vec<u8>>,
        associated_data: InputData<Vec<u8>>,
        nonce: InputData<Vec<u8>>,
    ) -> Self {
        let ciphertext = InterimProduct {
            target: OutputKey::random(),
            is_temp: true,
        };
        let tag = InterimProduct {
            target: OutputKey::random(),
            is_temp: true,
        };
        AeadEncrypt {
            associated_data,
            plaintext,
            nonce,
            key,
            ciphertext,
            tag,
            _marker: PhantomData,
        }
    }

    pub fn store_ciphertext(mut self, key: OutputKey) -> Self {
        self.ciphertext = InterimProduct {
            target: key,
            is_temp: false,
        };
        self
    }

    pub fn store_tag(mut self, key: OutputKey) -> Self {
        self.tag = InterimProduct {
            target: key,
            is_temp: false,
        };
        self
    }
}

impl<T> SourceInfo for AeadEncrypt<T> {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl<T: Aead> ProcedureStep for AeadEncrypt<T> {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        let AeadEncrypt {
            associated_data,
            plaintext,
            nonce,
            key,
            ciphertext,
            tag,
            ..
        } = self;
        let plaintext = match plaintext {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };

        let mut digested = Vec::new();
        let mut t = Tag::<T>::default();

        let f = |key: GuardedVec<u8>| {
            T::try_encrypt(&*key.borrow(), nonce, ad, plaintext, &mut digested, &mut t)
                .map_err(engine::Error::CryptoError)
        };

        runner.get_guard(&key, f).map_err(|e| anyhow::anyhow!(e))?;
        state.insert_data(ciphertext.target, digested.into(), ciphertext.is_temp);
        state.insert_data(tag.target, Vec::from(&*t).into(), tag.is_temp);
        Ok(())
    }
}

#[derive(Clone)]
pub struct AeadDecrypt<T> {
    associated_data: InputData<Vec<u8>>,
    ciphertext: InputData<Vec<u8>>,
    tag: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,
    plaintext: InterimProduct<OutputKey>,
    _marker: PhantomData<T>,
}

impl<T> AeadDecrypt<T> {
    pub fn new(
        key: Location,
        ciphertext: InputData<Vec<u8>>,
        associated_data: InputData<Vec<u8>>,
        tag: InputData<Vec<u8>>,
        nonce: InputData<Vec<u8>>,
    ) -> Self {
        let plaintext = InterimProduct {
            target: OutputKey::random(),
            is_temp: true,
        };
        AeadDecrypt {
            associated_data,
            ciphertext,
            tag,
            nonce,
            key,
            plaintext,
            _marker: PhantomData,
        }
    }
}

impl<T> OutputInfo for AeadDecrypt<T> {
    fn output_info(&self) -> &InterimProduct<OutputKey> {
        &self.plaintext
    }
    fn output_info_mut(&mut self) -> &mut InterimProduct<OutputKey> {
        &mut self.plaintext
    }
}

impl<T> SourceInfo for AeadDecrypt<T> {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl<T: Aead> ProcedureStep for AeadDecrypt<T> {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        let AeadDecrypt {
            associated_data,
            ciphertext,
            tag,
            nonce,
            key,
            plaintext,
            ..
        } = self;
        let ciphertext = match ciphertext {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };
        let tag = match tag {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key)?;
                data.as_ref()
            }
        };

        let mut output = Vec::new();

        let f = |key: GuardedVec<u8>| {
            T::try_decrypt(&*key.borrow(), nonce, ad, &mut output, ciphertext, tag).map_err(engine::Error::CryptoError)
        };

        runner.get_guard(&key, f).map_err(|e| anyhow::anyhow!(e))?;
        state.insert_data(plaintext.target, output.into(), plaintext.is_temp);
        Ok(())
    }
}

// K: Key, P: Plaintext, C: Ciphertext, M:Message (=Plaintext, but not intended to be encrypted)

// Cipher: Encrypt/Decrypt Stuff based on a key
// Block Cipher: C = E(K, P); E: Encryption-Alg
// Stream Cipher: C = P ⊕ KS where KS = SC(K, N); SC: Stream-Cipher Alg., N: Nonce, KS: Keystream
// MAC: Keyed hashing: T= MAC(K, M); T: Tag
// HMAC: Hash-based MAC aka the MAC is build from a Hash function
// Authenticated Encryption (AE): (& Authenticated Decryption (AD))
// Cipher & MAC: Cipher+MAC=C,T || MAC*Cipher = C || Cipher*MAC=C,T
// Authenticated Cipher: AE(K, P) = (C, T)
// Authenticated Encryption with associated Data (AEAD)
// AEAD(K, P, A) = (C, A, T); A: Associated Data that should not be encrypted, but authenticated
// ADAD(K, C, A, T) = (P, A): Decryption
