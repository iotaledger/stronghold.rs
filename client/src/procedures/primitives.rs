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
        x25519,
    },
    signatures::ed25519,
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use hmac::{
    digest::{BlockInput, FixedOutput, Reset, Update},
    Mac, NewMac,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, marker::PhantomData};
use stronghold_derive::{execute_procedure, Procedure};

// ==========================
// Helper Procedures
// ==========================

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PrimitiveProcedure {
    Helper(HelperProcedure),
    Crypto(CryptoProcedure),
}

impl ProcedureStep for PrimitiveProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            PrimitiveProcedure::Helper(proc) => proc.execute(runner, state),
            PrimitiveProcedure::Crypto(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HelperProcedure {
    WriteVault(WriteVault),
}

impl ProcedureStep for HelperProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            HelperProcedure::WriteVault(proc) => proc.execute(runner, state),
        }
    }
}

// TODO: remove notes, add proper docs.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoProcedure {
    // Generate Random array with length 64
    Slip10Generate(Slip10Generate),
    // for seg: u32 = [u8;4] in chain:
    //   child = HMAC_SH512(data: 0 ++ parent.privatekey ++ seg, key: parent.chaincode)
    //   child: privatekey: [u8;32] ++ chaincode: [u8;32] = [u8;64]
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),

    // bip39::mnemonic_to_seed(mnemonic, passphrase):
    // PBKDF2_HMAC_SHA512(password: mnemonic, salt: "mnemonic" ++ passphrase, count: 2048)
    BIP39Recover(BIP39Recover),
    Ed25519PublicKey(Ed25519PublicKey),
    Ed25519Sign(Ed25519Sign),
    Hash(Hashes),
    Hmac(Hmacs),
    Aead(Aeads),
}

impl ProcedureStep for CryptoProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
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
            Aead(proc) => proc.execute(runner, state),
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
impl GenerateSecret for WriteVault {
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
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::Aes256GcmEncrypt from AeadEncrypt<Aes256Gcm>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::Aes256GcmDecrypt from AeadDecrypt<Aes256Gcm>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::XChaCha20Poly1305Encrypt from AeadEncrypt<XChaCha20Poly1305>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::XChaCha20Poly1305Decrypt from AeadDecrypt<XChaCha20Poly1305>);

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

pub trait SecretKey {
    type Key;
    fn key_length() -> usize;
    fn from_bytes(bs: &[u8]) -> Result<Self::Key, crypto::Error>;
    fn generate() -> Result<Vec<u8>, crypto::Error> {
        let mut k = vec![0u8; Self::key_length()];
        fill(&mut k)?;
        Ok(k)
    }
}

pub trait Signature: SecretKey {
    fn signature_length() -> usize;
    fn pub_key_length() -> usize;

    fn sign(key: &Self::Key, bs: &[u8]) -> Vec<u8>;
    fn pub_key(key: &Self::Key) -> Vec<u8>;
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub struct Slip10;
impl SecretKey for Slip10 {
    type Key = slip10::Seed;

    fn key_length() -> usize {
        // TODO: make this configurable
        64
    }

    fn from_bytes(bs: &[u8]) -> Result<Self::Key, crypto::Error> {
        Ok(slip10::Seed::from_bytes(bs))
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub struct Ed25519;
impl SecretKey for Ed25519 {
    type Key = ed25519::SecretKey;
    fn key_length() -> usize {
        ed25519::SECRET_KEY_LENGTH
    }
    fn from_bytes(bs: &[u8]) -> Result<Self::Key, crypto::Error> {
        let bytes = bs.try_into().map_err(|_| crypto::Error::ConvertError {
            from: "bytes",
            to: "Ed25519 Public Key",
        })?;
        Ok(ed25519::SecretKey::from_bytes(bytes))
    }
}
impl Signature for Ed25519 {
    fn signature_length() -> usize {
        ed25519::SIGNATURE_LENGTH
    }
    fn pub_key_length() -> usize {
        ed25519::PUBLIC_KEY_LENGTH
    }
    fn sign(key: &Self::Key, bs: &[u8]) -> Vec<u8> {
        key.sign(bs).to_bytes().to_vec()
    }
    fn pub_key(key: &Self::Key) -> Vec<u8> {
        key.public_key().as_slice().to_vec()
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub struct X25519;
impl SecretKey for X25519 {
    type Key = x25519::SecretKey;
    fn key_length() -> usize {
        x25519::SECRET_KEY_LENGTH
    }
    fn from_bytes(bs: &[u8]) -> Result<Self::Key, crypto::Error> {
        let bytes = bs.try_into().map_err(|_| crypto::Error::ConvertError {
            from: "bytes",
            to: "X25519 Public Key",
        })?;
        Ok(x25519::SecretKey::from_bytes(bytes))
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct GenerateKey<T> {
    #[target]
    target: InterimProduct<Target>,
    _marker: PhantomData<T>,
}

impl<T> Default for GenerateKey<T> {
    fn default() -> Self {
        GenerateKey {
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

impl<T> GenerateKey<T> {
    pub fn new() -> Self {
        GenerateKey {
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: SecretKey> GenerateSecret for GenerateKey<T> {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
        let mut seed = vec![0u8; T::key_length()];
        fill(&mut seed)?;
        Ok(Products {
            secret: seed,
            output: (),
        })
    }
}

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
// TODO: fix size_bytes
pub type Slip10Generate = GenerateKey<Slip10>;

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
impl DeriveSecret for Slip10Derive {
    type Input = ();
    type Output = ChainCode;

    fn derive(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, engine::Error> {
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

#[derive(Procedure, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase) and store them in the `output` location
#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    passphrase: Option<String>,

    language: MnemonicLanguage,

    #[output_key]
    mnemonic_key: InterimProduct<OutputKey>,

    #[target]
    target: InterimProduct<Target>,
}

impl BIP39Generate {
    pub fn new(language: MnemonicLanguage, passphrase: Option<String>) -> Self {
        BIP39Generate {
            passphrase,
            language,
            mnemonic_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            target: InterimProduct {
                target: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for BIP39Generate {
    type Input = ();
    type Output = String;

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, engine::Error> {
        let mut entropy = [0u8; 32];
        fill(&mut entropy)?;

        let wordlist = match self.language {
            MnemonicLanguage::English => bip39::wordlist::ENGLISH,
            MnemonicLanguage::Japanese => bip39::wordlist::JAPANESE,
        };

        let mnemonic = bip39::wordlist::encode(&entropy, &wordlist).unwrap();

        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

        Ok(Products {
            secret: seed.to_vec(),
            output: mnemonic,
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
impl GenerateSecret for BIP39Recover {
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

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct GetPublicKey<T> {
    #[source]
    private_key: Location,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    _marker: PhantomData<T>,
}

impl<T> GetPublicKey<T> {
    pub fn new(private_key: Location) -> Self {
        GetPublicKey {
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Signature> UseSecret for GetPublicKey<T> {
    type Input = ();
    type Output = Vec<u8>;

    // TODO: this logic is most likely not the same for all signatures
    fn use_secret(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();
        let l = T::key_length();
        if raw.len() < l {
            // the client actor will interrupt the control flow
            // but could this be an option to return an error
            let e = engine::Error::CryptoError(crypto::Error::BufferSize {
                has: raw.len(),
                needs: l,
                name: "data buffer",
            });
            return Err(e);
        }
        raw.truncate(l);
        let mut bs = vec![0; l];
        bs.copy_from_slice(&raw);

        let sk = T::from_bytes(&bs)?;
        let pk = T::pub_key(&sk);

        Ok(pk.to_vec())
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
pub type Ed25519PublicKey = GetPublicKey<Ed25519>;

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub struct Sign<T> {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: InterimProduct<OutputKey>,

    _marker: PhantomData<T>,
}

impl<T> Sign<T> {
    pub fn new(msg: Vec<u8>, private_key: Location) -> Self {
        Sign {
            msg: InputData::Value(msg),
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
    pub fn dynamic(msg_key: OutputKey, private_key: Location) -> Self {
        Sign {
            msg: InputData::Key(msg_key),
            private_key,
            output_key: InterimProduct {
                target: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Signature> UseSecret for Sign<T> {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    // TODO: this logic is most likely not the same for all signatures
    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();

        let l = T::pub_key_length();
        if raw.len() < l {
            let e = engine::Error::CryptoError(crypto::Error::BufferSize {
                has: raw.len(),
                needs: l,
                name: "data buffer",
            });
            return Err(e);
        }
        raw.truncate(l);
        let mut bs = vec![0; l];
        bs.copy_from_slice(&raw);

        let sk = T::from_bytes(&bs)?;

        let sig = T::sign(&sk, &msg);
        Ok(sig.to_vec())
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
pub type Ed25519Sign = Sign<Ed25519>;

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub enum Hashes {
    Sha2_256(Hash<Sha256>),
    Sha2_384(Hash<Sha384>),
    Sha2_512(Hash<Sha512>),
    Blake2b256(Hash<Blake2b256>),
}

impl ProcedureStep for Hashes {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
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
impl<T: Digest> ProcessOutput for Hash<T> {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn process(self, input: Self::Input) -> Result<Self::Output, engine::Error> {
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
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
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
impl<T> UseSecret for Hmac<T>
where
    T: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error> {
        let mut mac = vec![0; <T as Digest>::OutputSize::USIZE];
        let mut m = hmac::Hmac::<T>::new_from_slice(&*guard.borrow()).unwrap();
        m.update(&msg);
        mac.copy_from_slice(&m.finalize().into_bytes());
        Ok(mac)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Aeads {
    Aes256GcmEncrypt(AeadEncrypt<Aes256Gcm>),
    Aes256GcmDecrypt(AeadDecrypt<Aes256Gcm>),
    XChaCha20Poly1305Encrypt(AeadEncrypt<XChaCha20Poly1305>),
    XChaCha20Poly1305Decrypt(AeadDecrypt<XChaCha20Poly1305>),
}

impl ProcedureStep for Aeads {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            Aeads::Aes256GcmEncrypt(proc) => proc.execute(runner, state),
            Aeads::Aes256GcmDecrypt(proc) => proc.execute(runner, state),
            Aeads::XChaCha20Poly1305Encrypt(proc) => proc.execute(runner, state),
            Aeads::XChaCha20Poly1305Decrypt(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
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
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
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
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut digested = Vec::new();
        let mut t = Tag::<T>::default();

        let f = |key: GuardedVec<u8>| {
            T::try_encrypt(&*key.borrow(), nonce, ad, plaintext, &mut digested, &mut t)
                .map_err(engine::Error::CryptoError)
        };

        runner.get_guard(&key, f).map_err(ProcedureError::VaultError)?;
        state.insert_data(ciphertext.target, digested.into(), ciphertext.is_temp);
        state.insert_data(tag.target, Vec::from(&*t).into(), tag.is_temp);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
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
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
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
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let tag = match tag {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_data(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut output = Vec::new();

        let f = |key: GuardedVec<u8>| {
            T::try_decrypt(&*key.borrow(), nonce, ad, &mut output, ciphertext, tag).map_err(engine::Error::CryptoError)
        };

        runner.get_guard(&key, f).map_err(ProcedureError::VaultError)?;
        state.insert_data(plaintext.target, output.into(), plaintext.is_temp);
        Ok(())
    }
}

// TODO: Add PBKDF

// TODO: Remove notes

// K: Key, P: Plaintext, C: Ciphertext, M:Message (=Plaintext, but not intended to be encrypted)

// Cipher: Encrypt/Decrypt Stuff based on a key
// // Block Cipher: C = E(K, P); E: Encryption-Alg
// // Stream Cipher: C = P ⊕ KS where KS = SC(K, N); SC: Stream-Cipher Alg., N: Nonce, KS: Keystream
// MAC: Keyed hashing: T= MAC(K, M); T: Tag
// HMAC: Hash-based MAC aka the MAC is build from a Hash function
// Authenticated Encryption (AE): (& Authenticated Decryption (AD))
// // Cipher & MAC: Cipher+MAC=C,T || MAC*Cipher = C || Cipher*MAC=C,T
// // Authenticated Cipher: AE(K, P) = (C, T)
// Authenticated Encryption with associated Data (AEAD)
// // AEAD(K, P, A) = (C, A, T); A: Associated Data that should not be encrypted, but authenticated
// // ADAD(K, C, A, T) = (P, A): Decryption
// Key Wrapping:
// // C = (KD, KEK) where KD: Key-data (= key to be wrapped),  KEK: Key-encryption-key (= often a Password)
// // -> Technically just normal cipher
