// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::{enum_from_inner, Location};
use crypto::{
    ciphers::traits::consts::Unsigned,
    hashes::sha::{SHA256, SHA256_LEN, SHA384, SHA384_LEN, SHA512, SHA512_LEN},
    keys::{
        bip39,
        pbkdf::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512},
        slip10, x25519,
    },
    macs::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512},
    signatures::ed25519,
    utils::rand::fill,
};

pub mod crypto_reexport {
    pub use crypto::{
        ciphers::{
            aes::Aes256Gcm,
            chacha::XChaCha20Poly1305,
            traits::{Aead, Tag},
        },
        hashes::{
            blake2b::Blake2b256,
            sha::{Sha256, Sha384, Sha512},
            Digest,
        },
        keys::slip10::{Chain, ChainCode},
    };
}
use crypto_reexport::*;
use engine::{runtime::GuardedVec, vault::RecordHint};
use serde::{Deserialize, Serialize};
use std::convert::{From, Into, TryFrom};
use stronghold_derive::{execute_procedure, Procedure};
use stronghold_utils::GuardDebug;

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
    PublicKey(PublicKey),
    GenerateKey(GenerateKey),
    Ed25519Sign(Ed25519Sign),
    X25519DiffieHellman(X25519DiffieHellman),
    Hash(Hash),
    Hmac(Hmac),
    Pbkdf2Hmac(Pbkdf2Hmac),
    AeadEncrypt(AeadEncrypt),
    AeadDecrypt(AeadDecrypt),
}

impl ProcedureStep for CryptoProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        use CryptoProcedure::*;
        match self {
            Slip10Generate(proc) => proc.execute(runner, state),
            Slip10Derive(proc) => proc.execute(runner, state),
            BIP39Generate(proc) => proc.execute(runner, state),
            BIP39Recover(proc) => proc.execute(runner, state),
            GenerateKey(proc) => proc.execute(runner, state),
            PublicKey(proc) => proc.execute(runner, state),
            Ed25519Sign(proc) => proc.execute(runner, state),
            X25519DiffieHellman(proc) => proc.execute(runner, state),
            Hash(proc) => proc.execute(runner, state),
            Hmac(proc) => proc.execute(runner, state),
            Pbkdf2Hmac(proc) => proc.execute(runner, state),
            AeadEncrypt(proc) => proc.execute(runner, state),
            AeadDecrypt(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct WriteVault {
    #[input_data]
    data: InputData<Vec<u8>>,
    #[target]
    target: TempTarget,
}

impl WriteVault {
    pub fn new<I, T>(data: I, location: Location, hint: RecordHint) -> Self
    where
        I: IntoInput<T>,
        T: Into<Vec<u8>>,
    {
        let data = match data.into_input() {
            InputData::Key(k) => InputData::Key(k),
            InputData::Value(v) => InputData::Value(v.into()),
        };
        WriteVault {
            data,
            target: TempTarget {
                write_to: Target { location, hint },
                is_temp: false,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for WriteVault {
    type Input = Vec<u8>;
    type Output = ();

    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
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
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::GenerateKey from GenerateKey);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::PublicKey from PublicKey);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Ed25519Sign from Ed25519Sign);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::X25519DiffieHellman from X25519DiffieHellman);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash from Hash);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac from Hmac);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Pbkdf2Hmac from Pbkdf2Hmac);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::AeadEncrypt from AeadEncrypt);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::AeadDecrypt from AeadDecrypt);

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AeadAlg {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    Blake2b,
    Sha2(Sha2Hash),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sha2Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase). Store the seed and return the mnemonic sentence as data output.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    passphrase: Option<String>,

    language: MnemonicLanguage,

    #[output_key]
    mnemonic_key: TempOutput,

    #[target]
    target: TempTarget,
}

impl BIP39Generate {
    pub fn new(language: MnemonicLanguage, passphrase: Option<String>) -> Self {
        BIP39Generate {
            passphrase,
            language,
            mnemonic_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for BIP39Generate {
    type Input = ();
    type Output = String;

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
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
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Recover {
    passphrase: Option<String>,

    #[input_data]
    mnemonic: InputData<String>,

    #[target]
    target: TempTarget,
}

impl BIP39Recover {
    pub fn new<I>(mnemonic: I, passphrase: Option<String>) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        BIP39Recover {
            passphrase,
            mnemonic: mnemonic.into_input(),
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for BIP39Recover {
    type Input = String;
    type Output = ();

    fn generate(self, mnemonic: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);
        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }
}

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Generate {
    size_bytes: usize,

    #[target]
    target: TempTarget,
}

impl Default for Slip10Generate {
    fn default() -> Self {
        Slip10Generate {
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            size_bytes: 64,
        }
    }
}

impl Slip10Generate {
    pub fn new(size_bytes: usize) -> Self {
        Slip10Generate {
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            size_bytes,
        }
    }
}

#[execute_procedure]
impl GenerateSecret for Slip10Generate {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = vec![0u8; self.size_bytes];
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

impl SourceInfo for SLIP10DeriveInput {
    fn source_location(&self) -> &Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }

    fn source_location_mut(&mut self) -> &mut Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }
}

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    chain: Chain,

    #[output_key]
    output_key: TempOutput,

    #[source]
    source: SLIP10DeriveInput,

    #[target]
    target: TempTarget,
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
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl DeriveSecret for Slip10Derive {
    type Input = ();
    type Output = ChainCode;

    fn derive(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, FatalProcedureError> {
        let dk = match self.source {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            SLIP10DeriveInput::Seed(_) => {
                slip10::Seed::from_bytes(&guard.borrow()).derive(slip10::Curve::Ed25519, &self.chain)
            }
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }
}

fn x25519_secret_key(guard: GuardedVec<u8>) -> Result<x25519::SecretKey, crypto::Error> {
    let raw = guard.borrow();
    let raw = (*raw).to_vec();
    if raw.len() != x25519::SECRET_KEY_LENGTH {
        let e = crypto::Error::BufferSize {
            has: raw.len(),
            needs: x25519::SECRET_KEY_LENGTH,
            name: "data buffer",
        };
        return Err(e);
    }
    x25519::SecretKey::try_from_slice(&raw)
}

fn ed25519_secret_key(guard: GuardedVec<u8>) -> Result<ed25519::SecretKey, crypto::Error> {
    let raw = guard.borrow();
    let mut raw = (*raw).to_vec();
    if raw.len() < ed25519::SECRET_KEY_LENGTH {
        let e = crypto::Error::BufferSize {
            has: raw.len(),
            needs: ed25519::SECRET_KEY_LENGTH,
            name: "data buffer",
        };
        return Err(e);
    }
    raw.truncate(ed25519::SECRET_KEY_LENGTH);
    let mut bs = [0; ed25519::SECRET_KEY_LENGTH];
    bs.copy_from_slice(&raw);

    Ok(ed25519::SecretKey::from_bytes(bs))
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKey {
    ty: KeyType,

    #[target]
    target: TempTarget,
}

impl GenerateKey {
    pub fn new(ty: KeyType) -> Self {
        GenerateKey {
            ty,
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for GenerateKey {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.ty {
            KeyType::Ed25519 => ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
            KeyType::X25519 => x25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
        };
        Ok(Products { secret, output: () })
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    ty: KeyType,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,
}

impl PublicKey {
    pub fn new(ty: KeyType, private_key: Location) -> Self {
        Self {
            ty,
            private_key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl UseSecret for PublicKey {
    type Input = ();
    type Output = Vec<u8>;

    fn use_secret(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            KeyType::Ed25519 => {
                let sk = ed25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes().to_vec())
            }
            KeyType::X25519 => {
                let sk = x25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes().to_vec())
            }
        }
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,
}

impl Ed25519Sign {
    pub fn new<I>(msg: I, private_key: Location) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Self {
            msg: msg.into_input(),
            private_key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl UseSecret for Ed25519Sign {
    type Input = Vec<u8>;
    type Output = [u8; ed25519::SIGNATURE_LENGTH];

    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let sk = ed25519_secret_key(guard)?;
        let sig = sk.sign(&msg);
        Ok(sig.to_bytes())
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct X25519DiffieHellman {
    public_key: [u8; x25519::PUBLIC_KEY_LENGTH],

    #[source]
    private_key: Location,

    #[target]
    target: TempTarget,
}

impl X25519DiffieHellman {
    pub fn new(public_key: [u8; x25519::PUBLIC_KEY_LENGTH], private_key: Location) -> Self {
        Self {
            public_key,
            private_key,
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl DeriveSecret for X25519DiffieHellman {
    type Input = ();
    type Output = ();

    fn derive(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Products<()>, FatalProcedureError> {
        let sk = x25519_secret_key(guard)?;
        let public = x25519::PublicKey::from_bytes(self.public_key);
        let shared_key = sk.diffie_hellman(&public);

        Ok(Products {
            secret: shared_key.to_bytes().to_vec(),
            output: (),
        })
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    ty: HashType,

    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: TempOutput,
}

impl Hash {
    pub fn new<I>(ty: HashType, msg: I) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Hash {
            ty,
            msg: msg.into_input(),
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl ProcessData for Hash {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn process(self, input: Self::Input) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            HashType::Blake2b => {
                let mut digest = [0; <Blake2b256 as Digest>::OutputSize::USIZE];
                digest.copy_from_slice(&Blake2b256::digest(&input));
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha256) => {
                let mut digest = [0; SHA256_LEN];
                SHA256(&input, &mut digest);
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha384) => {
                let mut digest = [0; SHA384_LEN];
                SHA384(&input, &mut digest);
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha512) => {
                let mut digest = [0; SHA512_LEN];
                SHA512(&input, &mut digest);
                Ok(digest.to_vec())
            }
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hmac {
    ty: Sha2Hash,

    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: TempOutput,

    #[source]
    key: Location,
}

impl Hmac {
    pub fn new<I>(ty: Sha2Hash, msg: I, key: Location) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Hmac {
            ty,
            msg: msg.into_input(),
            key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl UseSecret for Hmac {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            Sha2Hash::Sha256 => {
                let mut mac = [0; SHA256_LEN];
                HMAC_SHA256(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha384 => {
                let mut mac = [0; SHA384_LEN];
                HMAC_SHA384(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha512 => {
                let mut mac = [0; SHA512_LEN];
                HMAC_SHA512(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Hmac {
    ty: Sha2Hash,

    password: Vec<u8>,
    salt: Vec<u8>,
    count: u32,

    #[target]
    target: TempTarget,
}

impl Pbkdf2Hmac {
    pub fn new(ty: Sha2Hash, password: Vec<u8>, salt: Vec<u8>, count: u32) -> Self {
        Pbkdf2Hmac {
            ty,
            password,
            salt,
            count,
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for Pbkdf2Hmac {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret;
        match self.ty {
            Sha2Hash::Sha256 => {
                let mut buffer = [0; SHA256_LEN];
                PBKDF2_HMAC_SHA256(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut buffer = [0; SHA384_LEN];
                PBKDF2_HMAC_SHA384(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut buffer = [0; SHA512_LEN];
                PBKDF2_HMAC_SHA512(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
        }
        Ok(Products { secret, output: () })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEncrypt {
    alg: AeadAlg,

    associated_data: InputData<Vec<u8>>,
    plaintext: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,

    ciphertext: TempOutput,
    tag: TempOutput,
}

impl AeadEncrypt {
    /// Create a new aead encryption procedure.
    /// **Note**: The nonce is required to have length [`<T as Aead>::NONCE_LENGTH` ].
    pub fn new(
        alg: AeadAlg,
        key: Location,
        plaintext: impl IntoInput<Vec<u8>>,
        associated_data: impl IntoInput<Vec<u8>>,
        nonce: impl IntoInput<Vec<u8>>,
    ) -> Self {
        let ciphertext = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        let tag = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        AeadEncrypt {
            alg,
            associated_data: associated_data.into_input(),
            plaintext: plaintext.into_input(),
            nonce: nonce.into_input(),
            key,
            ciphertext,
            tag,
        }
    }

    pub fn store_ciphertext(mut self, key: OutputKey) -> Self {
        self.ciphertext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn ciphertext(&self) -> OutputKey {
        self.ciphertext.output_key()
    }

    pub fn store_tag(mut self, key: OutputKey) -> Self {
        self.tag = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn tag(&self) -> OutputKey {
        self.tag.output_key()
    }
}

impl SourceInfo for AeadEncrypt {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl ProcedureStep for AeadEncrypt {
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
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut ctx = vec![0; plaintext.len()];
        let mut t = match self.alg {
            AeadAlg::Aes256Gcm => Tag::<Aes256Gcm>::default(),
            AeadAlg::XChaCha20Poly1305 => Tag::<XChaCha20Poly1305>::default(),
        };

        let alg = self.alg;
        let f = |key: GuardedVec<u8>| {
            let f = match alg {
                AeadAlg::Aes256Gcm => Aes256Gcm::try_encrypt,
                AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::try_encrypt,
            };
            f(&*key.borrow(), nonce, ad, plaintext, &mut ctx, &mut t)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(ciphertext.write_to, ctx.into_procedure_io(), ciphertext.is_temp);
        state.insert_output(tag.write_to, Vec::from(&*t).into_procedure_io(), tag.is_temp);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadDecrypt {
    alg: AeadAlg,
    associated_data: InputData<Vec<u8>>,
    ciphertext: InputData<Vec<u8>>,
    tag: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,
    plaintext: TempOutput,
}

impl AeadDecrypt {
    /// Create a new aead encryption procedure.
    /// **Note**: It is required for the nonce to have length [`<T as Aead>::NONCE_LENGTH` ] and
    /// the tag to have length [`<T as Aead>::TAG_LENGTH` ];
    pub fn new(
        alg: AeadAlg,
        key: Location,
        ciphertext: impl IntoInput<Vec<u8>>,
        associated_data: impl IntoInput<Vec<u8>>,
        tag: impl IntoInput<Vec<u8>>,
        nonce: impl IntoInput<Vec<u8>>,
    ) -> Self {
        let plaintext = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        AeadDecrypt {
            alg,
            associated_data: associated_data.into_input(),
            ciphertext: ciphertext.into_input(),
            tag: tag.into_input(),
            nonce: nonce.into_input(),
            key,
            plaintext,
        }
    }

    pub fn store_plaintext(mut self, key: OutputKey) -> Self {
        self.plaintext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn plaintext(&self) -> OutputKey {
        self.plaintext.output_key()
    }
}

impl SourceInfo for AeadDecrypt {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl ProcedureStep for AeadDecrypt {
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
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let tag = match tag {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut ptx = vec![0; ciphertext.len()];

        let alg = self.alg;
        let f = |key: GuardedVec<u8>| {
            let f = match alg {
                AeadAlg::Aes256Gcm => Aes256Gcm::try_decrypt,
                AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::try_decrypt,
            };
            f(&*key.borrow(), nonce, ad, &mut ptx, ciphertext, tag)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(plaintext.write_to, ptx.into_procedure_io(), plaintext.is_temp);
        Ok(())
    }
}
