// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use super::types::*;
use crate::{derive_record_id, derive_vault_id, Client, ClientError, Location};
pub use crypto::keys::slip10::{Chain, ChainCode};
use crypto::{
    ciphers::{
        aes::Aes256Gcm,
        aes_kw::Aes256Kw,
        chacha::XChaCha20Poly1305,
        traits::{Aead, Tag},
    },
    hashes::{
        sha::{Sha256, Sha384, Sha512, SHA256_LEN, SHA384_LEN, SHA512_LEN},
        Digest,
    },
    keys::{
        bip39,
        pbkdf::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512},
        slip10, x25519,
    },
    macs::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512},
    signatures::ed25519,
    utils::rand::fill,
};

use engine::runtime::memories::buffer::{Buffer, Ref};
use serde::{Deserialize, Serialize};
use stronghold_utils::GuardDebug;

/// Enum that wraps all cryptographic procedures that are supported by Stronghold.
///
/// A procedure performs a (cryptographic) operation on a secret in the vault and/
/// or generates a new secret.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum StrongholdProcedure {
    WriteVault(WriteVault),
    RevokeData(RevokeData),
    GarbageCollect(GarbageCollect),
    CopyRecord(CopyRecord),
    Slip10Generate(Slip10Generate),
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),
    BIP39Recover(BIP39Recover),
    PublicKey(PublicKey),
    GenerateKey(GenerateKey),
    Ed25519Sign(Ed25519Sign),
    X25519DiffieHellman(X25519DiffieHellman),
    Hmac(Hmac),
    Hkdf(Hkdf),
    ConcatKdf(ConcatKdf),
    AesKeyWrapEncrypt(AesKeyWrapEncrypt),
    AesKeyWrapDecrypt(AesKeyWrapDecrypt),
    Pbkdf2Hmac(Pbkdf2Hmac),
    AeadEncrypt(AeadEncrypt),
    AeadDecrypt(AeadDecrypt),
}

impl Procedure for StrongholdProcedure {
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        use StrongholdProcedure::*;
        match self {
            WriteVault(proc) => proc.execute(runner).map(|o| o.into()),
            RevokeData(proc) => proc.execute(runner).map(|o| o.into()),
            GarbageCollect(proc) => proc.execute(runner).map(|o| o.into()),
            CopyRecord(proc) => proc.execute(runner).map(|o| o.into()),
            Slip10Generate(proc) => proc.execute(runner).map(|o| o.into()),
            Slip10Derive(proc) => proc.execute(runner).map(|o| o.into()),
            BIP39Generate(proc) => proc.execute(runner).map(|o| o.into()),
            BIP39Recover(proc) => proc.execute(runner).map(|o| o.into()),
            GenerateKey(proc) => proc.execute(runner).map(|o| o.into()),
            PublicKey(proc) => proc.execute(runner).map(|o| o.into()),
            Ed25519Sign(proc) => proc.execute(runner).map(|o| o.into()),
            X25519DiffieHellman(proc) => proc.execute(runner).map(|o| o.into()),
            Hmac(proc) => proc.execute(runner).map(|o| o.into()),
            Hkdf(proc) => proc.execute(runner).map(|o| o.into()),
            ConcatKdf(proc) => proc.execute(runner).map(|o| o.into()),
            AesKeyWrapEncrypt(proc) => proc.execute(runner).map(|o| o.into()),
            AesKeyWrapDecrypt(proc) => proc.execute(runner).map(|o| o.into()),
            Pbkdf2Hmac(proc) => proc.execute(runner).map(|o| o.into()),
            AeadEncrypt(proc) => proc.execute(runner).map(|o| o.into()),
            AeadDecrypt(proc) => proc.execute(runner).map(|o| o.into()),
        }
    }
}

impl StrongholdProcedure {
    pub(crate) fn input(&self) -> Option<Location> {
        match self {
            StrongholdProcedure::CopyRecord(CopyRecord { source: input, .. })
            | StrongholdProcedure::Slip10Derive(Slip10Derive {
                input: Slip10DeriveInput::Seed(input),
                ..
            })
            | StrongholdProcedure::Slip10Derive(Slip10Derive {
                input: Slip10DeriveInput::Key(input),
                ..
            })
            | StrongholdProcedure::PublicKey(PublicKey { private_key: input, .. })
            | StrongholdProcedure::Ed25519Sign(Ed25519Sign { private_key: input, .. })
            | StrongholdProcedure::X25519DiffieHellman(X25519DiffieHellman { private_key: input, .. })
            | StrongholdProcedure::Hkdf(Hkdf { ikm: input, .. })
            | StrongholdProcedure::ConcatKdf(ConcatKdf {
                shared_secret: input, ..
            })
            | StrongholdProcedure::Hmac(Hmac { key: input, .. })
            | StrongholdProcedure::AeadEncrypt(AeadEncrypt { key: input, .. })
            | StrongholdProcedure::AeadDecrypt(AeadDecrypt { key: input, .. }) => Some(input.clone()),
            _ => None,
        }
    }
    pub(crate) fn output(&self) -> Option<Location> {
        match self {
            StrongholdProcedure::WriteVault(WriteVault { location: output, .. })
            | StrongholdProcedure::CopyRecord(CopyRecord { target: output, .. })
            | StrongholdProcedure::Slip10Generate(Slip10Generate { output, .. })
            | StrongholdProcedure::Slip10Derive(Slip10Derive { output, .. })
            | StrongholdProcedure::BIP39Generate(BIP39Generate { output, .. })
            | StrongholdProcedure::BIP39Recover(BIP39Recover { output, .. })
            | StrongholdProcedure::GenerateKey(GenerateKey { output, .. })
            | StrongholdProcedure::X25519DiffieHellman(X25519DiffieHellman { shared_key: output, .. })
            | StrongholdProcedure::Hkdf(Hkdf { okm: output, .. })
            | StrongholdProcedure::ConcatKdf(ConcatKdf { output, .. })
            | StrongholdProcedure::Pbkdf2Hmac(Pbkdf2Hmac { output, .. }) => Some(output.clone()),
            _ => None,
        }
    }
}

/// Implement StrongholdProcedure: From<T> for all.
/// Implement [`Procedure`] if `$Trait:ident` != `_`.
#[macro_export]
macro_rules! procedures {
    { _ => { $($Proc:ident),+ }} => {
        $(
            impl From<$Proc> for StrongholdProcedure {
                fn from(proc: $Proc) -> Self {
                    StrongholdProcedure::$Proc(proc)
                }
            }
        )+
    };
    { $Trait:ident => { $($Proc:ident),+ }} => {
        $(
            impl Procedure for $Proc {
                type Output = <$Proc as $Trait>::Output;

                fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
                    self.exec(runner)
                }
            }
        )+
        procedures!(_ => { $($Proc),+ });
    };
    { $($Trait:tt => { $($Proc:ident),+ }),+} => {
        $(
            procedures!($Trait => { $($Proc),+ } );
        )+
    };
}

#[macro_export]
macro_rules! generic_procedures {
    { $Trait:ident<$n:literal> => { $($Proc:ident),+ }} => {
        $(
            impl Procedure for $Proc {
                type Output = <$Proc as $Trait<$n>>::Output;

                fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
                    self.exec(runner)
                }
            }
        )+
        procedures!(_ => { $($Proc),+ });
    };
    { $($Trait:tt<$n:literal> => { $($Proc:ident),+ }),+} => {
        $(
            generic_procedures!($Trait<$n> => { $($Proc),+ } );
        )+
    };
}

generic_procedures! {
    // Stronghold procedures that implement the `UseSecret` trait.
    UseSecret<1> => { PublicKey, Ed25519Sign, Hmac, AeadEncrypt, AeadDecrypt },
    UseSecret<2> => { AesKeyWrapEncrypt },
    // Stronghold procedures that implement the `DeriveSecret` trait.
    DeriveSecret<1> => { CopyRecord, Slip10Derive, X25519DiffieHellman, Hkdf, ConcatKdf, AesKeyWrapDecrypt }
}

procedures! {
    // Stronghold procedures that implement the `GenerateSecret` trait.
    GenerateSecret => { WriteVault, BIP39Generate, BIP39Recover, Slip10Generate, GenerateKey, Pbkdf2Hmac },
    // Stronghold procedures that directly implement the `Procedure` trait.
    _ => { RevokeData, GarbageCollect }
}

/// Write data to the specified [`Location`].
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct WriteVault {
    pub data: Vec<u8>,
    pub location: Location,
}

impl GenerateSecret for WriteVault {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        Ok(Products {
            secret: self.data,
            output: (),
        })
    }

    fn target(&self) -> &Location {
        &self.location
    }
}

/// Revoke the data from the specified [`Location`]. Revoked data is not readable and can be
/// removed from a vault with the [`GarbageCollect`] Procedure. If the `should_gc` flag is set to `true`,
/// it with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeData {
    pub location: Location,
    pub should_gc: bool,
}

impl Procedure for RevokeData {
    type Output = ();
    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        runner.revoke_data(&self.location)?;
        if self.should_gc {
            runner.garbage_collect(self.location.resolve().0);
        }
        Ok(())
    }
}

/// Garbage collects any revokes in a Vault based on the given `vault_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageCollect {
    pub vault_path: Vec<u8>,
}

impl Procedure for GarbageCollect {
    type Output = ();

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        let vault_id = derive_vault_id(self.vault_path);
        runner.garbage_collect(vault_id);
        Ok(())
    }
}

/// Copy the content of a record from one location to another.
///
/// Note: This does not remove the old record. Users that would like to move the record instead
/// of just copying it, should run the `RevokeData` procedure on the old location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyRecord {
    pub source: Location,
    pub target: Location,
}

impl DeriveSecret<1> for CopyRecord {
    type Output = ();

    fn derive(self, guards: [Buffer<u8>; 1]) -> Result<Products<()>, FatalProcedureError> {
        let products = Products {
            secret: (*guards[0].borrow()).to_vec(),
            output: (),
        };
        Ok(products)
    }

    fn source(&self) -> [Location; 1] {
        [self.source.clone()]
    }

    fn target(&self) -> &Location {
        &self.target
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AeadCipher {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sha2Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for MnemonicLanguage {
    type Err = ClientError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let converted = s.to_lowercase();
        match converted.as_str() {
            "english" => Ok(Self::English),
            "japanese" => Ok(Self::Japanese),
            _ => Err(ClientError::Inner("Illegal string provided".to_string())),
        }
    }
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase). Store the seed and return the mnemonic sentence as data output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    pub passphrase: Option<String>,
    pub language: MnemonicLanguage,
    pub output: Location,
}

impl GenerateSecret for BIP39Generate {
    type Output = String;

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
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

    fn target(&self) -> &Location {
        &self.output
    }
}

/// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
/// a BIP39 seed and store it in the `output` location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Recover {
    pub passphrase: Option<String>,
    pub mnemonic: String,
    pub output: Location,
}

impl GenerateSecret for BIP39Recover {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&self.mnemonic, &passphrase, &mut seed);
        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Generate {
    pub size_bytes: Option<usize>,

    pub output: Location,
}

impl GenerateSecret for Slip10Generate {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let size_bytes = self.size_bytes.unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        Ok(Products {
            secret: seed,
            output: (),
        })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum Slip10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    pub chain: Chain,

    pub input: Slip10DeriveInput,

    pub output: Location,
}

impl DeriveSecret<1> for Slip10Derive {
    type Output = ChainCode;

    fn derive(self, guards: [Buffer<u8>; 1]) -> Result<Products<ChainCode>, FatalProcedureError> {
        let dk = match self.input {
            Slip10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guards[0].borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            Slip10DeriveInput::Seed(_) => {
                slip10::Seed::from_bytes(&guards[0].borrow()).derive(slip10::Curve::Ed25519, &self.chain)
            }
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }

    fn source(&self) -> [Location; 1] {
        match &self.input {
            Slip10DeriveInput::Key(loc) => [loc.clone()],
            Slip10DeriveInput::Seed(loc) => [loc.clone()],
        }
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

fn x25519_secret_key(raw: Ref<u8>) -> Result<x25519::SecretKey, crypto::Error> {
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

fn ed25519_secret_key(raw: Ref<u8>) -> Result<ed25519::SecretKey, crypto::Error> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKey {
    pub ty: KeyType,
    pub output: Location,
}

impl GenerateSecret for GenerateKey {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.ty {
            KeyType::Ed25519 => ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
            KeyType::X25519 => x25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
        };
        Ok(Products { secret, output: () })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub ty: KeyType,

    pub private_key: Location,
}

impl UseSecret<1> for PublicKey {
    type Output = [u8; 32];

    fn use_secret(self, guards: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            KeyType::Ed25519 => {
                let sk = ed25519_secret_key(guards[0].borrow())?;
                Ok(sk.public_key().to_bytes())
            }
            KeyType::X25519 => {
                let sk = x25519_secret_key(guards[0].borrow())?;
                Ok(sk.public_key().to_bytes())
            }
        }
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    pub msg: Vec<u8>,

    pub private_key: Location,
}

impl UseSecret<1> for Ed25519Sign {
    type Output = [u8; ed25519::SIGNATURE_LENGTH];

    fn use_secret(self, guards: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = ed25519_secret_key(guards[0].borrow())?;
        let sig = sk.sign(&self.msg);
        Ok(sig.to_bytes())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519DiffieHellman {
    pub public_key: [u8; x25519::PUBLIC_KEY_LENGTH],

    pub private_key: Location,

    pub shared_key: Location,
}

impl DeriveSecret<1> for X25519DiffieHellman {
    type Output = ();

    fn derive(self, guards: [Buffer<u8>; 1]) -> Result<Products<()>, FatalProcedureError> {
        let sk = x25519_secret_key(guards[0].borrow())?;
        let public = x25519::PublicKey::from_bytes(self.public_key);
        let shared_key = sk.diffie_hellman(&public);

        Ok(Products {
            secret: shared_key.to_bytes().to_vec(),
            output: (),
        })
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }

    fn target(&self) -> &Location {
        &self.shared_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hmac {
    pub hash_type: Sha2Hash,

    pub msg: Vec<u8>,

    pub key: Location,
}

impl UseSecret<1> for Hmac {
    type Output = Vec<u8>;

    fn use_secret(self, guards: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        match self.hash_type {
            Sha2Hash::Sha256 => {
                let mut mac = [0; SHA256_LEN];
                HMAC_SHA256(&self.msg, &*guards[0].borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha384 => {
                let mut mac = [0; SHA384_LEN];
                HMAC_SHA384(&self.msg, &*guards[0].borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha512 => {
                let mut mac = [0; SHA512_LEN];
                HMAC_SHA512(&self.msg, &*guards[0].borrow(), &mut mac);
                Ok(mac.to_vec())
            }
        }
    }

    fn source(&self) -> [Location; 1] {
        [self.key.clone()]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hkdf {
    pub hash_type: Sha2Hash,
    pub salt: Vec<u8>,
    pub label: Vec<u8>,
    pub ikm: Location,
    pub okm: Location,
}

impl DeriveSecret<1> for Hkdf {
    type Output = ();

    fn derive(self, guards: [Buffer<u8>; 1]) -> Result<Products<()>, FatalProcedureError> {
        let secret = match self.hash_type {
            Sha2Hash::Sha256 => {
                let mut okm = [0; SHA256_LEN];
                hkdf::Hkdf::<Sha256>::new(Some(&self.salt), &*guards[0].borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut okm = [0; SHA384_LEN];
                hkdf::Hkdf::<Sha384>::new(Some(&self.salt), &*guards[0].borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut okm = [0; SHA512_LEN];
                hkdf::Hkdf::<Sha512>::new(Some(&self.salt), &*guards[0].borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
        };
        Ok(Products { secret, output: () })
    }

    fn source(&self) -> [Location; 1] {
        [self.ikm.clone()]
    }

    fn target(&self) -> &Location {
        &self.okm
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Hmac {
    pub hash_type: Sha2Hash,

    pub password: Vec<u8>,

    pub salt: Vec<u8>,

    pub count: u32,

    pub output: Location,
}

impl GenerateSecret for Pbkdf2Hmac {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.hash_type {
            Sha2Hash::Sha256 => {
                let mut buffer = [0; SHA256_LEN];
                PBKDF2_HMAC_SHA256(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut buffer = [0; SHA384_LEN];
                PBKDF2_HMAC_SHA384(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut buffer = [0; SHA512_LEN];
                PBKDF2_HMAC_SHA512(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
        };
        Ok(Products { secret, output: () })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEncrypt {
    pub cipher: AeadCipher,

    pub associated_data: Vec<u8>,

    pub plaintext: Vec<u8>,

    /// **Note**: The nonce is required to have length [`Aes256Gcm::NONCE_LENGTH`] /
    /// [`XChaCha20Poly1305::NONCE_LENGTH`], (depending on the [`AeadCipher`])
    pub nonce: Vec<u8>,

    pub key: Location,
}

impl UseSecret<1> for AeadEncrypt {
    type Output = Vec<u8>;

    fn use_secret(self, guards: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let mut ctx = vec![0; self.plaintext.len()];

        let f = match self.cipher {
            AeadCipher::Aes256Gcm => Aes256Gcm::try_encrypt,
            AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_encrypt,
        };
        let mut t = match self.cipher {
            AeadCipher::Aes256Gcm => Tag::<Aes256Gcm>::default(),
            AeadCipher::XChaCha20Poly1305 => Tag::<XChaCha20Poly1305>::default(),
        };
        f(
            &*guards[0].borrow(),
            &self.nonce,
            &self.associated_data,
            &self.plaintext,
            &mut ctx,
            &mut t,
        )?;
        let mut output = Vec::with_capacity(t.len() + ctx.len());
        output.extend(t);
        output.extend(ctx);
        Ok(output)
    }

    fn source(&self) -> [Location; 1] {
        [self.key.clone()]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadDecrypt {
    pub cipher: AeadCipher,

    pub associated_data: Vec<u8>,

    pub ciphertext: Vec<u8>,

    pub tag: Vec<u8>,

    pub nonce: Vec<u8>,

    pub key: Location,
}

impl UseSecret<1> for AeadDecrypt {
    type Output = Vec<u8>;

    fn use_secret(self, guards: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let mut ptx = vec![0; self.ciphertext.len()];

        let f = match self.cipher {
            AeadCipher::Aes256Gcm => Aes256Gcm::try_decrypt,
            AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_decrypt,
        };
        f(
            &*guards[0].borrow(),
            &self.nonce,
            &self.associated_data,
            &mut ptx,
            &self.ciphertext,
            &self.tag,
        )?;
        Ok(ptx)
    }

    fn source(&self) -> [Location; 1] {
        [self.key.clone()]
    }
}

/// Executes the concat KDF as defined in Section 5.8.1 of NIST.800-56A.
///
/// This derives key material from an existing shared secret (e.g. generated through ECDH)
/// and additional fixed inputs, such as identifiers of the involved parties (e.g. "Alice")
/// and algorithms (e.g. "A128GCM").
/// The provided hash function is applied to those inputs in a loop,
/// until enough key material was produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcatKdf {
    /// The hash function to use in the kdf.
    pub hash: Sha2Hash,
    /// The identifier of the used algorithm, e.g. `ECDH-ES+A256KW`.
    pub algorithm_id: String,
    /// The location of the shared secret `z`.
    pub shared_secret: Location,
    /// The number of bytes of key material that should be derived.
    pub key_len: usize,
    /// Agreement PartyUInfo.
    pub apu: Vec<u8>,
    /// Agreement PartyVInfo.
    pub apv: Vec<u8>,
    /// SuppPubInfo.
    pub pub_info: Vec<u8>,
    /// SuppPrivInfo.
    pub priv_info: Vec<u8>,
    /// The location to write the derived key material into.
    pub output: Location,
}

impl DeriveSecret<1> for ConcatKdf {
    type Output = ();

    fn derive(self, guards: [Buffer<u8>; 1]) -> Result<Products<()>, FatalProcedureError> {
        let derived_key_material: Vec<u8> = match self.hash {
            Sha2Hash::Sha256 => self.concat_kdf::<Sha256>(guards[0].borrow().as_ref()),
            Sha2Hash::Sha384 => self.concat_kdf::<Sha384>(guards[0].borrow().as_ref()),
            Sha2Hash::Sha512 => self.concat_kdf::<Sha512>(guards[0].borrow().as_ref()),
        }?;

        Ok(Products {
            secret: derived_key_material,
            output: (),
        })
    }

    fn source(&self) -> [Location; 1] {
        [self.shared_secret.clone()]
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

impl ConcatKdf {
    /// The Concat KDF as defined in Section 5.8.1 of NIST.800-56A.
    fn concat_kdf<D: Digest>(&self, z: &[u8]) -> Result<Vec<u8>, FatalProcedureError> {
        let mut digest: D = D::new();
        let alg: &str = self.algorithm_id.as_ref();
        let len: usize = self.key_len;
        let apu: &[u8] = self.apu.as_ref();
        let apv: &[u8] = self.apv.as_ref();
        let pub_info: &[u8] = self.pub_info.as_ref();
        let prv_info: &[u8] = self.priv_info.as_ref();

        let mut output: Vec<u8> = Vec::new();

        let target: usize = (len + (D::output_size() - 1)) / D::output_size();
        let rounds: u32 =
            u32::try_from(target).map_err(|_| FatalProcedureError::from("u32 iteration overflow".to_owned()))?;

        for count in 0..rounds {
            // Iteration Count
            digest.update(&(count as u32 + 1).to_be_bytes());

            // Derived Secret
            digest.update(z);

            // AlgorithmId
            digest.update(&(alg.len() as u32).to_be_bytes());
            digest.update(alg.as_bytes());

            // PartyUInfo
            digest.update(&(apu.len() as u32).to_be_bytes());
            digest.update(apu);

            // PartyVInfo
            digest.update(&(apv.len() as u32).to_be_bytes());
            digest.update(apv);

            // SuppPubInfo
            digest.update(pub_info);

            // SuppPrivInfo
            digest.update(prv_info);

            output.extend_from_slice(&digest.finalize_reset());
        }

        output.truncate(len);

        Ok(output)
    }
}

/// The available ciphers for AES key wrapping.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AesKeyWrapCipher {
    Aes256,
}

/// Encrypts a key in a vault using another key, and returns the ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesKeyWrapEncrypt {
    /// The cipher to use for encryption.
    pub cipher: AesKeyWrapCipher,
    /// The key to use for encryption of the `wrap_key`.
    pub encryption_key: Location,
    /// The key to wrap.
    pub wrap_key: Location,
}

impl UseSecret<2> for AesKeyWrapEncrypt {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 2]) -> Result<Self::Output, FatalProcedureError> {
        self.wrap_key(guard[0].borrow().as_ref(), guard[1].borrow().as_ref())
    }

    fn source(&self) -> [Location; 2] {
        [self.encryption_key.clone(), self.wrap_key.clone()]
    }
}

impl AesKeyWrapEncrypt {
    fn wrap_key(&self, encryption_key: &[u8], wrap_key: &[u8]) -> Result<Vec<u8>, FatalProcedureError> {
        // This uses Aes256Kw unconditionally, since AesKeyWrapCipher has just one variant.
        // The enum was added for future proofing so support for other variants can be added non-breakingly.
        let mut ciphertext: Vec<u8> = vec![0; wrap_key.len() + Aes256Kw::BLOCK];

        let wrap: Aes256Kw = Aes256Kw::new(encryption_key);
        wrap.wrap_key(wrap_key, &mut ciphertext)?;

        Ok(ciphertext)
    }
}

/// Decrypts a provided wrapped key using a decryption key, and writes the result into an output location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesKeyWrapDecrypt {
    /// The cipher to use for decryption.
    pub cipher: AesKeyWrapCipher,
    /// The key to use for decryption of the `wrapped_key`.
    pub decryption_key: Location,
    /// The ciphertext of the key to unwrap.
    pub wrapped_key: Vec<u8>,
    /// The location into which to write the decrypted key.
    pub output: Location,
}

impl DeriveSecret<1> for AesKeyWrapDecrypt {
    type Output = ();

    fn derive(self, guard: [Buffer<u8>; 1]) -> Result<Products<Self::Output>, FatalProcedureError> {
        let plaintext: Vec<u8> = self.unwrap_key(guard[0].borrow().as_ref())?;
        Ok(Products {
            secret: plaintext,
            output: (),
        })
    }

    fn source(&self) -> [Location; 1] {
        [self.decryption_key.clone()]
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

impl AesKeyWrapDecrypt {
    fn unwrap_key(&self, decryption_key: &[u8]) -> Result<Vec<u8>, FatalProcedureError> {
        // This uses Aes256Kw unconditionally, since AesKeyWrapCipher has just one variant.
        // The enum was added for future proofing so support for other variants can be added non-breakingly.
        let plaintext_len: usize = self.wrapped_key.len().checked_sub(Aes256Kw::BLOCK).ok_or_else(|| {
            FatalProcedureError::from(format!(
                "ciphertext needs to have a length >= than the block size: {}",
                Aes256Kw::BLOCK
            ))
        })?;
        let mut plaintext: Vec<u8> = vec![0; plaintext_len];

        let wrap: Aes256Kw = Aes256Kw::new(decryption_key);
        wrap.unwrap_key(self.wrapped_key.as_ref(), &mut plaintext)?;

        Ok(plaintext)
    }
}
