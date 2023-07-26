/// Reads the seed from a v2 snapshot by migrating it first to a v3 snapshot and prints it to stdout
/// Run with `cargo run --example get_secret_v2 --release --features=insecure`
use iota_stronghold::{procedures::GetSecret, KeyProvider, Location, SnapshotPath, Stronghold};

const STRONGHOLD_PASSWORD: &str = "STRONGHOLD_PASSWORD";
const STRONGHOLD_SNAPSHOT_PATH: &str = "examples/example_v2.stronghold";
const STRONGHOLD_SNAPSHOT_PATH_MIGRATED: &str = "examples/example_v2_v3.stronghold";

fn main() {
    migrate_snapshot_v2_to_v3(
        STRONGHOLD_SNAPSHOT_PATH,
        STRONGHOLD_PASSWORD,
        "wallet.rs",
        100,
        STRONGHOLD_SNAPSHOT_PATH_MIGRATED,
    );

    let key_provider = key_provider_from_password(STRONGHOLD_PASSWORD);
    let snapshot_path = SnapshotPath::from_path(STRONGHOLD_SNAPSHOT_PATH_MIGRATED);

    let client = Stronghold::default()
        .load_client_from_snapshot(PRIVATE_DATA_CLIENT_PATH, &key_provider, &snapshot_path)
        .unwrap();

    let seed_location = Location::generic(SECRET_VAULT_PATH, SEED_RECORD_PATH);

    let seed_bytes = client
        .execute_procedure(GetSecret {
            location: seed_location,
        })
        .unwrap();

    let hex_encoded_seed = seed_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("");

    println!("Seed: 0x{hex_encoded_seed}",);

    // example.stronghold was created with mnemonic: "enable flame always iron aim goose churn charge flower year inch
    // try amazing display dash eye power degree vote ghost sleep boat drink cart", so the expected seed should be:
    assert_eq!(hex_encoded_seed, "a759e4c7422f20e6f58ff962169267c9960a53a60df2a8d1ede771c91a093522d964909e77f1326b218f17dee10bfd3a118ac67a38fa4d9e916ab75691924a9e");
}

// Used historically in iota.rs/wallet.rs/iota-sdk
const SECRET_VAULT_PATH: &[u8] = b"iota-wallet-secret";
const SEED_RECORD_PATH: &[u8] = b"iota-wallet-seed";
const PRIVATE_DATA_CLIENT_PATH: &[u8] = b"iota_seed";

/// Hash a password, deriving a key, for accessing Stronghold.
pub fn key_provider_from_password(password: &str) -> KeyProvider {
    // PANIC: the hashed password length is guaranteed to be 32.
    KeyProvider::with_passphrase_hashed_blake2b(password.as_bytes().to_vec()).unwrap()
}

use std::{
    ffi::OsStr,
    num::NonZeroU32,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;
/// Migrates a snapshot from version 2 to version 3.
pub fn migrate_snapshot_v2_to_v3<P: AsRef<Path>>(
    current_path: P,
    current_password: &str,
    salt: impl AsRef<str>,
    rounds: u32,
    new_path: P,
) {
    use iota_stronghold::engine::snapshot::migration::{migrate, Version};

    let mut buffer = [0u8; 32];
    let mut tmp_path = current_path.as_ref().as_os_str().to_os_string();
    tmp_path.push(OsStr::new("-tmp"));
    let tmp_path = PathBuf::from(tmp_path);

    if tmp_path.exists() {
        panic!("PathAlreadyExists: {}", tmp_path.display());
    }

    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(
        current_password.as_bytes(),
        salt.as_ref().as_bytes(),
        NonZeroU32::try_from(rounds).unwrap(),
        buffer.as_mut(),
    );

    let current_version = Version::V2 {
        path: current_path.as_ref(),
        key: &buffer,
        aad: &[],
    };

    let new_version = Version::V3 {
        path: &tmp_path,
        password: current_password.as_bytes(),
    };

    migrate(current_version, new_version).unwrap();

    std::fs::rename(tmp_path, new_path.as_ref()).unwrap();

    buffer.zeroize();
}
