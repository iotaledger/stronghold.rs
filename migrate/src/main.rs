use std::path::Path;
use engine::snapshot::migration::{migrate, Version};

fn main() {
    let mut key = [0_u8; 32];
    let password = b"migration-test";
    let salt = b"wallet.rs";
    let iter = 100_usize;
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password, salt, iter, &mut key).unwrap();

    let v2 = Version::v2(Path::new("../stardust-cli-wallet.stronghold"), &key, &[]);
    let v3 = Version::v3(Path::new("../stardust-cli-wallet-v3.stronghold"), b"migration-test");
    println!("migrating: {:?}", migrate(v2, v3));
}
