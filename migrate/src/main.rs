use std::path::Path;
use engine::snapshot::migration::{migrate, Version};

fn main() {
    let prev = Version::V2wallet {
        path: Path::new("../stardust-cli-wallet.stronghold"),
        password: "migration-test".as_bytes(),
        aad: &[],
    };
    let next = Version::V3 {
        path: Path::new("../stardust-cli-wallet-v3.stronghold"),
        password: "migration-test".as_bytes(),
        aad: &[],
    };
    println!("migrating: {:?}", migrate(prev, next));
}
