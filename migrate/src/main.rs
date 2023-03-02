use std::path::Path;
use engine::snapshot::migration::{migrate, Version};

fn main() {
    let v2 = Version::v2wallet(Path::new("../stardust-cli-wallet.stronghold"), "migration-test".as_bytes(), &[]);
    let v3 = Version::v3(Path::new("../stardust-cli-wallet-v3.stronghold"), "migration-test".as_bytes());
    println!("migrating: {:?}", migrate(v2, v3));
}
