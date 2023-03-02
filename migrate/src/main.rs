use std::path::Path;
use engine::snapshot::migration::{migrate, Version};

fn main() {
    let v2 = Version::v2wallet(Path::new("../stardust-cli-wallet.stronghold"), b"migration-test", &[]);
    let v3 = Version::v3(Path::new("../stardust-cli-wallet-v3.stronghold"), b"migration-test");
    println!("migrating: {:?}", migrate(v2, v3));
}
