use crate::state::old_snapshot;
use crate::state::snapshot;
use std::convert::TryInto;

use riker::actors::*;

use crate::{line_error, utils::LoadFromPath, Location, RecordHint, Stronghold};

use engine::vault::{ClientId, VaultId};

fn stronghold_password<P: Into<String>>(password: P) -> Vec<u8> {
    let mut password = password.into();
    let mut dk = [0; 64];
    // safe to unwrap because rounds > 0
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password.as_bytes(), b"wallet.rs", 100, &mut dk).unwrap();

    let password: [u8; 32] = dk[0..32][..].try_into().unwrap();
    password.to_vec()
}
/// Location::generic("iota-wallet-secret", "iota-wallet-seed")
/// password: helloiota2491

fn setup_stronghold() -> Stronghold {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();

    Stronghold::init_stronghold_system(sys, client_path, vec![])
}

#[test]
fn test_snapshot_migration() {
    let pass = "helloiota2491";

    let pass = stronghold_password(pass);

    let mut stronghold = setup_stronghold();

    futures::executor::block_on(stronghold.read_snapshot(b"test".to_vec(), None, &pass, Some("old".into()), None));

    stronghold.system.print_tree();
}
