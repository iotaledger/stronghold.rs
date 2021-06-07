use iota::Multiaddr;
// #![no_main]
use iota_stronghold as iota;
use libfuzzer_sys::fuzz_target;
use std::{error::Error, str::FromStr};

fuzz_target!(|data: &[u8]| {
    // add fuzz targets
});

/// Callback type for blocking stronghold instance
type Callback = fn() -> Result<(), Box<dyn Error>>;

fn main() {
    let system = iota::ActorSystem::new().unwrap();
    let options = vec![];
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // fuzz target?
    let client_path = b"client_path".to_vec();

    let mut stronghold = iota::Stronghold::init_stronghold_system(system, client_path, options);

    // communications fuzzing
    stronghold.spawn_communication();

    runtime.block_on(async {
        stronghold
            .start_listening(Some(Multiaddr::from_str("/ip4/0.0.0.0/tcp/7001").unwrap()))
            .await;
        stronghold.get_swarm_info().await;
    });

    // block execution
    stronghold.keep_alive(None::<Callback>);
}
