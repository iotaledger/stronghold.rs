use threadpool::ThreadPool;
use iota_stronghold::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure, PublicKey, Sha2Hash, Hmac},
    KeyProvider, Location, SnapshotPath, Stronghold,
};


use crypto::{macs::hmac::HMAC_SHA256, hashes::sha::SHA256_LEN};
use std::error::Error;
use std::sync::mpsc::channel;


const NB_THREADS: usize = 1;

// Test to make sure that multithreaded stronghold does not crash
#[test]
fn test_stronghold_multithreaded_safety() {
    const NB_CLIENTS: usize = 5;
    const NB_INPUTS: usize = 10;

    let main_stronghold = Stronghold::default();
    let pool = ThreadPool::new(NB_THREADS);

    for i in 0..NB_CLIENTS {
        let stronghold = main_stronghold.clone();
        pool.execute(move || {
            let path = format!("client_path{}", i);
            stronghold.create_client(&path).unwrap();
            stronghold.write_client(&path).unwrap();
            for _ in 0..NB_INPUTS {
                let cl = stronghold.load_client(&path).unwrap();
                cl.store().insert(b"test".to_vec(), b"value".to_vec(), None).unwrap();
            }
            stronghold.write_client(&path).unwrap();
        });
    }
    pool.join();

    for i in 0..NB_CLIENTS {
        let path = format!("client_path{}", i);
        let cl = main_stronghold.load_client(path).unwrap();
        let value = cl.store().get(b"test").unwrap().unwrap();
        assert_eq!(value, b"value");
    }
}


// Test to check that multithreaded Stronghold function correctly
#[test]
fn test_stronghold_multithreaded_correctness() {
    const NB_INPUTS: usize = 50;

    let client_path = b"client_path".to_vec();

    let main_stronghold = Stronghold::default();
    let pool = ThreadPool::new(NB_THREADS);
    main_stronghold.create_client(&client_path).unwrap();
    main_stronghold.write_client(&client_path).unwrap();

    for i in 0..NB_INPUTS {
        let stronghold = main_stronghold.clone();
        let path = client_path.clone();
        pool.execute(move || {
            let cl = stronghold.get_client(&path).unwrap();
            // println!("before {}: {:?}", i, cl.store.keys().unwrap());
            let key = format!("{}", i).into_bytes();
            let value = format!("value{}", i).into_bytes();
            cl.store().insert(key, value, None).unwrap();
            // println!("insert {}: {:?}", i, cl.store.keys().unwrap());
            stronghold.write_client(&path).unwrap();
            // println!("commit {}: {:?}", i, cl.store.keys().unwrap());
        });
    }
    pool.join();

    let cl = main_stronghold.load_client(client_path).unwrap();
    // println!("{:?}", cl.store.keys());
    for i in 0..NB_INPUTS {
        let key = format!("{}", i).into_bytes();
        let expected_value = format!("value{}", i).into_bytes();
        let v = cl.store().get(&key).unwrap();
        assert_eq!(v, Some(expected_value));
    }
}

#[test]
fn test_full_stronghold_access_multithreaded() {
    const NB_INPUTS: usize = 50;
    let pool = ThreadPool::new(NB_THREADS);

    let stronghold = Stronghold::default();
    let snapshot_path: SnapshotPath = SnapshotPath::named("testing-snapshot.snapshot");
    let key = b"abcdefghijklmnopqrstuvwxyz123456".to_vec();
    let vault_path = format!("vault_path").into_bytes();
    let client_path = format!("client_path").into_bytes();


    for i in 0..NB_INPUTS {
        let key_provider = KeyProvider::try_from(key.clone()).map_err(|e| format!("Error {:?}", e)).unwrap();
        let stg = stronghold.clone();
        let spath = snapshot_path.clone();
        let cpath = client_path.clone();
        let vpath = vault_path.clone();
        let rpath = format!("record_path{}", i).into_bytes();
        let store_key = format!("key{}", i).into_bytes();
        let store_val = format!("value{}", i).into_bytes();
        pool.execute(move || {
            let res = test_full_stronghold_access(stg, spath, cpath, vpath, rpath, key_provider, (store_key, store_val));
            println!("{:?}", res);
            assert!(res.is_ok());
        });
    }

    let key_provider = KeyProvider::try_from(key.clone()).map_err(|e| format!("Error {:?}", e)).unwrap();
    let client = stronghold.load_client_from_snapshot(client_path, &key_provider, &snapshot_path).unwrap();


    // Verify the content of the vault for each input
    for i in 0..NB_INPUTS {
        let msg = format!("msg").into_bytes();
        let secret = format!("secret{}", i).into_bytes();
        let rpath = format!("record_path{}", i).into_bytes();
        let loc = crate::Location::generic(vault_path.clone(), rpath);
        let pk = Hmac {
            hash_type: Sha2Hash::Sha256,
            msg: msg.clone(),
            key: loc
        };

        // Check store content
        let store_key = format!("key{}", i).into_bytes();
        let expected_store_v = format!("value{}", i).into_bytes();
        let store_v = client.store().get(&store_key).unwrap();
        println!("{:?}", i);
        assert_eq!(store_v, Some(expected_store_v));


        // // Check vault content
        // // Generate a mac from secret in vault
        // let proc = StrongholdProcedure::Hmac(pk);
        // let procedure_result = client.clone().execute_procedure(proc);
        // println!("{:?}", procedure_result);
        // assert!(procedure_result.is_ok());
        // let vault_mac: Vec<u8> = procedure_result.unwrap().into();

        // // Generate mac manually
        // let mut expected_mac = [0; SHA256_LEN];
        // HMAC_SHA256(&msg, &secret, &mut expected_mac);
        // assert_eq!(vault_mac, expected_mac);
    }
}

fn test_full_stronghold_access(stronghold: Stronghold, snapshot_path: SnapshotPath, client_path: Vec<u8>, vault_path: Vec<u8>, record_path: Vec<u8>, key_provider: KeyProvider, store_kv: (Vec<u8>, Vec<u8>)) -> Result<Vec<u8>, Box<dyn Error>> {

    // create a new empty client
    let client = stronghold.create_client(client_path.clone())?;

    let output_location = crate::Location::generic(vault_path.clone(), record_path.clone());

    // Generate key and store it at output_location
    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location.clone(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

    assert!(procedure_result.is_ok());

    let vault_exists = client.vault_exists(vault_path.clone());
    assert!(vault_exists.is_ok());
    assert!(vault_exists.unwrap());

    // Derive the public key of the key previously generated
    let public_key_procedure = PublicKey {
        ty: KeyType::Ed25519,
        private_key: output_location.clone(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure.clone()));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // some store data in the store
    let (k, v) = store_kv;
    let store = client.store();
    store.insert(k.clone(), v.clone(), None)?;

    // write client into snapshot
    stronghold.write_client(client_path.clone())?;

    // commit all to snapshot file
    stronghold.commit_with_keyprovider(&snapshot_path, &key_provider)?;

    //// -- reset stronghold, re-load snapshot from disk

    // reset stronghold
    let stronghold = stronghold.reset();

    // Reload Client
    let client = stronghold.load_client_from_snapshot(client_path, &key_provider, &snapshot_path)?;

    // Check vault secret value
    let procedure_result: Vec<u8> = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure)).unwrap().into();
    assert_eq!(procedure_result, output);

    // Check store value
    let store = client.store();
    let new_v = store.get(&k).unwrap();
    assert_eq!(new_v, Some(v));

    Ok(output)
}
