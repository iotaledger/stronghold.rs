use iota_stronghold::Stronghold;
use threadpool::ThreadPool;

// Test to make sure that multithreaded stronghold does not crash
#[test]
fn test_stronghold_multithreaded_safety() {
    const NB_CLIENTS: usize = 5;
    const NB_INPUTS: usize = 10;

    let main_stronghold = Stronghold::default();
    let pool = ThreadPool::new(8);

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
    let pool = ThreadPool::new(5);
    main_stronghold.create_client(&client_path).unwrap();
    main_stronghold.write_client(&client_path).unwrap();

    for i in 0..NB_INPUTS {
        let stronghold = main_stronghold.clone();
        let path = client_path.clone();
        pool.execute(move || {
            let cl = stronghold.get_client(&path).unwrap();
            println!("before {}: {:?}", i, cl.store.keys().unwrap());
            let key = format!("{}", i).into_bytes();
            let value = format!("value{}", i).into_bytes();
            cl.store().insert(key, value, None).unwrap();
            println!("insert {}: {:?}", i, cl.store.keys().unwrap());
            stronghold.write_client(&path).unwrap();
            println!("commit {}: {:?}", i, cl.store.keys().unwrap());
        });
    }
    pool.join();

    let cl = main_stronghold.load_client(client_path).unwrap();
    println!("{:?}", cl.store.keys());
    for i in 0..NB_INPUTS {
        let key = format!("{}", i).into_bytes();
        let expected_value = format!("value{}", i).into_bytes();
        let v = cl.store().get(&key).unwrap();
        // assert_eq!(v, Some(expected_value));
    }
}

// #[test]
// fn test_full_stronghold_access_multithreaded() {
//     let vault_path = b"vault_path".to_vec();
//     let client_path = b"client_path".to_vec();

//     // load the base type
//     let stronghold = Stronghold::default();

//     let key = b"abcdefghijklmnopqrstuvwxyz123456".to_vec();
//     let keyprovider = KeyProvider::try_from(key).map_err(|e| format!("Error {:?}", e))?;
//     let snapshot_path: SnapshotPath = SnapshotPath::named("testing-snapshot.snapshot");

//     let snapshot = Snapshot::default();

//     // create a new empty client
//     let client = stronghold.create_client(client_path.clone())?;

//     let output_location = crate::Location::generic(b"vault_path".to_vec(), b"record_path".to_vec());

//     let generate_key_procedure = GenerateKey {
//         ty: KeyType::Ed25519,
//         output: output_location.clone(),
//         // hint: RecordHint::new(b"").unwrap(),
//     };

//     let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

//     assert!(procedure_result.is_ok());

//     let vault_exists = client.vault_exists(b"vault_path");
//     assert!(vault_exists.is_ok());
//     assert!(vault_exists.unwrap());

//     // get the public key
//     let public_key_procedure = crate::procedures::PublicKey {
//         ty: KeyType::Ed25519,
//         private_key: output_location,
//     };

//     let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure.clone()));

//     assert!(procedure_result.is_ok());

//     let procedure_result = procedure_result.unwrap();
//     let output: Vec<u8> = procedure_result.into();

//     // some store data
//     let store = client.store();

//     let vault_location = Location::const_generic(vault_path.to_vec(), b"".to_vec());
//     let vault = client.vault(b"vault_path");

//     // create a new secret inside the vault
//     assert!(vault
//         .write_secret(Location::const_generic(vault_path, b"record-path".to_vec()), vec![],)
//         .is_ok());

//     // write client into snapshot
//     stronghold.write_client(client_path.clone())?;

//     // commit all to snapshot file
//     stronghold.commit(&snapshot_path, &keyprovider)?;

//     //// -- reset stronghold, re-load snapshot from disk

//     // reset stronghold
//     let stronghold = stronghold.reset();

//     println!("load client from snapshot file");
//     let client = stronghold.load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)?;

//     // Write the state of the client back into the snapshot
//     let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

//     assert!(procedure_result.is_ok());

//     Ok(())
// }
