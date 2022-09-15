use iota_stronghold::Stronghold;
use threadpool::ThreadPool;

// Test to make sure that multithreaded stronghold does not crash
#[test]
fn test_stronghold_multithreaded_safety() {
    const NB_CLIENTS: usize = 20;
    const NB_INPUTS: usize = 100;

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
    const NB_INPUTS: usize = 100;
    let client_path = b"client_path".to_vec();

    let main_stronghold = Stronghold::default();
    let pool = ThreadPool::new(8);
    main_stronghold.create_client(&client_path).unwrap();
    main_stronghold.write_client(&client_path).unwrap();

    for i in 0..NB_INPUTS {
        let stronghold = main_stronghold.clone();
        let path = client_path.clone();
        pool.execute(move || {
            let cl = stronghold.load_client(&path).unwrap();
            let key = format!("key{}", i).into_bytes();
            let value = format!("value{}", i).into_bytes();
            cl.store().insert(key, value, None).unwrap();
            stronghold.write_client(&path).unwrap();
        });
    }
    pool.join();

    let cl = main_stronghold.load_client(client_path).unwrap();
    for i in 0..NB_INPUTS {
        let key = format!("key{}", i).into_bytes();
        let expected_value = format!("value{}", i).into_bytes();
        let v = cl.store().get(&key).unwrap();
        assert_eq!(v, Some(expected_value));
    }
}
