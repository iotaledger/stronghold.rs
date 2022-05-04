//FUNCTIONS
//#![allow(unused_imports)]
use crypto::hashes::{blake2b::Blake2b256, Digest};
use crypto::signatures::ed25519;
use iota_stronghold_new as stronghold;
use std::ffi::CStr;
use std::slice;
use stronghold::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    KeyProvider, Location, SnapshotPath, Store, Stronghold,
};
pub struct StrongholdWrapper {
    snapshot_path: String,
    stronghold: Stronghold,
}

fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

#[no_mangle]
pub extern "C" fn create(snapshot_path_c: *const libc::c_char, key_c: *const libc::c_char) -> *mut StrongholdWrapper {
    println!("[Rust] Create started");
    let client_path = "wasp";

    let snapshot_path = unsafe { CStr::from_ptr(snapshot_path_c) };
    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let stronghold = Stronghold::default();

    stronghold
        .create_client(client_path)
        .expect("[Rust] Cannot creat client");
    println!("[Rust] Client created");

    stronghold
        .write_client(client_path)
        .expect("[Rust] Store client state into snapshot state failed");

    println!("[Rust] Client written");

    println!(
        "[Rust] Writing snapshot => {}",
        snapshot_path.to_str().unwrap().to_string()
    );

    stronghold
        .commit(
            &SnapshotPath::from_path(snapshot_path.to_str().unwrap().to_string()),
            &KeyProvider::try_from(key_hash).unwrap(),
        )
        .expect("[Rust] Failed to commit to snapshot");

    let stronghold_wrapper = StrongholdWrapper {
        snapshot_path: snapshot_path.to_str().unwrap().to_string(),
        stronghold: stronghold,
    };

    println!("[Rust] Snapshot written");

    Box::into_raw(Box::new(stronghold_wrapper))
}

#[no_mangle]
pub extern "C" fn load(snapshot_path_c: *const libc::c_char, key_c: *const libc::c_char) -> *mut StrongholdWrapper {
    println!("[Rust] Load started");

    let client_path = "wasp";
    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());
    let snapshot_path = unsafe { CStr::from_ptr(snapshot_path_c) };

    println!("[Rust] Initializing Stronghold");

    let stronghold = Stronghold::default();

    println!(
        "[Rust] Loading snapshot => {}",
        snapshot_path.to_str().unwrap().to_string()
    );

    stronghold
        .load_client_from_snapshot(
            client_path,
            &KeyProvider::try_from(key_hash).unwrap(),
            &SnapshotPath::from_path(snapshot_path.to_str().unwrap()),
        )
        .unwrap();

    println!("[Rust] Snapshot loaded");

    let stronghold_wrapper = StrongholdWrapper {
        snapshot_path: snapshot_path.to_str().unwrap().to_string(),
        stronghold: stronghold,
    };

    return Box::into_raw(Box::new(stronghold_wrapper));
}

#[no_mangle]
pub extern "C" fn destroy_stronghold(stronghold_ptr: *mut StrongholdWrapper) {
    println!("[Rust] Destroy started");

    if stronghold_ptr.is_null() {
        println!("[Rust] Stronghold Pointer was null!");

        return;
    }

    unsafe {
        Box::from_raw(stronghold_ptr);
    }

    println!("[Rust] Destroyed instance");
}

#[no_mangle]
pub extern "C" fn destroy_signature(stronghold_ptr: *mut u8) {
    println!("[Rust] Destroy started");

    if stronghold_ptr.is_null() {
        println!("[Rust] Stronghold Pointer was null!");

        return;
    }

    unsafe {
        Box::from_raw(stronghold_ptr);
    }

    println!("[Rust] Destroyed instance");
}

#[no_mangle]
pub extern "C" fn generate_seed(stronghold_ptr: *mut StrongholdWrapper, key: *const libc::c_char) {
    println!("[Rust] Generate Seed started");

    let key_type = KeyType::Ed25519;
    let client_path = "wasp";
    let vault_path = "wasp";
    let record_path = "seed";

    let key = unsafe { CStr::from_ptr(key) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let stronghold = &stronghold_wrapper.stronghold;
    let client = stronghold.get_client(client_path).unwrap();

    let output = Location::Generic {
        record_path: record_path.as_bytes().to_vec(),
        vault_path: vault_path.as_bytes().to_vec(),
    };

    let generate_key_procedure = GenerateKey {
        ty: key_type,
        output: output,
    };

    println!("[Rust] Generating Key procedure started");

    client
        .execute_procedure(generate_key_procedure)
        .expect("Running procedure failed");

    println!("[Rust] Key generated");
    println!("[Rust] Storing client");

    stronghold
        .write_client(client_path)
        .expect("Store client state into snapshot state failed");

    println!("[Rust] client stored");

    println!("[Rust] Committing to snapshot");

    stronghold
        .commit(
            &SnapshotPath::from_path(stronghold_wrapper.snapshot_path.as_str()),
            &KeyProvider::try_from(key_hash).unwrap(),
        )
        .expect("Failed to commit to snapshot");

    println!("[Rust] Snapshot committed!");
}

#[no_mangle]
pub extern "C" fn sign(
    stronghold_ptr: *mut StrongholdWrapper,
    data_c: *const libc::c_uchar,
    data_length: libc::size_t,
) -> *mut u8 {
    let client_path = "wasp";
    let vault_path = "wasp";
    let record_path = "seed";

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let client = stronghold_wrapper.stronghold.get_client(client_path).unwrap();

    let output_location = Location::Generic {
        record_path: record_path.as_bytes().to_vec(),
        vault_path: vault_path.as_bytes().to_vec(),
    };

    let data = unsafe { slice::from_raw_parts(data_c, data_length as usize) };

    let sign_message = stronghold::procedures::Ed25519Sign {
        private_key: output_location,
        msg: data.to_vec(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::Ed25519Sign(sign_message));

    assert!(procedure_result.is_ok());

    let signature: Vec<u8> = procedure_result.unwrap().into();

    return Box::into_raw(Box::new(signature)) as *mut _;
}
