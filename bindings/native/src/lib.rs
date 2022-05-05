//FUNCTIONS
//#![allow(unused_imports)]
use crypto::hashes::{blake2b::Blake2b256, Digest};
use crypto::signatures::ed25519;
use iota_stronghold_new as stronghold;
use iota_stronghold_new::procedures::Slip10DeriveInput;
use std::ffi::CStr;
use std::slice;
use stronghold::procedures::{Chain, Ed25519Sign, PublicKey, Slip10Derive, Slip10Generate};
use stronghold::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    KeyProvider, Location, SnapshotPath, Store, Stronghold,
};

// For now just as consts here
const CLIENT_PATH: &str = "wasp";
const VAULT_PATH: &str = "wasp";
const KEY_TYPE: KeyType = KeyType::Ed25519;
const SEED_LENGTH: usize = 32;
const RECORD_PATH_SEED: &str = "seed";

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

    let snapshot_path = unsafe { CStr::from_ptr(snapshot_path_c) };
    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let stronghold = Stronghold::default();

    stronghold
        .create_client(CLIENT_PATH)
        .expect("[Rust] Cannot creat client");

    println!("[Rust] Client created");

    stronghold
        .write_client(CLIENT_PATH)
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
            CLIENT_PATH,
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
pub extern "C" fn destroy_data_pointer(ptr: *mut u8) {
    println!("[Rust] Destroy started");

    if ptr.is_null() {
        println!("[Rust] Stronghold Pointer was null!");

        return;
    }

    unsafe {
        Box::from_raw(ptr);
    }

    println!("[Rust] Destroyed instance");
}

#[no_mangle]
pub extern "C" fn generate_ed25519_keypair(
    stronghold_ptr: *mut StrongholdWrapper,
    key_c: *const libc::c_char,
    record_path_c: *const libc::c_char,
) {
    println!("[Rust] Generate Seed started");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap();

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let stronghold = &stronghold_wrapper.stronghold;
    let client = stronghold.get_client(CLIENT_PATH).unwrap();

    let output = Location::Generic {
        record_path: record_path.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    let generate_key_procedure = GenerateKey { ty: KEY_TYPE, output };

    println!("[Rust] Generating Key procedure started");

    client
        .execute_procedure(generate_key_procedure)
        .expect("Running procedure failed");

    println!("[Rust] Key generated");
    println!("[Rust] Storing client");

    stronghold
        .write_client(CLIENT_PATH)
        .expect("[Rust] Store client state into snapshot state failed");

    println!("[Rust] client stored");

    println!("[Rust] Committing to snapshot");

    stronghold
        .commit(
            &SnapshotPath::from_path(stronghold_wrapper.snapshot_path.as_str()),
            &KeyProvider::try_from(key_hash).unwrap(),
        )
        .expect("[Rust] Failed to commit to snapshot");

    println!("[Rust] Snapshot committed!");
}

#[no_mangle]
pub extern "C" fn generate_seed(stronghold_ptr: *mut StrongholdWrapper, key_c: *const libc::c_char) {
    println!("[Rust] Generate Seed started");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let stronghold = &stronghold_wrapper.stronghold;
    let client = stronghold.get_client(CLIENT_PATH).unwrap();

    let output = Location::Generic {
        record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    println!("[Rust] Generating Seed procedure started");

    let slip10_generate = Slip10Generate {
        size_bytes: Some(SEED_LENGTH),
        output,
    };

    client
        .execute_procedure(slip10_generate)
        .expect("Failed to generate seed");

    println!("[Rust] Key generated");
    println!("[Rust] Storing client");

    stronghold
        .write_client(CLIENT_PATH)
        .expect("[Rust] Store client state into snapshot state failed");

    println!("[Rust] client stored");

    println!("[Rust] Committing to snapshot");

    stronghold
        .commit(
            &SnapshotPath::from_path(stronghold_wrapper.snapshot_path.as_str()),
            &KeyProvider::try_from(key_hash).unwrap(),
        )
        .expect("[Rust] Failed to commit to snapshot");

    println!("[Rust] Snapshot committed!");
}

#[no_mangle]
pub extern "C" fn derive_seed(stronghold_ptr: *mut StrongholdWrapper, key_c: *const libc::c_char, address_index: u32) {
    println!("[Rust] Generate Seed started");

    let seed_derived_path = format!("{RECORD_PATH_SEED}{address_index}");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let stronghold = &stronghold_wrapper.stronghold;
    let client = stronghold.get_client(CLIENT_PATH).unwrap();

    let seed_location = Location::Generic {
        record_path: RECORD_PATH_SEED.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    let seed_derived_location = Location::Generic {
        record_path: seed_derived_path.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    let chain = Chain::from_u32_hardened(vec![address_index]);

    println!("[Rust] Deriving Seed procedure started");

    let slip10_derive = Slip10Derive {
        chain,
        input: iota_stronghold_new::procedures::Slip10DeriveInput::Seed(seed_location),
        output: seed_derived_location,
    };

    client
        .execute_procedure(slip10_derive)
        .expect("Failed to derive from seed!");

    println!("[Rust] Derive generated");
    println!("[Rust] Storing client");

    stronghold
        .write_client(CLIENT_PATH)
        .expect("[Rust] Store client state into snapshot state failed");

    println!("[Rust] client stored");
    println!("[Rust] Committing to snapshot");

    stronghold
        .commit(
            &SnapshotPath::from_path(stronghold_wrapper.snapshot_path.as_str()),
            &KeyProvider::try_from(key_hash).unwrap(),
        )
        .expect("[Rust] Failed to commit to snapshot");

    println!("[Rust] Snapshot committed!");
}

#[no_mangle]
pub extern "C" fn get_public_key(
    stronghold_ptr: *mut StrongholdWrapper,
    record_path_c: *const libc::c_char,
) -> *mut u8 {
    println!("[Rust] Get public key started");

    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap();

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let stronghold = &stronghold_wrapper.stronghold;
    let client = stronghold.get_client(CLIENT_PATH).unwrap();

    let private_key = Location::Generic {
        record_path: record_path.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    let public_key_procedure = PublicKey {
        ty: KEY_TYPE,
        private_key,
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    return Box::into_raw(Box::new(output)) as *mut _;
}

#[no_mangle]
pub extern "C" fn sign(
    stronghold_ptr: *mut StrongholdWrapper,
    record_path_c: *const libc::c_char,
    data_c: *const libc::c_uchar,
    data_length: libc::size_t,
) -> *mut u8 {
    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap();

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let client = stronghold_wrapper.stronghold.get_client(CLIENT_PATH).unwrap();

    let output_location = Location::Generic {
        record_path: record_path.as_bytes().to_vec(),
        vault_path: VAULT_PATH.as_bytes().to_vec(),
    };

    let data = unsafe { slice::from_raw_parts(data_c, data_length as usize) };

    let sign_message = Ed25519Sign {
        private_key: output_location,
        msg: data.to_vec(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::Ed25519Sign(sign_message));

    assert!(procedure_result.is_ok());

    let signature: Vec<u8> = procedure_result.unwrap().into();

    return Box::into_raw(Box::new(signature)) as *mut _;
}
