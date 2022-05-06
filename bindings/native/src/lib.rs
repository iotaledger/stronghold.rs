extern crate core;

mod wrapper;
mod shared;

//#![allow(unused_imports)]
use std::ffi::CStr;
use std::{ptr, slice};

use crate::shared::hash_blake2b;
use crate::wrapper::StrongholdWrapper;

#[no_mangle]
pub extern "C" fn create(snapshot_path_c: *const libc::c_char, key_c: *const libc::c_char) -> *mut StrongholdWrapper {
    println!("[Rust] Create started");

    let snapshot_path = unsafe { CStr::from_ptr(snapshot_path_c) };
    let snapshot_path = snapshot_path.to_str().unwrap().to_string();
    let key = unsafe { CStr::from_ptr(key_c) };
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let stronghold_wrapper = match StrongholdWrapper::create_new(snapshot_path, key_as_hash) {
        Ok(res) => res,
        Err(_err) => return ptr::null_mut(),
    };

    Box::into_raw(Box::new(stronghold_wrapper))
}

#[no_mangle]
pub extern "C" fn load(snapshot_path_c: *const libc::c_char, key_c: *const libc::c_char) -> *mut StrongholdWrapper {
    println!("[Rust] Load started");

    let snapshot_path = unsafe { CStr::from_ptr(snapshot_path_c) };
    let snapshot_path = snapshot_path.to_str().unwrap().to_string();
    let key = unsafe { CStr::from_ptr(key_c) };
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Initializing Stronghold");
    println!("[Rust] Loading snapshot => {}", snapshot_path);

    let stronghold_wrapper = match StrongholdWrapper::from_file(snapshot_path, key_as_hash) {
        Ok(res) => res,
        Err(_err) => return ptr::null_mut(),
    };

    println!("[Rust] Snapshot loaded");

    return Box::into_raw(Box::new(stronghold_wrapper));
}

#[no_mangle]
pub extern "C" fn destroy_stronghold(stronghold_ptr: *mut StrongholdWrapper) {
    println!("[Rust] Destroy started");

    if stronghold_ptr.is_null() {
        println!("[Rust] Stronghold pointer was null!");

        return;
    }

    unsafe {
        Box::from_raw(stronghold_ptr);
    }

    println!("[Rust] Destroyed instance");
}

// TODO: Find better way to generalize destroy into one function
#[no_mangle]
pub extern "C" fn destroy_data_pointer(ptr: *mut u8) {
    println!("[Rust] Destroy started");

    if ptr.is_null() {
        println!("[Rust] Data pointer was null!");

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
) -> *mut u8 {
    println!("[Rust] Generate Seed started");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap().to_string();

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let chain_code = match stronghold_wrapper.generate_ed25519_keypair(key_as_hash, record_path) {
        Ok(res) => res,
        Err(_err) => return ptr::null_mut(),
    };

    return Box::into_raw(Box::new(chain_code)) as *mut _;
}

#[no_mangle]
pub extern "C" fn generate_seed(stronghold_ptr: *mut StrongholdWrapper, key_c: *const libc::c_char) -> bool {
    println!("[Rust] Generate Seed started");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    return match stronghold_wrapper.generate_seed(key_as_hash) {
        Err(_err) => false,
        _ => true,
    };
}

#[no_mangle]
pub extern "C" fn derive_seed(stronghold_ptr: *mut StrongholdWrapper, key_c: *const libc::c_char, address_index: u32) -> bool {
    println!("[Rust] Generate Seed started");

    let key = unsafe { CStr::from_ptr(key_c) };
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    return match stronghold_wrapper.derive_seed(key_as_hash, address_index) {
        Err(_err) => false,
        _ => true,
    };
}

#[no_mangle]
pub extern "C" fn get_public_key(stronghold_ptr: *mut StrongholdWrapper, record_path_c: *const libc::c_char, ) -> *mut u8 {
    println!("[Rust] Get public key started");

    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap().to_string();

    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let public_key = match stronghold_wrapper.get_public_key(record_path) {
        Ok(res) => res,
        Err(_err) => return ptr::null_mut(),
    };

    return Box::into_raw(Box::new(public_key)) as *mut _;
}

#[no_mangle]
pub extern "C" fn sign(stronghold_ptr: *mut StrongholdWrapper, record_path_c: *const libc::c_char, data_c: *const libc::c_uchar,  data_length: libc::size_t, ) -> *mut u8 {
    let record_path = unsafe { CStr::from_ptr(record_path_c) };
    let record_path = record_path.to_str().unwrap().to_string();
    let data = unsafe { slice::from_raw_parts(data_c, data_length as usize) };


    println!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = unsafe {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    println!("[Rust] Got Stronghold instance from Box");

    let signature = match stronghold_wrapper.sign(record_path, data.to_vec()) {
        Ok(res) => res,
        Err(_err) => return ptr::null_mut(),
    };

    return Box::into_raw(Box::new(signature)) as *mut _;
}
