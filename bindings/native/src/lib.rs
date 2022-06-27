// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
extern crate core;

mod shared;
mod wrapper;

//#![allow(unused_imports)]
use log::LevelFilter;
use log::*;

use std::{
    cell::RefCell,
    error::Error,
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr, slice,
};

use crate::{
    shared::hash_blake2b,
    wrapper::{StrongholdWrapper, WrapperError},
};

thread_local! {
    static LAST_ERROR: RefCell<Option<Box<dyn Error>>> = RefCell::new(None);
}

fn set_last_error(err: WrapperError) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

#[no_mangle]
pub extern "C" fn stronghold_set_log_level(log_level: libc::size_t) {
    let filter = match log_level as usize {
        0 => Some(LevelFilter::Off),
        1 => Some(LevelFilter::Error),
        2 => Some(LevelFilter::Warn),
        3 => Some(LevelFilter::Info),
        4 => Some(LevelFilter::Debug),
        5 => Some(LevelFilter::Trace),
        _ => Some(LevelFilter::Off),
    };

    let _logger = env_logger::builder()
        .is_test(false)
        .filter_level(filter.unwrap())
        .try_init();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_get_last_error() -> *const c_char {
    let last_error = LAST_ERROR.with(|prev| prev.borrow_mut().take());

    let last_error = match last_error {
        Some(err) => err,
        None => return ptr::null_mut(),
    };

    let s = CString::new(last_error.to_string()).unwrap();
    s.into_raw()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_destroy_error(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    let _ = CString::from_raw(s);
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_create(
    snapshot_path_c: *const libc::c_char,
    key_c: *const libc::c_char,
) -> *mut StrongholdWrapper {
    let snapshot_path = CStr::from_ptr(snapshot_path_c);
    let snapshot_path = snapshot_path.to_str().unwrap().to_string();
    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let stronghold_wrapper = match StrongholdWrapper::create_new(snapshot_path, key_as_hash) {
        Ok(res) => res,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(stronghold_wrapper))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_load(
    snapshot_path_c: *const libc::c_char,
    key_c: *const libc::c_char,
) -> *mut StrongholdWrapper {
    let snapshot_path = CStr::from_ptr(snapshot_path_c);
    let snapshot_path = snapshot_path.to_str().unwrap().to_string();
    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let stronghold_wrapper = match StrongholdWrapper::from_file(snapshot_path, key_as_hash) {
        Ok(res) => res,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    info!("[Rust] Snapshot loaded");

    Box::into_raw(Box::new(stronghold_wrapper))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_destroy_stronghold(stronghold_ptr: *mut StrongholdWrapper) {
    info!("[Rust] Destroy started");

    if stronghold_ptr.is_null() {
        error!("[Rust] Stronghold pointer was null!");

        return;
    }

    Box::from_raw(stronghold_ptr);

    info!("[Rust] Destroyed instance");
}

// TODO: Find better way to generalize destroy into one function
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_destroy_data_pointer(ptr: *mut u8) {
    info!("[Rust] Destroy started");

    if ptr.is_null() {
        error!("[Rust] Data pointer was null!");

        return;
    }

    Box::from_raw(ptr);

    info!("[Rust] Destroyed instance");
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_generate_ed25519_keypair(
    stronghold_ptr: *mut StrongholdWrapper,
    key_c: *const libc::c_char,
    record_path_c: *const libc::c_char,
) -> *mut u8 {
    info!("[Rust] Generate ED25519 Keypair started");

    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let record_path = CStr::from_ptr(record_path_c);
    let record_path = record_path.to_str().unwrap().to_string();

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    let chain_code = match stronghold_wrapper.generate_ed25519_keypair(key_as_hash, record_path) {
        Ok(res) => res,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(chain_code)) as *mut _
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_write_vault(
    stronghold_ptr: *mut StrongholdWrapper,
    key_c: *const libc::c_char,
    record_path_c: *const libc::c_char,
    data_c: *const libc::c_uchar,
    data_length: libc::size_t,
) -> bool {
    info!("[Rust] Writing Vault started");

    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    let record_path = CStr::from_ptr(record_path_c);
    let record_path = record_path.to_str().unwrap().to_string();
    let data = slice::from_raw_parts(data_c, data_length as usize);

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    if let Err(err) = stronghold_wrapper.write_vault(key_as_hash, record_path, data.to_vec()) {
        set_last_error(err);
        return false;
    }

    true
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_generate_seed(
    stronghold_ptr: *mut StrongholdWrapper,
    key_c: *const libc::c_char,
) -> bool {
    info!("[Rust] Generate Seed started");

    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    if let Err(err) = stronghold_wrapper.generate_seed(key_as_hash) {
        set_last_error(err);
        return false;
    }

    true
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_derive_seed(
    stronghold_ptr: *mut StrongholdWrapper,
    key_c: *const libc::c_char,
    address_index: u32,
) -> bool {
    info!("[Rust] Derive Seed started");

    let key = CStr::from_ptr(key_c);
    let key_as_hash = hash_blake2b(key.to_str().unwrap().to_string());

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    if let Err(err) = stronghold_wrapper.derive_seed(key_as_hash, address_index) {
        set_last_error(err);
        return false;
    }

    true
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_get_public_key(
    stronghold_ptr: *mut StrongholdWrapper,
    record_path_c: *const libc::c_char,
) -> *mut u8 {
    info!("[Rust] Get public key started");

    let record_path = CStr::from_ptr(record_path_c);
    let record_path = record_path.to_str().unwrap().to_string();

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    let public_key = match stronghold_wrapper.get_public_key(record_path) {
        Ok(res) => res,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(public_key)) as *mut _
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn stronghold_sign(
    stronghold_ptr: *mut StrongholdWrapper,
    record_path_c: *const libc::c_char,
    data_c: *const libc::c_uchar,
    data_length: libc::size_t,
) -> *mut u8 {
    let record_path = CStr::from_ptr(record_path_c);
    let record_path = record_path.to_str().unwrap().to_string();
    let data = slice::from_raw_parts(data_c, data_length as usize);

    info!("[Rust] Getting Stronghold instance from Box");

    let stronghold_wrapper = {
        assert!(!stronghold_ptr.is_null());
        &mut *stronghold_ptr
    };

    info!("[Rust] Got Stronghold instance from Box");

    let signature = match stronghold_wrapper.sign(record_path, data.to_vec()) {
        Ok(res) => res,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(signature)) as *mut _
}
