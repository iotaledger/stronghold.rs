// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_stm::{transactional, TVar};

#[cfg(test)]
#[ctor::ctor]
/// This function will be run before any of the tests
fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

#[cfg(test)]
mod simple {

    use std::collections::HashMap;

    use stronghold_stm::LockedMemory;
    use zeroize::Zeroize;

    use super::*;

    #[tokio::test]
    async fn test_single_transaction() {
        let var: TVar<usize> = TVar::new(21);
        let v2 = var.clone();

        assert!(transactional(move |tx| {
            let a = tx.read(&v2)?;
            tx.write(a + 42, &v2)?;
            Ok(())
        })
        .await
        .is_ok());

        assert_eq!(*var.read().unwrap(), 63);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_multiple_transactions() {
        let var: TVar<usize> = TVar::new(21);
        let v2 = var.clone();
        let v3 = var.clone();

        let r2 = tokio::spawn(transactional(move |tx| {
            tx.write(42, &v3).unwrap();
            Ok(())
        }));

        let r1 = tokio::spawn(transactional(move |tx| {
            let a = tx.read(&v2).unwrap();
            tx.write(a + 42, &v2).unwrap();
            Ok(())
        }));

        r1.await
            .expect("Could not join task")
            .expect("Transaction error occured");
        r2.await
            .expect("Could not join task")
            .expect("Transaction error occured");

        assert_eq!(*var.read().unwrap(), 84);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_multiple_access() {
        let var: TVar<usize> = TVar::new(33);

        let result = var.read();
        assert!(result.is_ok());
        assert_eq!(*result.expect("Failed to unwrap result"), 33);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_multiple_types() {
        // local type for testing
        #[derive(Debug, Default, Clone, PartialEq)]
        struct Vault {
            data: HashMap<String, String>,
        }

        impl Zeroize for Vault {
            fn zeroize(&mut self) {
                todo!()
            }
        }

        impl LockedMemory for Vault {
            fn alloc<T>(
                _payload: T,
                _config: stronghold_stm::boxedalloc::MemoryConfiguration,
                _key: Option<Vec<u8>>,
            ) -> Result<Self, stronghold_stm::boxedalloc::MemoryError>
            where
                T: Zeroize + AsRef<Vec<u8>>,
            {
                todo!()
            }

            fn lock<T>(
                self,
                _payload: stronghold_stm::boxedalloc::GuardedMemory<T>,
                _key: Option<Vec<u8>>,
            ) -> Result<Self, stronghold_stm::boxedalloc::MemoryError>
            where
                T: Zeroize + AsRef<Vec<u8>>,
            {
                todo!()
            }

            fn unlock<T>(
                &self,
                _key: Option<Vec<u8>>,
            ) -> Result<stronghold_stm::boxedalloc::GuardedMemory<T>, stronghold_stm::boxedalloc::MemoryError>
            where
                T: Zeroize + AsRef<Vec<u8>>,
            {
                todo!()
            }
        }

        let var_usize = TVar::new(67usize);
        let var_vault = TVar::new(Vault::default());

        let (_u1, _u2) = (var_usize.clone(), var_usize.clone());
        let vv1 = var_vault.clone();
        let vv2 = var_vault.clone();

        // let r2 = tokio::spawn(transactional(move |tx| {
        //     tx.write(42, &u1).unwrap();
        //     Ok(())
        // }));

        // let r1 = tokio::spawn(transactional(move |tx| {
        //     let a = tx.read(&u2)?;
        //     tx.write(a + 42, &u2)?;

        //     // added a read: does this hang the transaction?
        //     // let _ = tx.read(&u2)?;
        //     Ok(())
        // }));

        let r3 = tokio::spawn(transactional(move |tx| {
            // FIXME:
            // this creates another copy in mem, but we actually want thread-safe writable access
            // to the inner (log) data. options are either to provide an option, that moves the inner type out
            // or store the inner log value into a mutex
            let mut v = tx.read(&vv1)?;

            // modify data
            v.data.insert("abcd".to_string(), "def".to_string());

            // write it back
            tx.write(v, &vv1)?;

            Ok(())
        }));

        let r4 = tokio::spawn(transactional(move |tx| {
            // FIXME:
            // this creates another copy in mem, but we actually want thread-safe writable access
            // to the inner (log) data. options are either to provide an option, that moves the inner type out
            // or store the inner log value into a mutex
            let mut v = tx.read(&vv2)?;
            v.data.insert("def".to_string(), "dddsa".to_string());
            tx.write(v, &vv2)?;

            // FIXME: this additional read would cause the transaction to
            // stay in the loop
            let _ = tx.read(&vv2)?;

            // v.data.get(&b"".to_vec());

            Ok(())
        }));

        // r1.await.expect("Could not join task").expect("Transaction failed");
        // r2.await.expect("Could not join task").expect("Transaction failed");
        r4.await.expect("Could not join task").expect("Transaction failed");
        r3.await.expect("Could not join task").expect("Transaction failed");

        // assert_eq!(*var_usize.read().unwrap(), 84);
        assert!(var_vault.read().unwrap().data.contains_key(&"def".to_string()));

        match var_vault.read() {
            Ok(inner) => {
                assert!(inner.data.contains_key(&"abcd".to_string()))
            }
            Err(e) => {
                println!("TEST MULTIPLE TYPES FAILED!!!!!!!");
                panic!("{}", e.to_string());
            }
        }

        // assert!(var_vault
        //     .read()
        //     .expect("Transaction failed")
        //     .data
        //     .contains_key(&"abcd".to_string()));
    }
}

#[cfg(test)]
mod complex {}
