// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::actors::{GetClient, Registry, RemoveClient, SpawnClient};
use actix::Actor;
use engine::vault::ClientId;

#[actix::test]
async fn test_insert_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        let n = registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await;

        assert!(n.is_ok());
    }
}

#[actix::test]
async fn test_get_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        assert!(registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await
            .is_ok());
    }

    assert!(registry
        .send(GetClient {
            id: ClientId::load("b".repeat(24).as_bytes()).unwrap(),
        })
        .await
        .is_ok());
}

#[actix::test]
async fn test_remove_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        assert!(registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await
            .is_ok());
    }

    if let Ok(result) = registry
        .send(RemoveClient {
            id: ClientId::load("a".repeat(24).as_bytes()).unwrap(),
        })
        .await
    {
        assert!(result.is_ok())
    }
}
