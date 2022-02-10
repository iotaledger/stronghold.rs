// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_utils::random;

use crate::{
    sync::{SelectOne, SelectOrMerge},
    Location, Stronghold,
};

use super::fresh;

#[actix::test]
async fn sync_clients() {
    let source_client = random::bytestring(4096);

    let loc1 = fresh::location();
    let hint1 = fresh::record_hint();

    let vault2 = random::bytestring(4096);
    let loc2 = Location::counter(vault2.clone(), 0usize);
    let hint2 = fresh::record_hint();

    let loc3 = Location::counter(vault2.clone(), 1usize);
    let hint31 = fresh::record_hint();

    let mut stronghold = Stronghold::init_stronghold_system(source_client.clone(), vec![])
        .await
        .unwrap();

    for (loc, hint) in [(&loc1, &hint1), (&loc2, &hint2), (&loc3, &hint31)] {
        stronghold
            .write_to_vault(loc.clone(), random::bytestring(4096), *hint, vec![])
            .await
            .unwrap()
            .unwrap();
    }

    let target_client = random::bytestring(4096);

    stronghold
        .spawn_stronghold_actor(target_client.clone(), vec![])
        .await
        .unwrap();

    let hint32 = fresh::record_hint();

    let loc4 = fresh::location();
    let hint4 = fresh::record_hint();

    let loc5 = fresh::location();
    let hint5 = fresh::record_hint();

    for (loc, hint) in [(&loc3, &hint32), (&loc4, &hint4), (&loc5, &hint5)] {
        stronghold
            .write_to_vault(loc.clone(), random::bytestring(4096), *hint, vec![])
            .await
            .unwrap()
            .unwrap();
    }

    stronghold
        .sync_clients(
            source_client.clone(),
            target_client.clone(),
            SelectOrMerge::Merge(SelectOne::KeepOld),
            None,
        )
        .await
        .unwrap();

    // Source client should be unchanged.
    stronghold.switch_actor_target(source_client).await.unwrap();
    let v1_ids = stronghold.list_hints_and_ids(loc1.vault_path()).await.unwrap();
    assert_eq!(v1_ids.len(), 1);
    assert!(v1_ids.iter().any(|(_, hint)| hint == &hint1));
    let v2_ids = stronghold.list_hints_and_ids(vault2.clone()).await.unwrap();
    assert_eq!(v2_ids.len(), 2);
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint2));
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint31));
    let v4_ids = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    assert!(v4_ids.is_empty());
    let v5_ids = stronghold.list_hints_and_ids(loc5.vault_path()).await.unwrap();
    assert!(v5_ids.is_empty());

    // Target client should contain it's own values + the merged ones from the source client.
    stronghold.switch_actor_target(target_client).await.unwrap();

    // Check merged records.
    let v1_ids = stronghold.list_hints_and_ids(loc1.vault_path()).await.unwrap();
    assert_eq!(v1_ids.len(), 1);
    assert!(v1_ids.iter().any(|(_, hint)| hint == &hint1));
    let v2_ids = stronghold.list_hints_and_ids(vault2).await.unwrap();
    assert_eq!(v2_ids.len(), 2);
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint2));

    // For conflicting record it should keep old record.
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint32));

    // Check old records.
    let v4_ids = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    assert_eq!(v4_ids.len(), 1);
    assert!(v4_ids.iter().any(|(_, hint)| hint == &hint4));
    let v5_ids = stronghold.list_hints_and_ids(loc5.vault_path()).await.unwrap();
    assert_eq!(v5_ids.len(), 1);
    assert!(v5_ids.iter().any(|(_, hint)| hint == &hint5));
}
