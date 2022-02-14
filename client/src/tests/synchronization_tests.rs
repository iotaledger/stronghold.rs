// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_utils::random;

use crate::{
    sync::{SelectOne, SelectOrMerge},
    Location, Stronghold,
};

use super::fresh;

macro_rules! write_client {
    ($stronghold:ident => $client:ident: $($loc:ident -> $hint:ident),+) => {
        let $client = random::bytestring(4096);
        $stronghold
            .spawn_stronghold_actor($client.clone(), vec![])
            .await?;
        $(
            let $loc = fresh::location();
            let $hint = fresh::record_hint();
            $stronghold
                .write_to_vault($loc.clone(), random::bytestring(4096), $hint, vec![])
                .await??;
        )+
    };
}

#[actix::test]
async fn sync_clients() -> Result<(), Box<dyn std::error::Error>> {
    let source_client = random::bytestring(4096);

    let mut stronghold = Stronghold::init_stronghold_system(source_client.clone(), vec![]).await?;

    let loc1 = fresh::location();
    let hint1 = fresh::record_hint();

    // Two records in the same vault.
    let vault2 = random::bytestring(4096);
    let loc2 = Location::counter(vault2.clone(), 0usize);
    let hint2 = fresh::record_hint();

    let loc3 = Location::counter(vault2.clone(), 1usize);
    let hint31 = fresh::record_hint();

    for (loc, hint) in [(&loc1, hint1), (&loc2, hint2), (&loc3, hint31)] {
        stronghold
            .write_to_vault(loc.clone(), random::bytestring(4096), hint, vec![])
            .await??;
    }

    // Records that only exists at target client.
    write_client!(stronghold => target_client: loc4 -> hint4, loc5 -> hint5);

    // Conflicting record that exists at both clients with different hints.
    let hint32 = fresh::record_hint();
    stronghold
        .write_to_vault(loc3.clone(), random::bytestring(4096), hint32, vec![])
        .await??;

    // Do sync.
    stronghold
        .sync_clients(
            source_client.clone(),
            target_client.clone(),
            SelectOrMerge::Merge(SelectOne::KeepOld),
            None,
        )
        .await?;

    // Source client should be unchanged.
    stronghold.switch_actor_target(source_client).await?;
    let v1_ids = stronghold.list_hints_and_ids(loc1.vault_path()).await?;
    assert_eq!(v1_ids.len(), 1);
    assert!(v1_ids.iter().any(|(_, hint)| hint == &hint1));
    let v2_ids = stronghold.list_hints_and_ids(vault2.clone()).await?;
    assert_eq!(v2_ids.len(), 2);
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint2));
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint31));
    let v4_ids = stronghold.list_hints_and_ids(loc4.vault_path()).await?;
    assert!(v4_ids.is_empty());
    let v5_ids = stronghold.list_hints_and_ids(loc5.vault_path()).await?;
    assert!(v5_ids.is_empty());

    // Target client should contain it's own values + the merged ones from the source client.
    stronghold.switch_actor_target(target_client).await?;

    // Check merged records.
    let v1_ids = stronghold.list_hints_and_ids(loc1.vault_path()).await?;
    assert_eq!(v1_ids.len(), 1);
    assert!(v1_ids.iter().any(|(_, hint)| hint == &hint1));
    let v2_ids = stronghold.list_hints_and_ids(vault2).await?;
    assert_eq!(v2_ids.len(), 2);
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint2));

    // For conflicting record it should keep old record.
    assert!(v2_ids.iter().any(|(_, hint)| hint == &hint32));

    // Check old records.
    let v4_ids = stronghold.list_hints_and_ids(loc4.vault_path()).await?;
    assert_eq!(v4_ids.len(), 1);
    assert!(v4_ids.iter().any(|(_, hint)| hint == &hint4));
    let v5_ids = stronghold.list_hints_and_ids(loc5.vault_path()).await?;
    assert_eq!(v5_ids.len(), 1);
    assert!(v5_ids.iter().any(|(_, hint)| hint == &hint5));

    Ok(())
}

#[cfg(feature = "p2p")]
#[actix::test]
async fn remote_sync() -> Result<(), Box<dyn std::error::Error>> {
    use engine::vault::ClientId;

    use crate::{
        p2p::{NetworkConfig, Rule, SwarmInfo},
        utils::LoadFromPath,
    };

    let client_01 = "client-0".as_bytes().to_vec();
    let mut source_stronghold = Stronghold::init_stronghold_system(client_01.clone(), vec![]).await?;
    source_stronghold
        .write_to_vault(
            fresh::location(),
            random::bytestring(4096),
            fresh::record_hint(),
            vec![],
        )
        .await??;

    // Client-1 only exists at source stronghold.
    write_client!(source_stronghold => client_1: loc_11 -> hint_11, loc_12 -> hint_12);

    // Client-2 only exists at source stronghold, but will be mapped to a new client-5 at target.
    let client_2 = "client-2".as_bytes().to_vec();
    source_stronghold
        .spawn_stronghold_actor(client_2.clone(), vec![])
        .await?;
    let loc_21 = fresh::location();
    let hint_21 = fresh::record_hint();
    let loc_22 = fresh::location();
    let hint_22 = fresh::record_hint();

    for (loc, hint) in [(&loc_21, hint_21), (&loc_22, hint_22)] {
        source_stronghold
            .write_to_vault(loc.clone(), random::bytestring(4096), hint, vec![])
            .await??;
    }
    write_client!(source_stronghold => client_3: loc_31 -> hint_311, loc_32 -> hint_32);

    source_stronghold.fill_snapshot_state().await?;

    source_stronghold.spawn_p2p(NetworkConfig::default(), None).await?;
    source_stronghold
        .set_firewall_rule(Rule::AllowAll, vec![], true)
        .await?;
    let addr = source_stronghold.start_listening(None).await??;
    let SwarmInfo {
        local_peer_id: source_id,
        ..
    } = source_stronghold.get_swarm_info().await?;

    // Empty client only used for init.
    let client_02 = random::bytestring(4096);
    let mut target_stronghold = Stronghold::init_stronghold_system(client_02.clone(), vec![]).await?;
    target_stronghold.spawn_p2p(NetworkConfig::default(), None).await?;
    target_stronghold.add_peer(source_id, Some(addr)).await??;

    // Conflicting client 3 exists on both strongholds.
    target_stronghold
        .spawn_stronghold_actor(client_3.clone(), vec![])
        .await?;

    // Hint at target stronghold, for conflicting record at loc_31 that exists at both strongholds.
    let hint_312 = fresh::record_hint();
    // Different record that only exists at the target stronghold.
    let loc_33 = fresh::location();
    let hint_33 = fresh::record_hint();

    for (loc, hint) in [(&loc_31, hint_312), (&loc_33, hint_33)] {
        target_stronghold
            .write_to_vault(loc.clone(), random::bytestring(4096), hint, vec![])
            .await??;
    }
    // Additional client 4 that only exists at target.
    write_client!(target_stronghold => client_4: loc_41 -> hint_41, loc_42 -> hint_42);

    // Skip client-0, map client-2 to client-5, else keep ids unchanged.
    let mapping: fn(_) -> Option<_> = |(cid, vid, rid)| {
        let client_0_path = "client-0".as_bytes().to_vec();
        let client_0_id = ClientId::load_from_path(&client_0_path, &client_0_path.clone());
        if cid == client_0_id {
            return None;
        }

        let client_2_path = "client-2".as_bytes().to_vec();
        let client_2_id = ClientId::load_from_path(&client_2_path, &client_2_path.clone());
        if cid == client_2_id {
            let client_5_path = "client-5".as_bytes().to_vec();
            let client_5_id = ClientId::load_from_path(&client_5_path, &client_5_path.clone());
            return Some((client_5_id, vid, rid));
        }
        Some((cid, vid, rid))
    };

    // Do sync.
    let merge_policy = SelectOrMerge::Merge(SelectOrMerge::Merge(SelectOne::Replace));
    target_stronghold
        .sync_with(source_id, merge_policy, Some(mapping.into()))
        .await?;

    // Client-01 was skipped;
    assert!(!target_stronghold.load_state(client_01, None).await?);
    // Client-02 still exists;
    assert!(target_stronghold.load_state(client_02, None).await?);

    // Client-4 still exists;
    assert!(target_stronghold.load_state(client_4, None).await?);
    let list = target_stronghold.list_hints_and_ids(loc_41.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_41);
    let list = target_stronghold.list_hints_and_ids(loc_42.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_42);

    // Client-1 was fully imported.
    assert!(target_stronghold.load_state(client_1, None).await?);
    let list = target_stronghold.list_hints_and_ids(loc_11.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_11);
    let list = target_stronghold.list_hints_and_ids(loc_12.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_12);

    // Client-2 was fully imported as client-5.
    assert!(!target_stronghold.load_state(client_2, None).await?);
    assert!(
        target_stronghold
            .load_state("client-5".as_bytes().to_vec(), None)
            .await?
    );
    let list = target_stronghold.list_hints_and_ids(loc_21.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_21);
    let list = target_stronghold.list_hints_and_ids(loc_22.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_22);

    // Client-3 was merged into existing client-3.
    assert!(target_stronghold.load_state(client_3, None).await?);
    // loc_31 exists at both. According to merge policy SelectOne::Replace the
    // existing record (and therefore also the hint) is replaces with the one from
    // the source vault.
    let list = target_stronghold.list_hints_and_ids(loc_31.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_311);
    // Import (non-conflicting) record-32 from source.
    let list = target_stronghold.list_hints_and_ids(loc_32.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_32);
    // Keep (non-conflicting) existing record-33.
    let list = target_stronghold.list_hints_and_ids(loc_33.vault_path()).await?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, hint_33);

    drop(source_stronghold);
    drop(target_stronghold);

    Ok(())
}
