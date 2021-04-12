// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use crate::{line_error, utils::LoadFromPath, Location, RecordHint, ResultMessage, Stronghold};
use crypto::macs::hmac::HMAC_SHA512;

use engine::vault::{ClientId, VaultId};

fn setup_stronghold() -> Stronghold {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();

    Stronghold::init_stronghold_system(sys, client_path, vec![])
}

// test basic read and write.
#[test]
fn test_read_write() {
    let stronghold = setup_stronghold();

    let loc0 = Location::counter::<_, usize>("path", 0);

    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));
}

// test read and write with the counter head.
#[test]
fn test_head_read_write() {
    let stronghold = setup_stronghold();

    let lochead = Location::counter::<_, usize>("path", 0);

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    let lochead = lochead.increment_counter();

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"second hint").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));
}

// #[test]
// fn test_multi_write_read_counter_head() {
//     let stronghold = setup_stronghold();

//     let lochead = Location::counter::<_, usize>("path", None);
//     let loc5 = Location::counter::<_, usize>("path", Some(5));
//     let loc15 = Location::counter::<_, usize>("path", Some(15));

//     for i in 0..20 {
//         futures::executor::block_on(async {
//             let data = format!("test {:?}", i);
//             stronghold
//                 .write_to_vault(
//                     lochead.clone(),
//                     data.as_bytes().to_vec(),
//                     RecordHint::new(data).expect(line_error!()),
//                     vec![],
//                 )
//                 .await;
//         });
//     }

//     let list = futures::executor::block_on(stronghold.list_hints_and_ids("path"));

//     println!("{:?}", list);

//     let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead));

//     println!("{:?}", p);

//     let (p, _) = futures::executor::block_on(stronghold.read_secret(loc5));

//     println!("{:?}", p);

//     let (p, _) = futures::executor::block_on(stronghold.read_secret(loc15));

//     println!("{:?}", p);
// }

// test delete_data.
#[test]
fn test_revoke_with_gc() {
    let stronghold = setup_stronghold();

    let lochead = Location::counter::<_, usize>("path", 0);

    for i in 0..10 {
        futures::executor::block_on(async {
            let lochead = lochead.clone().increment_counter();
            let data = format!("test {:?}", i);
            stronghold
                .write_to_vault(
                    lochead.clone(),
                    data.as_bytes().to_vec(),
                    RecordHint::new(data).expect(line_error!()),
                    vec![],
                )
                .await;
        });
    }

    for i in 1..11 {
        futures::executor::block_on(async {
            let loc = Location::counter::<_, usize>("path", i);

            stronghold.delete_data(loc.clone(), false).await;

            let (p, _) = stronghold.read_secret(loc).await;

            assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));
        })
    }

    let (ids, _res) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path().to_vec()));

    futures::executor::block_on(stronghold.garbage_collect(lochead.vault_path().to_vec()));

    assert_eq!(ids, vec![]);
}

// /// Test writing to a snapshot and reading back.
// #[test]
// fn test_write_read_snapshot() {
//     let mut stronghold = setup_stronghold();

//     let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
//     let lochead = Location::counter::<_, usize>("path", None);

//     let client_path = b"test".to_vec();

//     for i in 0..20 {
//         futures::executor::block_on(async {
//             let data = format!("test {:?}", i);
//             stronghold
//                 .write_to_vault(
//                     lochead.clone(),
//                     data.as_bytes().to_vec(),
//                     RecordHint::new(data).expect(line_error!()),
//                     vec![],
//                 )
//                 .await;
//         });
//     }

//     futures::executor::block_on(stronghold.write_all_to_snapshot(&key_data, Some("test1".into()), None));

//     futures::executor::block_on(stronghold.kill_stronghold(client_path.clone(), false));

//     futures::executor::block_on(stronghold.read_snapshot(client_path, None, &key_data, Some("test1".into()), None));

//     for i in 0..20 {
//         futures::executor::block_on(async {
//             let loc = Location::counter::<_, usize>("path", Some(i));
//             let (p, _) = stronghold.read_secret(loc).await;

//             let res = format!("test {:?}", i);

//             assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
//         });
//     }
// }

// /// Makes 11 actors and writes one record into each of the child actors.  Writes the data from all of the actors into a
// /// snapshot. Clears the cache of the actors and then rebuilds them before re-reading the snapshot data back and
// /// checking it for consistency.
// #[test]
// fn test_write_read_multi_snapshot() {
//     let mut stronghold = setup_stronghold();

//     let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
//     let lochead = Location::counter::<_, usize>("path", None);

//     for i in 0..20 {
//         futures::executor::block_on(
//             stronghold.spawn_stronghold_actor(format!("test {:?}", i).as_bytes().to_vec(), vec![]),
//         );
//     }

//     for i in 0..20 {
//         futures::executor::block_on(async {
//             let data = format!("test {:?}", i);

//             stronghold
//                 .switch_actor_target(format!("test {:?}", i).as_bytes().to_vec())
//                 .await;

//             stronghold
//                 .write_to_vault(
//                     lochead.clone(),
//                     data.as_bytes().to_vec(),
//                     RecordHint::new(data).expect(line_error!()),
//                     vec![],
//                 )
//                 .await;
//         });
//     }

//     futures::executor::block_on(stronghold.write_all_to_snapshot(&key_data, Some("test2".into()), None));

//     for i in 0..20 {
//         futures::executor::block_on(stronghold.kill_stronghold(format!("test {:?}", i).as_bytes().to_vec(), false));
//     }

//     for i in 0..20 {
//         futures::executor::block_on(stronghold.read_snapshot(
//             format!("test {:?}", i).as_bytes().to_vec(),
//             None,
//             &key_data,
//             Some("test2".into()),
//             None,
//         ));
//     }

//     for i in 0..10 {
//         futures::executor::block_on(async {
//             stronghold
//                 .switch_actor_target(format!("test {:?}", i % 10).as_bytes().to_vec())
//                 .await;

//             let (p, _) = stronghold.read_secret(lochead.clone()).await;

//             let res = format!("test {:?}", i);

//             assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
//         });
//     }
// }

#[test]
fn test_store() {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();
    let payload = b"test data";

    let location = Location::generic("some_data", "location");

    let stronghold = Stronghold::init_stronghold_system(sys, client_path, vec![]);

    futures::executor::block_on(stronghold.write_to_store(location.clone(), payload.to_vec(), None));

    let (res, _) = futures::executor::block_on(stronghold.read_from_store(location));

    assert_eq!(std::str::from_utf8(&res), Ok("test data"));
}

/// ID Tests.
#[test]
fn test_client_id() {
    let path = b"some_path";
    let data = b"a bunch of random data";
    let mut buf = [0; 64];

    let id = ClientId::load_from_path(data, path).unwrap();

    HMAC_SHA512(data, path, &mut buf);

    let (test, _) = buf.split_at(24);

    assert_eq!(ClientId::load(test).unwrap(), id);
}

#[test]
fn test_vault_id() {
    let path = b"another_path_of_data";
    let data = b"a long sentance for seeding the id with some data and bytes.  Testing to see how long this can be without breaking the hmac";
    let mut buf = [0; 64];

    let id = VaultId::load_from_path(data, path).unwrap();

    HMAC_SHA512(data, path, &mut buf);

    let (test, _) = buf.split_at(24);

    assert_eq!(VaultId::load(test).unwrap(), id);
}
