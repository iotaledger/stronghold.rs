// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use crate::{hd::Seed, line_error, VaultId};

use engine::vault::{RecordHint, RecordId};

use runtime::zone::soft;

#[derive(Debug, Clone)]
pub enum RMsg {
    Slip10GenerateKey {
        seed: Vec<u8>,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
}

pub struct Runtime {}

// impl ActorFactory for Runtime {
//     fn create() -> Self {
//         Runtime {}
//     }
// }

// impl Actor for Runtime {
//     type Msg = RMsg;

//     fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
//         self.receive(ctx, msg, sender);
//     }
// }

// impl Receive<RMsg> for Runtime {
//     type Msg = RMsg;

//     fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
//         match msg {
//             RMsg::Slip10GenerateKey {
//                 seed,
//                 vault_id,
//                 record_id,
//                 hint: hint,
//             } => {
//                 let (master_key, secret_key) = soft(|| {
//                     let seed = Seed::from_bytes(&seed);

//                     let master_key = seed.to_master_key();

//                     let secret_key = master_key.secret_key().expect(line_error!());

//                     (master_key, secret_key)
//                 })
//                 .expect(line_error!());

//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 let (vid0, rid0, hint0) = master_record;
//                 let (vid1, rid1, hint1) = secret_record;

//                 keystore.try_tell(
//                     InternalMsg::WriteData(vid0, rid0, master_key.chain_code().to_vec(), hint0),
//                     None,
//                 );

//                 keystore.try_tell(
//                     InternalMsg::WriteData(vid1, rid1, secret_key.to_le_bytes().to_vec(), hint1),
//                     None,
//                 )
//             }
//         }
//     }
// }
