use riker::actors::*;

use crate::{actors::KMsg, hd::Seed, line_error, VaultId};

use engine::{
    primitives::rng::SecureRng,
    random::OsRng,
    vault::{RecordHint, RecordId},
};

use runtime::zone::*;

#[derive(Debug, Clone)]
pub enum RMsg {
    Slip10GenerateKey {
        master_record: (VaultId, RecordId, RecordHint),
        secret_record: (VaultId, RecordId, RecordHint),
    },
}

pub struct Runtime {}

impl ActorFactory for Runtime {
    fn create() -> Self {
        Runtime {}
    }
}

impl Actor for Runtime {
    type Msg = RMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<RMsg> for Runtime {
    type Msg = RMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            RMsg::Slip10GenerateKey {
                master_record,
                secret_record,
            } => {
                let (master_key, secret_key) = soft(|| {
                    let mut rng: Vec<u8> = vec![0u8; 64];

                    OsRng.random(&mut rng).expect(line_error!());

                    let seed = Seed::from_bytes(&rng);

                    let master_key = seed.to_master_key();

                    let secret_key = master_key.secret_key().expect(line_error!());

                    (master_key, secret_key)
                })
                .expect(line_error!());

                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                let (vid0, rid0, hint0) = master_record;
                let (vid1, rid1, hint1) = secret_record;

                keystore.try_tell(
                    KMsg::WriteData(vid0, rid0, master_key.chain_code().to_vec(), hint0),
                    None,
                );

                keystore.try_tell(
                    KMsg::WriteData(vid1, rid1, secret_key.to_le_bytes().to_vec(), hint1),
                    None,
                )
            }
        }
    }
}
