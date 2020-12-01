use engine::vault::{RecordHint, RecordId};

use iota_stronghold::{init_stronghold, line_error, ClientMsg, SHRequest, SHResults, VaultId};

use riker::actors::*;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum InterfaceMsg {
    CreateVault,
    WriteData(usize, Option<usize>, Vec<u8>, RecordHint),
    InitRecord(usize),
    ReadData(usize, Option<usize>),
    RevokeData(usize, usize),
    GarbageCollect(usize),
    ListIds(usize),
    WriteSnapshot(String, Option<String>, Option<PathBuf>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
}

#[derive(Clone, Debug)]
pub struct StartTest {}

#[actor(StartTest, InterfaceMsg)]
pub struct TestActor {}

#[actor(SHResults, InterfaceMsg)]
pub struct MockExternal {
    chan: ChannelRef<SHResults>,
    vaults: Vec<VaultId>,
    records: Vec<Vec<RecordId>>,
}

impl Actor for TestActor {
    type Msg = TestActorMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Actor for MockExternal {
    type Msg = MockExternalMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let sub = Box::new(ctx.myself());
        let topic = Topic::from("external");
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl ActorFactoryArgs<ChannelRef<SHResults>> for MockExternal {
    fn create_args(chan: ChannelRef<SHResults>) -> Self {
        let vaults = Vec::new();
        let records = Vec::new();

        Self { vaults, records, chan }
    }
}

impl ActorFactory for TestActor {
    fn create() -> Self {
        Self {}
    }
}

impl Receive<SHResults> for MockExternal {
    type Msg = MockExternalMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: SHResults, _sender: Sender) {
        match msg {
            SHResults::ReturnCreate(vid, rid) => {
                println!("Create Vault: {:?} with first record: {:?}", vid, rid);
                self.vaults.push(vid);

                self.records.push(vec![rid]);
            }
            SHResults::ReturnInit(vid, rid) => {
                println!("Record {:?} Initialized at {:?} Vault", rid, vid);

                let index = self.vaults.iter().position(|&v| v == vid).expect(line_error!());

                let rids = &mut self.records[index];

                rids.push(rid);
            }
            SHResults::ReturnList(list) => {
                list.iter().for_each(|(rid, hint)| {
                    println!("Record: {:?}, Hint: {:?}", rid, hint);
                });
            }
            SHResults::ReturnRead(data) => {
                println!("Data Output: {}", std::str::from_utf8(&data).expect(line_error!()));
            }
            SHResults::ReturnRebuild(vids, rids) => {
                println!("Read from snapshot and rebuilt table");

                self.vaults.clear();

                self.records.clear();

                let iter = vids.iter().zip(rids.iter());

                for (v, rs) in iter {
                    let mut rids = Vec::new();
                    rs.iter().for_each(|r| {
                        rids.push(*r);
                    });
                    self.vaults.push(*v);
                    self.records.push(rids);
                }
            }
        }
    }
}

impl Receive<InterfaceMsg> for MockExternal {
    type Msg = MockExternalMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: InterfaceMsg, _sender: Sender) {
        match msg {
            InterfaceMsg::CreateVault => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                client.try_tell(ClientMsg::SHRequest(SHRequest::CreateNewVault), None);
            }
            InterfaceMsg::WriteData(vidx, ridx, payload, hint) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let rid = if let Some(ridx) = ridx {
                    let rids = self.records[vidx].clone();

                    Some(rids[ridx])
                } else {
                    None
                };

                let vidx = self.vaults[vidx];

                client.try_tell(
                    ClientMsg::SHRequest(SHRequest::WriteData(vidx, rid, payload, hint)),
                    None,
                );
            }
            InterfaceMsg::InitRecord(vidx) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let vid = self.vaults[vidx];

                client.try_tell(ClientMsg::SHRequest(SHRequest::InitRecord(vid)), None);
            }
            InterfaceMsg::ReadData(vidx, ridx) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let vid = self.vaults[vidx];

                let rid = if let Some(ridx) = ridx {
                    let rids = self.records[vidx].clone();

                    Some(rids[ridx])
                } else {
                    None
                };

                client.try_tell(ClientMsg::SHRequest(SHRequest::ReadData(vid, rid)), None);
            }
            InterfaceMsg::RevokeData(vidx, ridx) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let vid = self.vaults[vidx];

                let rids = self.records[vidx].clone();

                let rid = rids[ridx];

                client.try_tell(ClientMsg::SHRequest(SHRequest::RevokeData(vid, rid)), None);
            }
            InterfaceMsg::GarbageCollect(vidx) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let vid = self.vaults[vidx];

                client.try_tell(ClientMsg::SHRequest(SHRequest::GarbageCollect(vid)), None);
            }
            InterfaceMsg::ListIds(vidx) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                let vid = self.vaults[vidx];

                client.try_tell(ClientMsg::SHRequest(SHRequest::ListIds(vid)), None);
            }
            InterfaceMsg::WriteSnapshot(pass, name, path) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                client.try_tell(ClientMsg::SHRequest(SHRequest::WriteSnapshot(pass, name, path)), None);
            }
            InterfaceMsg::ReadSnapshot(pass, name, path) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                client.try_tell(ClientMsg::SHRequest(SHRequest::ReadSnapshot(pass, name, path)), None);
            }
        }
    }
}

impl Receive<StartTest> for TestActor {
    type Msg = TestActorMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, _msg: StartTest, _sender: Sender) {
        let mock = ctx.select("/user/mock/").expect(line_error!());
        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::CreateVault), None);

        std::thread::sleep(std::time::Duration::from_millis(5));

        mock.try_tell(
            MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                0,
                None,
                b"Some Data".to_vec(),
                RecordHint::new(b"some_hint").expect(line_error!()),
            )),
            None,
        );

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(0, None)), None);
        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ListIds(0)), None);

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::CreateVault), None);

        std::thread::sleep(std::time::Duration::from_millis(5));

        mock.try_tell(
            MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                1,
                None,
                b"Some more data".to_vec(),
                RecordHint::new(b"key_data").expect(line_error!()),
            )),
            None,
        );

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::InitRecord(1)), None);

        std::thread::sleep(std::time::Duration::from_millis(5));

        mock.try_tell(
            MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                1,
                None,
                b"Even more data".to_vec(),
                RecordHint::new(b"password").expect(line_error!()),
            )),
            None,
        );

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, Some(0))), None);
        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, None)), None);

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ListIds(1)), None);
        std::thread::sleep(std::time::Duration::from_millis(5));

        mock.try_tell(
            MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteSnapshot("password".into(), None, None)),
            None,
        );
        std::thread::sleep(std::time::Duration::from_millis(300));

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::RevokeData(1, 0)), None);

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::RevokeData(1, 1)), None);

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::GarbageCollect(1)), None);

        mock.try_tell(
            MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadSnapshot("password".into(), None, None)),
            None,
        );
        std::thread::sleep(std::time::Duration::from_millis(300));

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, None)), None);

        mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, Some(0))), None);
    }
}

impl Receive<InterfaceMsg> for TestActor {
    type Msg = TestActorMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: InterfaceMsg, _sender: Sender) {}
}

fn main() {
    let sys = ActorSystem::new().expect(line_error!());

    let (sys, chan) = init_stronghold(sys);

    sys.actor_of_args::<MockExternal, _>("mock", chan).expect(line_error!());

    let test = sys.sys_actor_of::<TestActor>("test").expect(line_error!());

    test.tell(StartTest {}, None);

    std::thread::sleep(std::time::Duration::from_millis(2000));
}
