// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use communication_refactored::{
    firewall::{
        FirewallPermission, FirewallRequest, FirewallRules, PermissionValue, RequestPermissions, Rule, RuleDirection,
        ToPermissionVariants, VariantPermission,
    },
    BehaviourEvent, NetBehaviour, NetBehaviourConfig, Query, RecvResponseErr, RequestDirection,
};
use futures::{
    channel::mpsc::{self, Receiver},
    executor::LocalPool,
    stream::StreamExt,
    FutureExt,
};
use libp2p::{
    core::{identity, transport::Transport, upgrade, PeerId},
    mdns::{Mdns, MdnsConfig},
    noise::{Keypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
    Multiaddr,
};
use serde::{Deserialize, Serialize};

type TestSwarm = Swarm<NetBehaviour<Request, Response, RequestPermission>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Request {
    Ping,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Response {
    Pong,
    Other,
}

fn init_swarm(
    pool: &mut LocalPool,
    default_in: Option<Rule>,
    default_out: Option<Rule>,
) -> (PeerId, TestSwarm, mpsc::Receiver<FirewallRequest<RequestPermission>>) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer = id_keys.public().into_peer_id();
    let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
    let (relay_transport, relay_behaviour) =
        new_transport_and_behaviour(RelayConfig::default(), TcpConfig::new().nodelay(true));
    let transport = relay_transport
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(YamuxConfig::default())
        .boxed();

    let mut cfg = NetBehaviourConfig::default();
    if let Some(default_in) = default_in {
        cfg.firewall.set_default(default_in, RuleDirection::Inbound);
    }
    if let Some(default_out) = default_out {
        cfg.firewall.set_default(default_out, RuleDirection::Outbound);
    }
    let mdns = pool
        .run_until(Mdns::new(MdnsConfig::default()))
        .expect("Failed to create mdns behaviour.");
    let (firewall_sender, firewall_receiver) = mpsc::channel(1);
    let behaviour = NetBehaviour::new(cfg, mdns, relay_behaviour, firewall_sender);
    let swarm = Swarm::new(transport, behaviour, peer);
    (peer, swarm, firewall_receiver)
}

fn start_listening(pool: &mut LocalPool, swarm: &mut TestSwarm) -> Multiaddr {
    let addr = "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress.");
    swarm.listen_on(addr).unwrap();
    match pool.run_until(swarm.next_event()) {
        SwarmEvent::NewListenAddr(addr) => addr,
        other => panic!("Unexepected event: {:?}", other),
    }
}

#[derive(Debug)]
enum TestPermission {
    All,
    None,
    PingOnly,
    OtherOnly,
}

impl TestPermission {
    fn random() -> Self {
        match rand::random::<u8>() % 4 {
            0 => TestPermission::All,
            1 => TestPermission::None,
            2 => TestPermission::PingOnly,
            3 => TestPermission::OtherOnly,
            _ => unreachable!(),
        }
    }

    fn as_rule(&self) -> Rule {
        match self {
            TestPermission::All => Rule::allow_all(),
            TestPermission::None => Rule::reject_all(),
            TestPermission::PingOnly => {
                let permission = RequestPermission::Ping;
                Rule::Permission(FirewallPermission::none().add_permission(&permission.permission()))
            }
            TestPermission::OtherOnly => {
                let permission = RequestPermission::Other;
                Rule::Permission(FirewallPermission::none().add_permission(&permission.permission()))
            }
        }
    }
}

struct RulesTestConfig<'a> {
    swarm_a: &'a mut TestSwarm,
    peer_a_id: PeerId,
    swarm_b: &'a mut TestSwarm,
    peer_b_id: PeerId,

    a_default: TestPermission,
    a_rule: Option<TestPermission>,
    b_default: TestPermission,
    b_rule: Option<TestPermission>,
    req: Request,
}

impl<'a> fmt::Display for RulesTestConfig<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n\n[Peer A]:\n[Test Config] default: {:?}, rule: {:?}\n[Actual Firewall Rules]:
            default: {:?},
            peer b rule: {:?}\n[Peer B]:\n[Test Config] default: {:?}, rule: {:?}\n[Actual Firewall Rules]:
            default: {:?},
            peer a rule: {:?}\nRequest: {:?}\n\n",
            self.a_default,
            self.a_rule,
            self.swarm_a.behaviour().get_firewall_default(),
            self.swarm_a.behaviour().get_peer_rules(&self.peer_b_id),
            self.b_default,
            self.b_rule,
            self.swarm_b.behaviour().get_firewall_default(),
            self.swarm_b.behaviour().get_peer_rules(&self.peer_a_id),
            self.req
        )
    }
}

impl<'a> RulesTestConfig<'a> {
    fn new_test_case(
        swarm_a: &'a mut TestSwarm,
        peer_a_id: PeerId,
        swarm_b: &'a mut TestSwarm,
        peer_b_id: PeerId,
    ) -> Self {
        let a_rule = (rand::random::<u8>() % 2 > 0).then(TestPermission::random);
        let b_rule = (rand::random::<u8>() % 2 > 0).then(TestPermission::random);
        let req = (rand::random::<u8>() % 2 > 0)
            .then(|| Request::Ping)
            .unwrap_or(Request::Other);
        RulesTestConfig {
            swarm_a,
            peer_a_id,
            swarm_b,
            peer_b_id,
            a_default: TestPermission::random(),
            a_rule,
            b_default: TestPermission::random(),
            b_rule,
            req,
        }
    }

    fn configure_firewall(&mut self) {
        self.swarm_a
            .behaviour_mut()
            .set_firewall_default(RuleDirection::Outbound, self.a_default.as_rule());
        if let Some(peer_rule) = self.a_rule.as_ref() {
            self.swarm_a
                .behaviour_mut()
                .set_peer_rule(self.peer_b_id, RuleDirection::Outbound, peer_rule.as_rule());
        } else {
            self.swarm_a
                .behaviour_mut()
                .remove_peer_rule(self.peer_b_id, RuleDirection::Both)
        }
        self.swarm_b
            .behaviour_mut()
            .set_firewall_default(RuleDirection::Inbound, self.b_default.as_rule());
        if let Some(peer_rule) = self.b_rule.as_ref() {
            self.swarm_b
                .behaviour_mut()
                .set_peer_rule(self.peer_a_id, RuleDirection::Inbound, peer_rule.as_rule());
        } else {
            self.swarm_b
                .behaviour_mut()
                .remove_peer_rule(self.peer_a_id, RuleDirection::Both)
        }
    }

    fn test_request(self, pool: &mut LocalPool) {
        let response_recv = self
            .swarm_a
            .behaviour_mut()
            .send_request(self.peer_b_id, self.req.clone());
        assert_eq!(response_recv.peer, self.peer_b_id);
        pool.run_until(async {
            loop {
                futures::select_biased!(
                    event = self.swarm_b.next().fuse() => match event {
                        BehaviourEvent::ReceiveRequest {peer, request, ..} => {
                            assert_eq!(peer, self.peer_a_id);
                            request.response_sender.send(Response::Pong).unwrap();
                        },
                        other => panic!("Unexepected event: {:?}", other)
                    },
                    event = self.swarm_a.next().fuse() => match event {
                        BehaviourEvent::ReceiveResponse { result, peer, request_id} => {
                            assert_eq!(peer, self.peer_b_id);
                            assert_eq!(request_id, response_recv.request_id);
                            assert_eq!(result.is_ok(), response_recv.receiver.await.is_ok());
                            return self.assert_expected_res(result);
                        },
                        other => panic!("Unexepected event: {:?}", other)
                    },
                )
            }
        })
    }

    fn assert_expected_res(self, res: Result<(), RecvResponseErr>) {
        let a_rule = self.a_rule.as_ref().unwrap_or(&self.a_default);
        let b_rule = self.b_rule.as_ref().unwrap_or(&self.b_default);
        let is_alowed = |rule: &TestPermission| match rule {
            TestPermission::All => true,
            TestPermission::None => false,
            TestPermission::PingOnly => matches!(self.req, Request::Ping),
            TestPermission::OtherOnly => matches!(self.req, Request::Other),
        };

        if !is_alowed(a_rule) {
            assert_eq!(res, Err(RecvResponseErr::NotPermitted), "Failed on config: {}", self);
        } else if !is_alowed(b_rule) {
            match res {
                Err(RecvResponseErr::UnsupportedProtocols) | Err(RecvResponseErr::ConnectionClosed) => {}
                other => panic!("Unexpected Result: {:?},\nconfig: {}", other, self),
            }
        } else {
            res.unwrap_or_else(|e| panic!("Unexpected rejection {:?} on config: {}", e, self));
        }
    }
}

#[test]
fn firewall_permissions() {
    let mut pool = LocalPool::new();

    // reject outbound requests for A
    let (peer_a_id, mut swarm_a, _) = init_swarm(&mut pool, None, Some(Rule::reject_all()));
    // reject inbound request for B
    let (peer_b_id, mut swarm_b, _) = init_swarm(&mut pool, Some(Rule::reject_all()), None);

    let peer_b_addr = start_listening(&mut pool, &mut swarm_b);
    swarm_a.behaviour_mut().add_address(peer_b_id, peer_b_addr);

    for _ in 0..100 {
        let mut test = RulesTestConfig::new_test_case(&mut swarm_a, peer_a_id, &mut swarm_b, peer_b_id);
        test.configure_firewall();
        test.test_request(&mut pool);
    }
}

#[derive(Debug)]
enum FwRuleRes {
    AllowAll,
    RejectAll,
    Ask,
    Drop,
}

impl FwRuleRes {
    fn random() -> Self {
        match rand::random::<u8>() % 6 {
            0 | 1 | 2 => FwRuleRes::AllowAll,
            3 => FwRuleRes::RejectAll,
            4 => FwRuleRes::Ask,
            5 => FwRuleRes::Drop,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum FwApprovalRes {
    Allow,
    Reject,
    Drop,
}

impl FwApprovalRes {
    fn random() -> Self {
        match rand::random::<u8>() % 4 {
            0 | 1 => FwApprovalRes::Allow,
            2 => FwApprovalRes::Reject,
            3 => FwApprovalRes::Drop,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum TestPeer {
    A,
    B,
}

struct AskTestConfig<'a> {
    swarm_a: &'a mut TestSwarm,
    peer_a_id: PeerId,
    firewall_a: &'a mut Receiver<FirewallRequest<RequestPermission>>,
    swarm_b: &'a mut TestSwarm,
    peer_b_id: PeerId,
    firewall_b: &'a mut Receiver<FirewallRequest<RequestPermission>>,
    a_rule: FwRuleRes,
    a_approval: FwApprovalRes,
    b_rule: FwRuleRes,
    b_approval: FwApprovalRes,
}

impl<'a> fmt::Display for AskTestConfig<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n[Peer A] rule: {:?}, approval: {:?};\n[Peer B] rule: {:?}, approval: {:?}\n",
            self.a_rule, self.a_approval, self.b_rule, self.b_approval
        )
    }
}

impl<'a> AskTestConfig<'a> {
    fn new_test_case(
        swarm_a: &'a mut TestSwarm,
        peer_a_id: PeerId,
        firewall_a: &'a mut Receiver<FirewallRequest<RequestPermission>>,
        swarm_b: &'a mut TestSwarm,
        peer_b_id: PeerId,
        firewall_b: &'a mut Receiver<FirewallRequest<RequestPermission>>,
    ) -> Self {
        AskTestConfig {
            swarm_a,
            peer_a_id,
            firewall_a,
            swarm_b,
            peer_b_id,
            firewall_b,
            a_rule: FwRuleRes::random(),
            a_approval: FwApprovalRes::random(),
            b_rule: FwRuleRes::random(),
            b_approval: FwApprovalRes::random(),
        }
    }

    fn test_request_with_ask(&mut self, pool: &mut LocalPool) {
        let response_recv = self.swarm_a.behaviour_mut().send_request(self.peer_b_id, Request::Ping);
        pool.run_until(async {
            loop {
                futures::select!(
                    event = self.swarm_a.next().fuse() => match event {
                        BehaviourEvent::ReceiveResponse { result, ..} => {
                            assert_eq!(result.is_ok(), response_recv.receiver.await.is_ok());
                            self.assert_expected_res(result);
                            break;
                        },
                        other => panic!("Unexepected event: {:?}", other)
                    },
                    event = self.swarm_b.next().fuse() => match event {
                        BehaviourEvent::ReceiveRequest {request, ..} => request.response_sender.send(Response::Pong).unwrap(),
                        other => panic!("Unexepected event: {:?}", other)
                    },
                    req = self.firewall_a.next() => self.firewall_handle_ask(req.unwrap(), TestPeer::A),
                    req = self.firewall_b.next() => self.firewall_handle_ask(req.unwrap(), TestPeer::B)
                )
            }
        })
    }

    fn firewall_handle_ask(&self, req: FirewallRequest<RequestPermission>, test_peer: TestPeer) {
        let (peer_rule, approval) = match test_peer {
            TestPeer::A => (&self.a_rule, &self.a_approval),
            TestPeer::B => (&self.b_rule, &self.b_approval),
        };
        match req {
            FirewallRequest::PeerSpecificRule(Query { response_sender, .. }) => {
                let (rule, other) = match peer_rule {
                    FwRuleRes::AllowAll => (Rule::allow_all(), Rule::reject_all()),
                    FwRuleRes::RejectAll => (Rule::reject_all(), Rule::allow_all()),
                    FwRuleRes::Ask => match approval {
                        FwApprovalRes::Allow => (Rule::Ask, Rule::reject_all()),
                        _ => (Rule::Ask, Rule::allow_all()),
                    },
                    FwRuleRes::Drop => {
                        drop(response_sender);
                        return;
                    }
                };

                let (inbound, outbound) = match test_peer {
                    TestPeer::A => (other, rule),
                    TestPeer::B => (rule, other),
                };
                response_sender
                    .send(FirewallRules::new(Some(inbound), Some(outbound)))
                    .unwrap();
            }
            FirewallRequest::RequestApproval(Query {
                response_sender,
                request: (_, dir, _),
                ..
            }) => {
                match test_peer {
                    TestPeer::A => assert_eq!(dir, RequestDirection::Outbound),
                    TestPeer::B => assert_eq!(dir, RequestDirection::Inbound),
                }
                if !matches!(peer_rule, FwRuleRes::Ask) {
                    panic!(
                        "Unexpected Request for approval, Peer: {:?}, config: {}.",
                        test_peer, self
                    );
                }
                let res = match approval {
                    FwApprovalRes::Allow => true,
                    FwApprovalRes::Reject => false,
                    FwApprovalRes::Drop => {
                        drop(response_sender);
                        return;
                    }
                };
                response_sender.send(res).unwrap();
            }
        }
    }

    fn assert_expected_res(&self, res: Result<(), RecvResponseErr>) {
        let is_allowed = |rule: &FwRuleRes, approval: &FwApprovalRes| match rule {
            FwRuleRes::AllowAll => true,
            FwRuleRes::Drop | FwRuleRes::RejectAll => false,
            FwRuleRes::Ask if matches!(approval, FwApprovalRes::Allow) => true,
            _ => false,
        };

        if !is_allowed(&self.a_rule, &self.a_approval) {
            assert_eq!(res, Err(RecvResponseErr::NotPermitted), "Failed on config: {}", self);
        } else if !is_allowed(&self.b_rule, &self.b_approval) {
            match res {
                Err(RecvResponseErr::UnsupportedProtocols) | Err(RecvResponseErr::ConnectionClosed) => {}
                other => panic!("Unexpected Result: {:?},\nconfig: {}", other, self),
            }
        } else {
            res.unwrap_or_else(|e| panic!("Unexpected rejection {:?} on config: {}", e, self));
        }
    }

    fn clean(self) {
        self.swarm_a
            .behaviour_mut()
            .remove_peer_rule(self.peer_b_id, RuleDirection::Both);
        self.swarm_b
            .behaviour_mut()
            .remove_peer_rule(self.peer_a_id, RuleDirection::Both);
    }
}

#[test]
fn firewall_ask() {
    let mut pool = LocalPool::new();

    // reject outbound requests for A
    let (peer_a_id, mut swarm_a, mut firewall_a) = init_swarm(&mut pool, None, None);
    // reject inbound request for B
    let (peer_b_id, mut swarm_b, mut firewall_b) = init_swarm(&mut pool, None, None);

    let peer_b_addr = start_listening(&mut pool, &mut swarm_b);
    swarm_a.behaviour_mut().add_address(peer_b_id, peer_b_addr);

    for _ in 0..100 {
        let mut test = AskTestConfig::new_test_case(
            &mut swarm_a,
            peer_a_id,
            &mut firewall_a,
            &mut swarm_b,
            peer_b_id,
            &mut firewall_b,
        );
        test.test_request_with_ask(&mut pool);
        test.clean();
    }
}
