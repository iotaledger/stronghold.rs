// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::{
    channel::{mpsc, oneshot},
    future::{join, poll_fn},
    prelude::*,
    FutureExt,
};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use p2p::{
    firewall::{
        permissions::{FirewallPermission, PermissionValue, RequestPermissions, VariantPermission},
        FirewallRequest, FirewallRules, FwRequest, Rule, RuleDirection,
    },
    ChannelSinkConfig, EventChannel, InboundFailure, NetworkEvent, OutboundFailure, PeerId, ReceiveRequest,
    RequestDirection, StrongholdP2p, StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
use std::{fmt, future, marker::PhantomData, sync::Arc, task::Poll, time::Duration};
use stronghold_utils::random::random;
use tokio::time::sleep;

type TestPeer = StrongholdP2p<Request, Response, RequestPermission>;

macro_rules! expect_ok (
     ($expression:expr, $config:expr) => {
        $expression.await.expect(&format!("Unexpected Error on unwrap; config: {}", $config))
    };
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Request {
    Ping,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Response {
    Pong,
    Other,
}

type NewPeer = (
    mpsc::Receiver<FirewallRequest<RequestPermission>>,
    mpsc::Receiver<ReceiveRequest<Request, Response>>,
    mpsc::Receiver<NetworkEvent>,
    TestPeer,
);

async fn init_peer() -> NewPeer {
    let (firewall_tx, firewall_rx) = mpsc::channel(10);
    let (request_channel, rq_rx) = EventChannel::new(10, ChannelSinkConfig::Block);
    let (event_channel, event_rx) = EventChannel::new(10, ChannelSinkConfig::Block);
    let builder = StrongholdP2pBuilder::<Request, Response, RequestPermission>::new(
        firewall_tx,
        request_channel,
        Some(event_channel),
    );
    #[cfg(not(feature = "tcp-transport"))]
    let peer = {
        let executor = |fut| {
            tokio::spawn(fut);
        };
        builder
            .build_with_transport(TokioTcpConfig::new(), executor)
            .await
            .unwrap()
    };
    #[cfg(feature = "tcp-transport")]
    let peer = builder.build().await.unwrap();
    (firewall_rx, rq_rx, event_rx, peer)
}

#[derive(Debug, Clone)]
enum TestPermission {
    AllowAll,
    RejectAll,
    Restricted(RequestPermission),
}

impl TestPermission {
    fn random() -> Self {
        match random::<u8>() % 4 {
            0 => TestPermission::AllowAll,
            1 => TestPermission::RejectAll,
            2 => TestPermission::Restricted(RequestPermission::Ping),
            3 => TestPermission::Restricted(RequestPermission::Other),
            _ => unreachable!(),
        }
    }

    fn restrict_by_type(rq: &RequestPermission, allowed: RequestPermission) -> bool {
        let permissions = FirewallPermission::none().add_permissions([&allowed.permission()]);
        permissions.permits(&rq.permission())
    }

    fn as_rule(&self) -> Rule<RequestPermission> {
        match self {
            TestPermission::AllowAll => Rule::AllowAll,
            TestPermission::RejectAll => Rule::RejectAll,
            TestPermission::Restricted(permission) => {
                let permission = permission.clone();
                Rule::Restricted {
                    restriction: Arc::new(move |rq: &RequestPermission| Self::restrict_by_type(rq, permission.clone())),
                    _maker: PhantomData,
                }
            }
        }
    }
}

struct RulesTestConfig<'a> {
    peer_a: &'a mut TestPeer,
    peer_b: &'a mut TestPeer,
    b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
    b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,

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
            "\n[Peer A Config] default: {:?}, peer b rule: {:?}\n[Peer B Config] default: {:?}, peer a rule: {:?}\nRequest: {:?}\n",
            self.a_default,
            self.a_rule,
            self.b_default,
            self.b_rule,
            self.req
        )
    }
}

impl<'a> RulesTestConfig<'a> {
    fn new_test_case(
        peer_a: &'a mut TestPeer,
        peer_b: &'a mut TestPeer,
        b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
        b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ) -> Self {
        let a_rule = (random::<u8>() % 2 > 0).then(TestPermission::random);
        let b_rule = (random::<u8>() % 2 > 0).then(TestPermission::random);
        let req = (random::<u8>() % 2 > 0)
            .then(|| Request::Ping)
            .unwrap_or(Request::Other);
        RulesTestConfig {
            peer_a,
            peer_b,
            b_events_rx,
            b_request_rx,
            a_default: TestPermission::random(),
            a_rule,
            b_default: TestPermission::random(),
            b_rule,
            req,
        }
    }

    async fn configure_firewall(&mut self) {
        let peer_a_id = self.peer_a.peer_id();
        let peer_b_id = self.peer_b.peer_id();
        if let Some(peer_rule) = self.b_rule.as_ref() {
            self.peer_b
                .set_peer_rule(peer_a_id, RuleDirection::Inbound, peer_rule.as_rule())
                .await;
        }
        self.peer_b
            .set_firewall_default(RuleDirection::Inbound, self.b_default.as_rule())
            .await;
        if let Some(peer_rule) = self.a_rule.as_ref() {
            self.peer_a
                .set_peer_rule(peer_b_id, RuleDirection::Outbound, peer_rule.as_rule())
                .await;
        }
        self.peer_a
            .set_firewall_default(RuleDirection::Outbound, self.a_default.as_rule())
            .await;
    }

    async fn test_request(&mut self) {
        let peer_a_id = self.peer_a.peer_id();
        let peer_b_id = self.peer_b.peer_id();

        let mut peer_a = self.peer_a.clone();
        let res_future = peer_a.send_request(peer_b_id, self.req.clone()).boxed();

        let a_rule = self.a_rule.as_ref().unwrap_or(&self.a_default);
        let b_rule = self.b_rule.as_ref().unwrap_or(&self.b_default);
        let req = self.req.clone();
        let is_allowed = |rule: &TestPermission| match rule {
            TestPermission::AllowAll => true,
            TestPermission::RejectAll => false,
            TestPermission::Restricted(RequestPermission::Ping) => matches!(req, Request::Ping),
            TestPermission::Restricted(RequestPermission::Other) => matches!(req, Request::Other),
        };
        if !is_allowed(a_rule) {
            let res = res_future.await;
            assert_eq!(
                res,
                Err(OutboundFailure::NotPermitted),
                "Unexpected Result {:?}; config {}",
                res,
                self
            );
        } else if !is_allowed(b_rule) {
            match b_rule {
                TestPermission::RejectAll => match res_future.await {
                    Ok(_) => panic!("Unexpected response; config {}", self),
                    Err(OutboundFailure::UnsupportedProtocols) | Err(OutboundFailure::ConnectionClosed) => {}
                    Err(e) => panic!("Unexpected Failure {:?}; config {}", e, self),
                },
                TestPermission::Restricted(_) => {
                    match res_future.await {
                        Ok(_) => panic!("Unexpected response; config {}", self),
                        Err(OutboundFailure::Timeout) | Err(OutboundFailure::ConnectionClosed) => {}
                        Err(e) => panic!("Unexpected Failure {:?}; config {}", e, self),
                    }
                    self.expect_b_inbound_reject(peer_a_id).await;
                }
                _ => unreachable!(),
            }
        } else {
            let config_str = format!("{}", self);
            let source_fut = async {
                res_future
                    .await
                    .unwrap_or_else(|err| panic!("Unexpected outbound failure {:?}; config {}", err, config_str));
            };
            let dst_fut = async {
                let ReceiveRequest {
                    peer,
                    request,
                    response_tx,
                    ..
                } = self.b_request_rx.select_next_some().await;
                assert_eq!(peer, peer_a_id);
                assert_eq!(request, self.req);
                response_tx.send(Response::Pong).unwrap();
            };
            join(source_fut, dst_fut).await;
        }
    }

    async fn expect_b_inbound_reject(&mut self, remote: PeerId) {
        let mut filtered = self.b_events_rx.filter(|ev| {
            future::ready(!matches!(
                ev,
                NetworkEvent::ConnectionEstablished { .. }
                    | NetworkEvent::ConnectionClosed { .. }
                    | NetworkEvent::NewListenAddr(..)
            ))
        });
        match expect_ok!(filtered.next(), self) {
            NetworkEvent::InboundFailure {
                peer,
                failure: InboundFailure::NotPermitted,
                ..
            } => {
                assert_eq!(peer, remote);
            }
            other => panic!("Unexpected Result: {:?}; config: {}", other, self),
        }
    }

    async fn clean(self) {
        let peer_a_id = self.peer_a.peer_id();
        let peer_b_id = self.peer_b.peer_id();
        self.peer_b.remove_peer_rule(peer_a_id, RuleDirection::Both).await;
        self.peer_b.remove_firewall_default(RuleDirection::Both).await;
        self.peer_a.remove_peer_rule(peer_b_id, RuleDirection::Both).await;
        self.peer_a.remove_firewall_default(RuleDirection::Both).await;
    }
}

#[tokio::test]
async fn firewall_permissions() {
    let iterations = 100;
    let run_test = async {
        let (_, _, _, mut peer_a) = init_peer().await;
        let (_, mut b_rq_rx, mut b_event_rx, mut peer_b) = init_peer().await;
        let peer_b_id = peer_b.peer_id();

        let peer_b_addr = peer_b
            .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .await
            .unwrap();
        peer_a.add_address(peer_b_id, peer_b_addr).await;

        for _ in 0..iterations {
            let mut test = RulesTestConfig::new_test_case(&mut peer_a, &mut peer_b, &mut b_event_rx, &mut b_rq_rx);
            test.configure_firewall().await;
            sleep(Duration::from_millis(10)).await;
            test.test_request().await;
            test.clean().await;
        }
    };

    futures::select! {
        _ = run_test.fuse() => {},
        _ = sleep(Duration::from_secs(iterations)).fuse() => panic!("Test timed out"),
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
        match random::<u8>() % 6 {
            0 | 1 => FwRuleRes::AllowAll,
            2 => FwRuleRes::RejectAll,
            3 | 4 => FwRuleRes::Ask,
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
        match random::<u8>() % 4 {
            0 | 1 => FwApprovalRes::Allow,
            2 => FwApprovalRes::Reject,
            3 => FwApprovalRes::Drop,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum Peer {
    A,
    B,
}

struct AskTestConfig<'a> {
    peer_a: &'a mut TestPeer,
    firewall_a: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,

    peer_b: &'a mut TestPeer,
    firewall_b: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,
    b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
    b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,

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
        peer_a: &'a mut TestPeer,
        firewall_a: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,
        peer_b: &'a mut TestPeer,
        firewall_b: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,
        b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
        b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ) -> Self {
        AskTestConfig {
            peer_a,
            firewall_a,
            peer_b,
            firewall_b,
            b_events_rx,
            b_request_rx,
            a_rule: FwRuleRes::random(),
            a_approval: FwApprovalRes::random(),
            b_rule: FwRuleRes::random(),
            b_approval: FwApprovalRes::random(),
        }
    }

    async fn test_request_with_ask(&mut self) {
        let peer_a_id = self.peer_a.peer_id();
        let peer_b_id = self.peer_b.peer_id();

        let is_allowed = |rule: &FwRuleRes, approval: &FwApprovalRes| match rule {
            FwRuleRes::AllowAll => true,
            FwRuleRes::Drop | FwRuleRes::RejectAll => false,
            FwRuleRes::Ask if matches!(approval, FwApprovalRes::Allow) => true,
            _ => false,
        };

        let mut peer_a = self.peer_a.clone();
        let (tx_res, mut rx_res) = oneshot::channel();

        let operation_future = async {
            let res = peer_a.send_request(peer_b_id, Request::Ping).await;
            tx_res.send(res).unwrap();
        };

        let resolved = async {
            self.firewall_handle_next(Peer::A).await;

            if !is_allowed(&self.a_rule, &self.a_approval) {
                let res = rx_res
                    .await
                    .unwrap()
                    .expect_err(&format!("Unexpected response; config {}", self));
                assert_eq!(
                    res,
                    OutboundFailure::NotPermitted,
                    "Unexpected outbound failure {:?}; config {}",
                    res,
                    self
                );
                return;
            }

            self.firewall_handle_next(Peer::B).await;

            if !is_allowed(&self.b_rule, &self.b_approval) {
                let res = poll_fn(|cx| {
                    match rx_res.poll_unpin(cx) {
                        Poll::Ready(Ok(Err(err))) => return Poll::Ready(err),
                        Poll::Ready(Ok(Ok(_))) => panic!("Unexpected response; config {}", self),
                        Poll::Ready(Err(_)) => unreachable!(),
                        _ => {}
                    }
                    if matches!(self.b_rule, FwRuleRes::Drop) {
                        match self.firewall_b.poll_next_unpin(cx) {
                            Poll::Ready(Some(FirewallRequest::PeerSpecificRule { rule_tx, .. })) => drop(rule_tx),
                            Poll::Ready(Some(_)) => panic!(
                                "Unexpected RequestApproval after PeerSpecificRule was dropped; config {}",
                                self
                            ),
                            Poll::Ready(None) => panic!("Unexpected firewall channel closed; config {}", self),
                            _ => {}
                        }
                    }
                    Poll::Pending
                })
                .await;

                match res {
                    OutboundFailure::Timeout | OutboundFailure::ConnectionClosed => {
                        self.expect_b_inbound_reject(peer_a_id).await;
                    }
                    OutboundFailure::UnsupportedProtocols if matches!(self.b_rule, FwRuleRes::RejectAll) => {}
                    other => panic!("Unexpected outbound failure {:?}; config: {}", other, self),
                }
                return;
            }

            let ReceiveRequest { peer, response_tx, .. } = self.b_request_rx.select_next_some().await;
            assert_eq!(peer, peer_a_id);
            response_tx.send(Response::Pong).unwrap();
            rx_res
                .await
                .unwrap()
                .unwrap_or_else(|err| panic!("Unexpected outbound failure {:?}; config {}", err, self));
        };
        join(operation_future, resolved).await;
    }

    async fn expect_b_inbound_reject(&mut self, remote: PeerId) {
        let mut filtered = self.b_events_rx.filter(|ev| {
            future::ready(!matches!(
                ev,
                NetworkEvent::ConnectionEstablished { .. }
                    | NetworkEvent::ConnectionClosed { .. }
                    | NetworkEvent::NewListenAddr(..)
            ))
        });
        match expect_ok!(filtered.next(), self) {
            NetworkEvent::InboundFailure {
                peer,
                failure: InboundFailure::NotPermitted,
                ..
            } => {
                assert_eq!(peer, remote);
            }
            other => panic!("Unexpected Result: {:?}; config: {}", other, self),
        }
    }

    async fn firewall_handle_next(&mut self, test_peer: Peer) {
        let config = format!("{}", self);
        let (fw_channel, peer_rule, approval) = match test_peer {
            Peer::A => (&mut self.firewall_a, &self.a_rule, &self.a_approval),
            Peer::B => (&mut self.firewall_b, &self.b_rule, &self.b_approval),
        };
        let response_tx = match expect_ok!(fw_channel.next(), config) {
            FirewallRequest::PeerSpecificRule { rule_tx, .. } => rule_tx,
            _ => panic!("Unexpected RequestApproval before PeerSpecificRule"),
        };

        let (rule, other) = match peer_rule {
            FwRuleRes::AllowAll => (Rule::AllowAll, Rule::RejectAll),
            FwRuleRes::RejectAll => (Rule::RejectAll, Rule::AllowAll),
            FwRuleRes::Ask => match approval {
                FwApprovalRes::Allow => (Rule::Ask, Rule::RejectAll),
                _ => (Rule::Ask, Rule::AllowAll),
            },
            FwRuleRes::Drop => {
                drop(response_tx);
                return;
            }
        };
        let (inbound, outbound) = match test_peer {
            Peer::A => (other, rule),
            Peer::B => (rule, other),
        };

        response_tx
            .send(FirewallRules::new(Some(inbound), Some(outbound)))
            .unwrap_or_else(|_| panic!("Error on unwrap; config: {}", config));

        if matches!(peer_rule, FwRuleRes::Ask) {
            let response_tx = match expect_ok!(fw_channel.next(), self) {
                FirewallRequest::RequestApproval {
                    approval_tx, direction, ..
                } => {
                    match test_peer {
                        Peer::A => assert_eq!(direction, RequestDirection::Outbound),
                        Peer::B => assert_eq!(direction, RequestDirection::Inbound),
                    }
                    approval_tx
                }
                _ => panic!("Unexpected double PeerRuleQuery"),
            };

            let res = match approval {
                FwApprovalRes::Allow => true,
                FwApprovalRes::Reject => false,
                FwApprovalRes::Drop => {
                    drop(response_tx);
                    return;
                }
            };
            response_tx
                .send(res)
                .unwrap_or_else(|_| panic!("Error on unwrap; config: {}", self));
        }
    }

    async fn clean(self) {
        let peer_a_id = self.peer_a.peer_id();
        let peer_b_id = self.peer_b.peer_id();
        self.peer_a.remove_peer_rule(peer_b_id, RuleDirection::Both).await;
        self.peer_b.remove_peer_rule(peer_a_id, RuleDirection::Both).await;
    }
}

#[tokio::test]
async fn firewall_ask() {
    let iterations = 100;
    let run_test = async {
        let (mut firewall_a, _, _, mut peer_a) = init_peer().await;
        let (mut firewall_b, mut b_rq_rx, mut b_event_rx, mut peer_b) = init_peer().await;

        // Firewall should have no rules per default and ask each time a peer connects.
        peer_a.remove_firewall_default(RuleDirection::Both).await;
        peer_b.remove_firewall_default(RuleDirection::Both).await;

        let peer_b_id = peer_b.peer_id();
        let peer_b_addr = peer_b
            .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .await
            .unwrap();

        peer_a.add_address(peer_b_id, peer_b_addr).await;

        for _ in 0..iterations {
            let mut test = AskTestConfig::new_test_case(
                &mut peer_a,
                &mut firewall_a,
                &mut peer_b,
                &mut firewall_b,
                &mut b_event_rx,
                &mut b_rq_rx,
            );
            test.test_request_with_ask().await;
            test.clean().await;
            sleep(Duration::from_millis(10)).await;
        }
    };

    futures::select! {
        _ = run_test.fuse() => {},
        _ = sleep(Duration::from_secs(iterations)).fuse() => panic!("Test timed out"),
    }
}
