// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication_refactored::{
    firewall::{
        FirewallPermission, FirewallRequest, FirewallRules, PeerRuleQuery, PermissionValue, RequestApprovalQuery,
        RequestPermissions, Rule, RuleDirection, ToPermissionVariants, VariantPermission,
    },
    InboundFailure, NetworkEvent, OutboundFailure, PeerId, ReceiveRequest, RequestDirection, ShCommunication,
    ShCommunicationBuilder,
};
use futures::{
    channel::{mpsc, oneshot},
    future::{join, poll_fn},
    prelude::*,
    FutureExt,
};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use serde::{Deserialize, Serialize};
use std::{fmt, future, task::Poll, time::Duration};
use tokio::time::sleep;

type TestComms = ShCommunication<Request, Response, RequestPermission>;

macro_rules! expect_ok (
     ($expression:expr, $config:expr) => {
        $expression.await.expect(&format!("Unexpected Error on unwrap; config: {}", $config));
    };
);

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

type NewComms = (
    mpsc::Receiver<FirewallRequest<RequestPermission>>,
    mpsc::Receiver<ReceiveRequest<Request, Response>>,
    mpsc::Receiver<NetworkEvent>,
    ShCommunication<Request, Response, RequestPermission>,
);

async fn init_comms() -> NewComms {
    let (firewall_tx, firewall_rx) = mpsc::channel(10);
    let (rq_tx, rq_rx) = mpsc::channel(10);
    let (event_tx, event_rx) = mpsc::channel(10);
    let builder = ShCommunicationBuilder::new(firewall_tx, rq_tx, Some(event_tx));
    #[cfg(not(feature = "tcp-transport"))]
    let comms = builder.build_with_transport(TokioTcpConfig::new()).await;
    #[cfg(feature = "tcp-transport")]
    let comms = builder.build().await.unwrap();
    (firewall_rx, rq_rx, event_rx, comms)
}

#[derive(Debug, Clone, Copy)]
enum TestPermission {
    AllowAll,
    RejectAll,
    PingOnly,
    OtherOnly,
}

impl TestPermission {
    fn random() -> Self {
        match rand::random::<u8>() % 4 {
            0 => TestPermission::AllowAll,
            1 => TestPermission::RejectAll,
            2 => TestPermission::PingOnly,
            3 => TestPermission::OtherOnly,
            _ => unreachable!(),
        }
    }

    fn as_rule(&self) -> Rule {
        match self {
            TestPermission::AllowAll => Rule::allow_all(),
            TestPermission::RejectAll => Rule::reject_all(),
            TestPermission::PingOnly => {
                let permission = RequestPermission::Ping;
                Rule::Permission(FirewallPermission::none().add_permissions([&permission.permission()]))
            }
            TestPermission::OtherOnly => {
                let permission = RequestPermission::Other;
                Rule::Permission(FirewallPermission::none().add_permissions([&permission.permission()]))
            }
        }
    }
}

struct RulesTestConfig<'a> {
    comms_a: &'a mut TestComms,
    comms_b: &'a mut TestComms,
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
        comms_a: &'a mut TestComms,
        comms_b: &'a mut TestComms,
        b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
        b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ) -> Self {
        let a_rule = (rand::random::<u8>() % 2 > 0).then(TestPermission::random);
        let b_rule = (rand::random::<u8>() % 2 > 0).then(TestPermission::random);
        let req = (rand::random::<u8>() % 2 > 0)
            .then(|| Request::Ping)
            .unwrap_or(Request::Other);
        RulesTestConfig {
            comms_a,
            comms_b,
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
        let peer_a_id = self.comms_a.get_peer_id();
        let peer_b_id = self.comms_b.get_peer_id();
        if let Some(peer_rule) = self.b_rule.as_ref() {
            self.comms_b
                .set_peer_rule(peer_a_id, RuleDirection::Inbound, peer_rule.as_rule())
                .await;
        }
        self.comms_b
            .set_firewall_default(RuleDirection::Inbound, self.b_default.as_rule())
            .await;
        if let Some(peer_rule) = self.a_rule.as_ref() {
            self.comms_a
                .set_peer_rule(peer_b_id, RuleDirection::Outbound, peer_rule.as_rule())
                .await;
        }
        self.comms_a
            .set_firewall_default(RuleDirection::Outbound, self.a_default.as_rule())
            .await;
    }

    async fn test_request(&mut self) {
        let peer_a_id = self.comms_a.get_peer_id();
        let peer_b_id = self.comms_b.get_peer_id();

        let mut comms_a = self.comms_a.clone();
        let res_future = comms_a.send_request(peer_b_id, self.req.clone()).boxed();

        let a_rule = self.a_rule.unwrap_or(self.a_default);
        let b_rule = self.b_rule.unwrap_or(self.b_default);
        let req = self.req.clone();
        let is_allowed = |rule: TestPermission| match rule {
            TestPermission::AllowAll => true,
            TestPermission::RejectAll => false,
            TestPermission::PingOnly => matches!(req, Request::Ping),
            TestPermission::OtherOnly => matches!(req, Request::Other),
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
                TestPermission::OtherOnly | TestPermission::PingOnly => {
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
        let peer_a_id = self.comms_a.get_peer_id();
        let peer_b_id = self.comms_b.get_peer_id();
        self.comms_b.remove_peer_rule(peer_a_id, RuleDirection::Both).await;
        self.comms_b.remove_firewall_default(RuleDirection::Both).await;
        self.comms_a.remove_peer_rule(peer_b_id, RuleDirection::Both).await;
        self.comms_a.remove_firewall_default(RuleDirection::Both).await;
    }
}

#[tokio::test]
async fn firewall_permissions() {
    let (_, _, _, mut comms_a) = init_comms().await;
    let (_, mut b_rq_rx, mut b_event_rx, mut comms_b) = init_comms().await;
    let peer_b_id = comms_b.get_peer_id();

    let peer_b_addr = comms_b.start_listening(None).await.unwrap();
    comms_a.add_address(peer_b_id, peer_b_addr).await;

    for _ in 0..100 {
        let mut test = RulesTestConfig::new_test_case(&mut comms_a, &mut comms_b, &mut b_event_rx, &mut b_rq_rx);
        test.configure_firewall().await;
        sleep(Duration::from_millis(10)).await;
        test.test_request().await;
        test.clean().await;
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
    comms_a: &'a mut TestComms,
    firewall_a: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,

    comms_b: &'a mut TestComms,
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
        comms_a: &'a mut TestComms,
        firewall_a: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,
        comms_b: &'a mut TestComms,
        firewall_b: &'a mut mpsc::Receiver<FirewallRequest<RequestPermission>>,
        b_events_rx: &'a mut mpsc::Receiver<NetworkEvent>,
        b_request_rx: &'a mut mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ) -> Self {
        AskTestConfig {
            comms_a,
            firewall_a,
            comms_b,
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
        let peer_a_id = self.comms_a.get_peer_id();
        let peer_b_id = self.comms_b.get_peer_id();

        let is_allowed = |rule: &FwRuleRes, approval: &FwApprovalRes| match rule {
            FwRuleRes::AllowAll => true,
            FwRuleRes::Drop | FwRuleRes::RejectAll => false,
            FwRuleRes::Ask if matches!(approval, FwApprovalRes::Allow) => true,
            _ => false,
        };

        let mut comms_a = self.comms_a.clone();
        let (tx_res, mut rx_res) = oneshot::channel();

        let operation_future = async {
            let res = comms_a.send_request(peer_b_id, Request::Ping).await;
            tx_res.send(res).unwrap();
        };

        let resolved = async {
            self.firewall_handle_next(TestPeer::A).await;

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

            self.firewall_handle_next(TestPeer::B).await;

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
                            Poll::Ready(Some(FirewallRequest::PeerSpecificRule(rq))) => drop(rq.response_tx),
                            Poll::Ready(Some(_)) => panic!(
                                "Unexpected RequestApprovalQuery after PeerRuleQuery was dropped; config {}",
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

    async fn firewall_handle_next(&mut self, test_peer: TestPeer) {
        let config = format!("{}", self);
        let (fw_channel, peer_rule, approval) = match test_peer {
            TestPeer::A => (&mut self.firewall_a, &self.a_rule, &self.a_approval),
            TestPeer::B => (&mut self.firewall_b, &self.b_rule, &self.b_approval),
        };
        let response_tx = match expect_ok!(fw_channel.next(), config) {
            FirewallRequest::PeerSpecificRule(PeerRuleQuery { response_tx, .. }) => response_tx,
            _ => panic!("Unexpected RequestApprovalQuery before PeerRuleQuery"),
        };

        let (rule, other) = match peer_rule {
            FwRuleRes::AllowAll => (Rule::allow_all(), Rule::reject_all()),
            FwRuleRes::RejectAll => (Rule::reject_all(), Rule::allow_all()),
            FwRuleRes::Ask => match approval {
                FwApprovalRes::Allow => (Rule::Ask, Rule::reject_all()),
                _ => (Rule::Ask, Rule::allow_all()),
            },
            FwRuleRes::Drop => {
                drop(response_tx);
                return;
            }
        };
        let (inbound, outbound) = match test_peer {
            TestPeer::A => (other, rule),
            TestPeer::B => (rule, other),
        };

        response_tx
            .send(FirewallRules::new(Some(inbound), Some(outbound)))
            .unwrap_or_else(|_| panic!("Error on unwrap; config: {}", config));

        if matches!(peer_rule, FwRuleRes::Ask) {
            let response_tx = match expect_ok!(fw_channel.next(), self) {
                FirewallRequest::RequestApproval(RequestApprovalQuery {
                    response_tx,
                    data: (_, dir, _),
                    ..
                }) => {
                    match test_peer {
                        TestPeer::A => assert_eq!(dir, RequestDirection::Outbound),
                        TestPeer::B => assert_eq!(dir, RequestDirection::Inbound),
                    }
                    response_tx
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
        let peer_a_id = self.comms_a.get_peer_id();
        let peer_b_id = self.comms_b.get_peer_id();
        self.comms_a.remove_peer_rule(peer_b_id, RuleDirection::Both).await;
        self.comms_b.remove_peer_rule(peer_a_id, RuleDirection::Both).await;
    }
}

#[tokio::test]
async fn firewall_ask() {
    let (mut firewall_a, _, _, mut comms_a) = init_comms().await;
    let (mut firewall_b, mut b_rq_rx, mut b_event_rx, mut comms_b) = init_comms().await;
    let peer_b_id = comms_b.get_peer_id();

    let peer_b_addr = comms_b.start_listening(None).await.unwrap();
    comms_a.add_address(peer_b_id, peer_b_addr).await;

    for _ in 0..100 {
        let mut test = AskTestConfig::new_test_case(
            &mut comms_a,
            &mut firewall_a,
            &mut comms_b,
            &mut firewall_b,
            &mut b_event_rx,
            &mut b_rq_rx,
        );
        test.test_request_with_ask().await;
        test.clean().await;
        sleep(Duration::from_millis(10)).await;
    }
}
