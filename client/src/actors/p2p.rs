// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{secure_messages::WriteToVault, GetTarget},
    state::p2p::{Network, NetworkConfig, ShRequest, ShResult},
};
use actix::prelude::*;
use futures::{FutureExt, TryFutureExt};
use messages::*;
use p2p::{
    firewall::{FirewallRules, Rule},
    DialErr, ListenErr, ListenRelayErr, Multiaddr, OutboundFailure, ReceiveRequest, RelayNotSupported,
};
use std::convert::{TryFrom, TryInto};

macro_rules! impl_handler {
    ($mty:ty => $rty:ty, |$cid:ident, $mid:ident| $body:stmt ) => {
        impl Handler<$mty> for Network {
            type Result = ResponseActFuture<Self, $rty>;
            fn handle(&mut self, $mid: $mty, _: &mut Self::Context) -> Self::Result {
                let mut $cid = self.network.clone();
                async move { $body }.into_actor(self).boxed_local()
            }
        }
    };
}

macro_rules! sh_request_dispatch {
    ($request:ident => |$inner: ident| $body:block) => {
        match $request {
            ShRequest::CheckVault($inner) => $body
            ShRequest::CheckRecord($inner) => $body
            ShRequest::WriteToStore($inner) => $body
            ShRequest::ReadFromStore($inner) => $body
            ShRequest::DeleteFromStore($inner) => $body
            ShRequest::WriteToRemoteVault($inner) =>  {
                let $inner: WriteToVault = $inner.into();
                $body
            }
            #[cfg(test)]
            ShRequest::ReadFromVault($inner) => $body
            ShRequest::GarbageCollect($inner) => $body
            ShRequest::ListIds($inner) => $body
            ShRequest::ClearCache($inner) => $body
            ShRequest::Procedures($inner) => $body
        }
    }
}

impl Actor for Network {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let inbound_request_rx = self._inbound_request_rx.take().unwrap();
        Self::add_stream(inbound_request_rx, ctx);
    }
}

impl StreamHandler<ReceiveRequest<ShRequest, ShResult>> for Network {
    fn handle(&mut self, item: ReceiveRequest<ShRequest, ShResult>, ctx: &mut Self::Context) {
        let ReceiveRequest {
            request, response_tx, ..
        } = item;
        sh_request_dispatch!(request => |inner| {
            let fut = self.registry
                .send(GetTarget)
                .and_then(|client| async { match client {
                    Some(client) => client.send(inner).await,
                    _ => Err(MailboxError::Closed)
                }})
                .map_ok(|response| response_tx.send(response.into()))
                .map(|_| ())
                .into_actor(self);
            ctx.wait(fut);
        });
    }
}

impl<Rq> Handler<SendRequest<Rq>> for Network
where
    Rq: Into<ShRequest> + Message + 'static,
    Rq::Result: TryFrom<ShResult, Error = ()>,
{
    type Result = ResponseActFuture<Self, Result<Rq::Result, OutboundFailure>>;

    fn handle(&mut self, msg: SendRequest<Rq>, _: &mut Self::Context) -> Self::Result {
        let mut network = self.network.clone();
        async move {
            let request: ShRequest = msg.request.into();
            let res = network.send_request(msg.peer, request).await;
            res.map(|wrapper| {
                let res: Rq::Result = wrapper.try_into().unwrap();
                res
            })
        }
        .into_actor(self)
        .boxed_local()
    }
}

impl Handler<ExportConfig> for Network {
    type Result = ResponseActFuture<Self, NetworkConfig>;

    fn handle(&mut self, _: ExportConfig, _: &mut Self::Context) -> Self::Result {
        let mut network = self.network.clone();
        let config = self._config.clone();
        async move {
            let state = network.export_state().await;
            config.load_state(state)
        }
        .into_actor(self)
        .boxed_local()
    }
}

impl_handler!(GetSwarmInfo => SwarmInfo, |network, _msg| {
    let listeners = network.get_listeners().await;
    let local_peer_id = network.peer_id();
    let connections = network.get_connections().await;
    SwarmInfo { local_peer_id, listeners, connections}
});

impl_handler!(StartListening => Result<Multiaddr, ListenErr>, |network, msg| {
    let addr = msg.address.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
    network.start_listening(addr).await
});

impl_handler!(StartListeningRelay => Result<Multiaddr, ListenRelayErr>, |network, msg| {
    network.start_relayed_listening(msg.relay, msg.relay_addr).await
});

impl_handler!(StopListening => (), |network, _msg| {
    network.stop_listening().await
});

impl_handler!(StopListeningAddr => (), |network, msg| {
    network.stop_listening_addr(msg.address).await
});

impl_handler!(StopListeningRelay => bool, |network, msg| {
    network.stop_listening_relay(msg.relay).await
});

impl_handler!(ConnectPeer => Result<Multiaddr, DialErr>, |network, msg| {
    network.connect_peer(msg.peer).await
});

impl_handler!(GetFirewallDefault => FirewallRules<ShRequest>, |network, _msg| {
    network.get_firewall_default().await
});

impl_handler!(SetFirewallDefault<ShRequest> => (), |network, msg| {
    network.set_firewall_default(msg.direction, msg.rule).await
});

impl_handler!(RemoveFirewallDefault => (), |network, msg| {
    network.remove_firewall_default(msg.direction).await
});

impl_handler!(GetFirewallRules => FirewallRules<ShRequest>, |network, msg| {
    network.get_peer_rules(msg.peer).await
});

impl_handler!(SetFirewallRule<ShRequest> => (), |network, msg| {
    network.set_peer_rule(msg.peer, msg.direction, msg.rule).await
});

impl_handler!(RemoveFirewallRule => (), |network, msg| {
    network.remove_peer_rule(msg.peer, msg.direction).await
});

impl_handler!(GetPeerAddrs => Vec<Multiaddr>, |network, msg| {
    network.get_addrs(msg.peer).await
});

impl_handler!(AddPeerAddr => (), |network, msg| {
    network.add_address(msg.peer, msg.address).await
});

impl_handler!(RemovePeerAddr => (), |network, msg| {
    network.add_address(msg.peer, msg.address).await
});

impl_handler!(AddDialingRelay => Result<Option<Multiaddr>, RelayNotSupported>, |network, msg| {
    network.add_dialing_relay(msg.relay, msg.relay_addr).await
});

impl_handler!(RemoveDialingRelay => bool, |network, msg| {
    network.remove_dialing_relay(msg.relay).await
});

pub mod messages {

    use super::*;
    use p2p::{firewall::RuleDirection, EstablishedConnections, Listener, Multiaddr, PeerId};

    #[derive(Message)]
    #[rtype(result = "Result<Rq::Result, OutboundFailure>")]
    pub struct SendRequest<Rq>
    where
        Rq: Message,
    {
        pub peer: PeerId,
        pub request: Rq,
    }

    pub struct SwarmInfo {
        pub local_peer_id: PeerId,
        pub listeners: Vec<Listener>,
        pub connections: Vec<(PeerId, EstablishedConnections)>,
    }

    #[derive(Message)]
    #[rtype(result = "SwarmInfo")]
    pub struct GetSwarmInfo;

    #[derive(Message)]
    #[rtype(result = "Result<Multiaddr, ListenErr>")]
    pub struct StartListening {
        pub address: Option<Multiaddr>,
    }

    #[derive(Message)]
    #[rtype(result = "Result<Multiaddr, ListenRelayErr>")]
    pub struct StartListeningRelay {
        pub relay: PeerId,
        pub relay_addr: Option<Multiaddr>,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct StopListening;

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct StopListeningAddr {
        pub address: Multiaddr,
    }

    #[derive(Message)]
    #[rtype(result = "bool")]
    pub struct StopListeningRelay {
        pub relay: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "Result<Multiaddr, DialErr>")]
    pub struct ConnectPeer {
        pub peer: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "FirewallRules<ShRequest>")]
    pub struct GetFirewallDefault;

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct SetFirewallDefault<ShRequest> {
        pub direction: RuleDirection,
        pub rule: Rule<ShRequest>,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct RemoveFirewallDefault {
        pub direction: RuleDirection,
    }

    #[derive(Message)]
    #[rtype(result = "FirewallRules<ShRequest>")]
    pub struct GetFirewallRules {
        pub peer: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct SetFirewallRule<ShRequest> {
        pub peer: PeerId,
        pub direction: RuleDirection,
        pub rule: Rule<ShRequest>,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct RemoveFirewallRule {
        pub peer: PeerId,
        pub direction: RuleDirection,
    }

    #[derive(Message)]
    #[rtype(result = "Vec<Multiaddr>")]
    pub struct GetPeerAddrs {
        pub peer: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct AddPeerAddr {
        pub peer: PeerId,
        pub address: Multiaddr,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct RemovePeerAddr {
        pub peer: PeerId,
        pub address: Multiaddr,
    }

    #[derive(Message)]
    #[rtype(result = "Result<Option<Multiaddr>, RelayNotSupported>")]
    pub struct AddDialingRelay {
        pub relay: PeerId,
        pub relay_addr: Option<Multiaddr>,
    }

    #[derive(Message)]
    #[rtype(result = "bool")]
    pub struct RemoveDialingRelay {
        pub relay: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "NetworkConfig")]
    pub struct ExportConfig;
}
