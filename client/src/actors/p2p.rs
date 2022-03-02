// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{secure_messages::WriteToVault, GetClient},
    state::p2p::{AccessRequest, Network, NetworkConfig, Request, ShRequest, ShResult},
    utils::LoadFromPath,
};
use actix::prelude::*;
use engine::vault::ClientId;
use futures::{FutureExt, TryFutureExt};
use messages::*;
use p2p::{
    firewall::{Rule, RuleDirection},
    DialErr, ListenErr, ListenRelayErr, Multiaddr, OutboundFailure, ReceiveRequest, RelayNotSupported,
};
use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
    sync::Arc,
};

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
            Request::CheckVault($inner) => $body
            Request::CheckRecord($inner) => $body
            Request::WriteToStore($inner) => $body
            Request::ReadFromStore($inner) => $body
            Request::DeleteFromStore($inner) => $body
            Request::WriteToRemoteVault($inner) =>  {
                let $inner: WriteToVault = $inner.into();
                $body
            }
            #[cfg(test)]
            Request::ReadFromVault($inner) => $body
            Request::RevokeData($inner) => $body
            Request::ListIds($inner) => $body
            Request::Procedures($inner) => $body
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
        let ShRequest { client_path, request } = request;
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        sh_request_dispatch!(request => |inner| {
            let fut = self.registry
                .send(GetClient {id: client_id})
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
    Rq: Into<Request> + Message + 'static,
    Rq::Result: TryFrom<ShResult, Error = ()>,
{
    type Result = ResponseActFuture<Self, Result<Rq::Result, OutboundFailure>>;

    fn handle(&mut self, msg: SendRequest<Rq>, _: &mut Self::Context) -> Self::Result {
        let mut network = self.network.clone();
        async move {
            let sh_request = ShRequest {
                client_path: msg.client_path,
                request: msg.request.into(),
            };
            let res = network.send_request(msg.peer, sh_request).await;
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

impl_handler!(SetFirewallDefault => (), |network, msg| {
    let restriction = move |rq: &AccessRequest| rq.check(msg.permissions.clone());
    let rule = Rule::Restricted {
        restriction: Arc::new(restriction),
        _maker: PhantomData,
    };
    network.set_firewall_default(RuleDirection::Inbound, rule).await
});

impl_handler!(SetFirewallRule => (), |network, msg| {
    let restriction = move |rq: &AccessRequest| rq.check(msg.permissions.clone());
    let rule = Rule::Restricted {
        restriction: Arc::new(restriction),
        _maker: PhantomData,
    };
    network.set_peer_rule(msg.peer, RuleDirection::Inbound, rule).await
});

impl_handler!(RemoveFirewallRule => (), |network, msg| {
    network.remove_peer_rule(msg.peer, RuleDirection::Inbound).await
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

    use crate::state::p2p::Permissions;

    use super::*;
    use p2p::{EstablishedConnections, Listener, Multiaddr, PeerId};

    #[derive(Message)]
    #[rtype(result = "Result<Rq::Result, OutboundFailure>")]
    pub struct SendRequest<Rq>
    where
        Rq: Message,
    {
        pub peer: PeerId,
        pub client_path: Vec<u8>,
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
    #[rtype(result = "()")]
    pub struct SetFirewallDefault {
        pub permissions: Permissions,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct SetFirewallRule {
        pub peer: PeerId,
        pub permissions: Permissions,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct RemoveFirewallRule {
        pub peer: PeerId,
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
