// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::actors::{GetTarget, Registry};
use actix::prelude::*;
use futures::{channel::mpsc, FutureExt, TryFutureExt};
pub use messages::SwarmInfo;
use messages::*;
use p2p::{
    firewall::{FirewallConfiguration, FirewallRules, Rule},
    ChannelSinkConfig, ConnectionLimits, DialErr, EventChannel, InitKeypair, ListenErr, ListenRelayErr, Multiaddr,
    OutboundFailure, ReceiveRequest, StrongholdP2p, StrongholdP2pBuilder,
};
use std::{
    convert::{TryFrom, TryInto},
    io,
    time::Duration,
};

macro_rules! impl_handler {
    ($mty:ty => $rty:ty, |$cid:ident, $mid:ident| $body:stmt ) => {
        impl Handler<$mty> for NetworkActor {
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
            ShRequest::CreateVault($inner) => $body
            ShRequest::WriteToVault($inner) => $body
            #[cfg(test)]
            ShRequest::ReadFromVault($inner) => $body
            ShRequest::GarbageCollect($inner) => $body
            ShRequest::ListIds($inner) => $body
            ShRequest::ClearCache($inner) => $body
            ShRequest::CallProcedure($inner) => $body
        }
    }
}

macro_rules! sh_request_from {
    ($T:ident) => {
        impl From<$T> for ShRequest {
            fn from(t: $T) -> Self {
                ShRequest::$T(t)
            }
        }
    };
}

macro_rules! sh_result_mapping {
    ($enum:ident::$variant:ident, Result<$ok:ty, anyhow::Error>) => {
        sh_result_mapping!($enum::$variant, Result<$ok, anyhow::Error>,
            |i| $enum::$variant(i.map_err(|e| e.to_string())),
            |v| v.map_err(anyhow::Error::msg)
        );
    };
    ($enum:ident::$variant:ident, $inner:ty) => {
        sh_result_mapping!($enum::$variant, $inner,
            |t| $enum::$variant(t),
            |t| t
        );
    };
    ($enum:ident::$variant:ident, $inner:ty,
        |$i:ident| $map_from_inner:expr,
        |$v:ident| $map_try_from_enum:expr
    ) => {
        impl From<$inner> for $enum {
            fn from($i: $inner) -> Self {
                $map_from_inner
            }
        }
        impl TryFrom<$enum> for $inner {
            type Error = ();
            fn try_from(t: $enum) -> Result<Self, Self::Error> {
                if let $enum::$variant($v) = t {
                    Ok($map_try_from_enum)
                } else {
                    Err(())
                }
            }
        }
    }
}

pub struct NetworkActor {
    network: StrongholdP2p<ShRequest, ShResult>,
    inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<ShRequest, ShResult>>>,
    registry: Addr<Registry>,
}

impl NetworkActor {
    pub async fn new(
        registry: Addr<Registry>,
        firewall_rule: Rule<ShRequest>,
        network_config: NetworkConfig,
    ) -> Result<Self, io::Error> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (inbound_request_tx, inbound_request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
        let firewall_config = FirewallConfiguration::new(Some(firewall_rule), Some(Rule::AllowAll));
        let mut builder =
            StrongholdP2pBuilder::new(firewall_tx, inbound_request_tx, None).with_firewall_config(firewall_config);
        if let Some(keypair) = network_config.keypair {
            builder = builder.with_keys(keypair)
        }
        if let Some(timeout) = network_config.request_timeout {
            builder = builder.with_request_timeout(timeout)
        }
        if let Some(timeout) = network_config.connection_timeout {
            builder = builder.with_connection_timeout(timeout)
        }
        if let Some(limit) = network_config.connections_limit {
            builder = builder.with_connections_limit(limit)
        }
        let network = builder.build().await?;
        let actor = Self {
            network,
            inbound_request_rx: Some(inbound_request_rx),
            registry,
        };
        Ok(actor)
    }
}

impl Actor for NetworkActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let inbound_request_rx = self.inbound_request_rx.take().unwrap();
        Self::add_stream(inbound_request_rx, ctx);
    }
}

impl StreamHandler<ReceiveRequest<ShRequest, ShResult>> for NetworkActor {
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

impl<Rq> Handler<SendRequest<Rq>> for NetworkActor
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

impl_handler!(GetSwarmInfo => SwarmInfo, |network, _msg| {
    let listeners = network.get_listeners().await;
    let local_peer_id = network.get_peer_id();
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

impl_handler!(StopListeningRelay => (), |network, msg| {
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

impl_handler!(AddDialingRelay => Option<Multiaddr>, |network, msg| {
    network.add_dialing_relay(msg.relay, None).await
});

impl_handler!(RemoveDialingRelay => (), |network, msg| {
    network.remove_dialing_relay(msg.relay).await
});

// Config for the new network.
/// Default behaviour:
/// - A new keypair is created and used, from which the [`PeerId`] of the local peer is derived.
/// - No limit for simultaneous connections.
/// - Request-timeout and Connection-timeout are 10s.
pub struct NetworkConfig {
    keypair: Option<InitKeypair>,
    request_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    connections_limit: Option<ConnectionLimits>,
}

impl NetworkConfig {
    /// Set the keypair that is used for authenticating the traffic on the transport layer.
    /// The local [`PeerId`] is derived from the keypair.
    pub fn with_keypair(mut self, keypair: InitKeypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set a timeout for receiving a response after a request was sent.
    ///
    /// This applies for inbound and outbound requests.
    pub fn with_request_timeout(mut self, t: Duration) -> Self {
        self.request_timeout = Some(t);
        self
    }

    /// Set the limit for simultaneous connections.
    /// By default no connection limits apply.
    pub fn with_connections_limit(mut self, limit: ConnectionLimits) -> Self {
        self.connections_limit = Some(limit);
        self
    }

    /// Set the timeout for a idle connection to a remote peer.
    pub fn with_connection_timeout(mut self, t: Duration) -> Self {
        self.connection_timeout = Some(t);
        self
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            keypair: None,
            request_timeout: None,
            connection_timeout: None,
            connections_limit: None,
        }
    }
}

pub mod messages {
    use super::*;
    use crate::{ProcResult, RecordHint, RecordId};
    use p2p::{firewall::RuleDirection, EstablishedConnections, Listener, Multiaddr, PeerId};
    use serde::{Deserialize, Serialize};

    #[cfg(test)]
    use crate::actors::secure_testing::ReadFromVault;
    use crate::actors::{
        secure_messages::{
            CheckRecord, CheckVault, ClearCache, CreateVault, DeleteFromStore, GarbageCollect, ListIds, ReadFromStore,
            WriteToStore, WriteToVault,
        },
        secure_procedures::CallProcedure,
    };

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
    #[rtype(result = "()")]
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
    #[rtype(result = "Option<Multiaddr>")]
    pub struct AddDialingRelay {
        pub relay: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct RemoveDialingRelay {
        pub relay: PeerId,
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct Shutdown;

    // Wrapper for Requests to a remote Secure Client
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShRequest {
        CheckVault(CheckVault),
        CheckRecord(CheckRecord),
        ListIds(ListIds),
        CreateVault(CreateVault),
        #[cfg(test)]
        ReadFromVault(ReadFromVault),
        WriteToVault(WriteToVault),
        ReadFromStore(ReadFromStore),
        WriteToStore(WriteToStore),
        DeleteFromStore(DeleteFromStore),
        GarbageCollect(GarbageCollect),
        ClearCache(ClearCache),
        CallProcedure(CallProcedure),
    }

    sh_request_from!(CheckVault);
    sh_request_from!(CheckRecord);
    sh_request_from!(ListIds);
    sh_request_from!(CreateVault);
    #[cfg(test)]
    sh_request_from!(ReadFromVault);
    sh_request_from!(WriteToVault);
    sh_request_from!(ReadFromStore);
    sh_request_from!(WriteToStore);
    sh_request_from!(DeleteFromStore);
    sh_request_from!(GarbageCollect);
    sh_request_from!(ClearCache);
    sh_request_from!(CallProcedure);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShResult {
        Empty(()),
        Bool(bool),
        Status(Result<(), String>),
        Vector(Result<Vec<u8>, String>),
        List(Result<Vec<(RecordId, RecordHint)>, String>),
        Proc(Result<ProcResult, String>),
    }

    sh_result_mapping!(ShResult::Empty, ());
    sh_result_mapping!(ShResult::Bool, bool);
    sh_result_mapping!(ShResult::Status, Result<(), anyhow::Error>);
    sh_result_mapping!(ShResult::Vector, Result<Vec<u8>, anyhow::Error>);
    sh_result_mapping!(ShResult::List, Result<Vec<(RecordId, RecordHint)>, anyhow::Error>);
    sh_result_mapping!(ShResult::Proc, Result<ProcResult, anyhow::Error>);
}
