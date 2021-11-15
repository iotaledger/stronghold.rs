// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{secure_messages::WriteToVault, GetTarget, RecordError, Registry},
    enum_from_inner,
    procedures::{CollectedOutput, Procedure},
};
use actix::prelude::*;
use futures::{channel::mpsc, FutureExt, TryFutureExt};
use messages::*;
use p2p::{
    firewall::{FirewallRules, Rule},
    BehaviourState, ChannelSinkConfig, ConnectionLimits, DialErr, EventChannel, ListenErr, ListenRelayErr, Multiaddr,
    OutboundFailure, ReceiveRequest, RelayNotSupported, StrongholdP2p, StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
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
            ShRequest::WriteToRemoteVault($inner) =>  {
                let $inner: WriteToVault = $inner.into();
                $body
            }
            #[cfg(test)]
            ShRequest::ReadFromVault($inner) => $body
            ShRequest::GarbageCollect($inner) => $body
            ShRequest::ListIds($inner) => $body
            ShRequest::ClearCache($inner) => $body
            ShRequest::Procedure($inner) => $body
        }
    }
}

macro_rules! sh_result_mapping {
    ($enum:ident::$variant:ident => $inner:ty) => {
        impl From<$inner> for $enum {
            fn from(i: $inner) -> Self {
                $enum::$variant(i)
            }
        }
        impl TryFrom<$enum> for $inner {
            type Error = ();
            fn try_from(t: $enum) -> Result<Self, Self::Error> {
                if let $enum::$variant(v) = t {
                    Ok(v)
                } else {
                    Err(())
                }
            }
        }
    };
}

pub struct NetworkActor {
    network: StrongholdP2p<ShRequest, ShResult>,
    inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<ShRequest, ShResult>>>,
    registry: Addr<Registry>,
    config: NetworkConfig,
}

impl NetworkActor {
    pub async fn new(registry: Addr<Registry>, mut network_config: NetworkConfig) -> Result<Self, io::Error> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (inbound_request_tx, inbound_request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
        let mut builder = StrongholdP2pBuilder::new(firewall_tx, inbound_request_tx, None)
            .with_mdns_support(network_config.enable_mdns)
            .with_relay_support(network_config.enable_relay);
        if let Some(state) = network_config.state.take() {
            builder = builder.load_state(state);
        } else {
            builder = builder.with_firewall_default(FirewallRules::allow_all())
        }
        if let Some(timeout) = network_config.request_timeout {
            builder = builder.with_request_timeout(timeout)
        }
        if let Some(timeout) = network_config.connection_timeout {
            builder = builder.with_connection_timeout(timeout)
        }
        if let Some(ref limit) = network_config.connections_limit {
            builder = builder.with_connections_limit(limit.clone())
        }

        let network = builder.build().await?;
        let actor = Self {
            network,
            inbound_request_rx: Some(inbound_request_rx),
            registry,
            config: network_config,
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

impl Handler<ExportConfig> for NetworkActor {
    type Result = ResponseActFuture<Self, NetworkConfig>;

    fn handle(&mut self, _: ExportConfig, _: &mut Self::Context) -> Self::Result {
        let mut network = self.network.clone();
        let config = self.config.clone();
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

// Config for the new network.
/// Default behaviour:
/// - No limit for simultaneous connections.
/// - Request-timeout and Connection-timeout are 10s.
/// - [`Mdns`][`libp2p::mdns`] protocol is disabled. **Note**: Enabling mdns will broadcast our own address and id to
///   the local network.
/// - [`Relay`][`libp2p::relay`] functionality is disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    request_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    connections_limit: Option<ConnectionLimits>,
    enable_mdns: bool,
    enable_relay: bool,
    state: Option<BehaviourState<ShRequest>>,
}

impl NetworkConfig {
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

    /// Enable / Disable [`Mdns`][`libp2p::mdns`] protocol.
    /// **Note**: Enabling mdns will broadcast our own address and id to the local network.
    pub fn with_mdns_enabled(mut self, is_enabled: bool) -> Self {
        self.enable_mdns = is_enabled;
        self
    }

    /// Enable / Disable [`Relay`][`libp2p::relay`] functionality.
    /// This also means that other peers can use us as relay/
    pub fn with_relay_enabled(mut self, is_enabled: bool) -> Self {
        self.enable_relay = is_enabled;
        self
    }

    /// Import state exported from a past network actor.
    pub fn load_state(mut self, state: BehaviourState<ShRequest>) -> Self {
        self.state = Some(state);
        self
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            request_timeout: None,
            connection_timeout: None,
            connections_limit: None,
            enable_mdns: false,
            enable_relay: false,
            state: None,
        }
    }
}

pub mod messages {

    use super::*;
    use crate::{procedures::ProcedureError, Location, RecordHint, RecordId};
    use p2p::{firewall::RuleDirection, EstablishedConnections, Listener, Multiaddr, PeerId};
    use serde::{Deserialize, Serialize};

    use crate::actors::secure_messages::{
        CheckRecord, CheckVault, ClearCache, DeleteFromStore, GarbageCollect, ListIds, ReadFromStore, WriteToStore,
        WriteToVault,
    };
    #[cfg(test)]
    use crate::actors::secure_testing::ReadFromVault;

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

    #[derive(Debug, Message, Clone, Serialize, Deserialize)]
    #[rtype(result = "Result<(), RemoteRecordError>")]
    pub struct WriteToRemoteVault {
        pub location: Location,
        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl From<WriteToRemoteVault> for WriteToVault {
        fn from(t: WriteToRemoteVault) -> Self {
            let WriteToRemoteVault {
                location,
                payload,
                hint,
            } = t;
            WriteToVault {
                location,
                payload,
                hint,
            }
        }
    }

    impl From<WriteToVault> for WriteToRemoteVault {
        fn from(t: WriteToVault) -> Self {
            let WriteToVault {
                location,
                payload,
                hint,
            } = t;
            WriteToRemoteVault {
                location,
                payload,
                hint,
            }
        }
    }

    pub type RemoteRecordError = String;

    // Wrapper for Requests to a remote Secure Client
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShRequest {
        CheckVault(CheckVault),
        CheckRecord(CheckRecord),
        ListIds(ListIds),
        #[cfg(test)]
        ReadFromVault(ReadFromVault),
        WriteToRemoteVault(WriteToRemoteVault),
        ReadFromStore(ReadFromStore),
        WriteToStore(WriteToStore),
        DeleteFromStore(DeleteFromStore),
        GarbageCollect(GarbageCollect),
        ClearCache(ClearCache),
        Procedure(Procedure),
    }

    enum_from_inner!(ShRequest from CheckVault);
    enum_from_inner!(ShRequest from ListIds);
    #[cfg(test)]
    enum_from_inner!(ShRequest from ReadFromVault);
    enum_from_inner!(ShRequest from WriteToRemoteVault);
    enum_from_inner!(ShRequest from ReadFromStore);
    enum_from_inner!(ShRequest from WriteToStore);
    enum_from_inner!(ShRequest from DeleteFromStore);
    enum_from_inner!(ShRequest from GarbageCollect);
    enum_from_inner!(ShRequest from ClearCache);
    enum_from_inner!(ShRequest from Procedure);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShResult {
        Empty(()),
        Data(Option<Vec<u8>>),
        Bool(bool),
        WriteRemoteVault(Result<(), RemoteRecordError>),
        ListIds(Vec<(RecordId, RecordHint)>),
        Proc(Result<CollectedOutput, ProcedureError>),
    }

    sh_result_mapping!(ShResult::Empty => ());
    sh_result_mapping!(ShResult::Bool => bool);
    sh_result_mapping!(ShResult::Data => Option<Vec<u8>>);
    sh_result_mapping!(ShResult::ListIds => Vec<(RecordId, RecordHint)>);
    sh_result_mapping!(ShResult::Proc => Result<CollectedOutput, ProcedureError>);

    impl From<Result<(), RecordError>> for ShResult {
        fn from(inner: Result<(), RecordError>) -> Self {
            ShResult::WriteRemoteVault(inner.map_err(|e| e.to_string()))
        }
    }

    impl TryFrom<ShResult> for Result<(), RemoteRecordError> {
        type Error = ();
        fn try_from(t: ShResult) -> Result<Self, Self::Error> {
            if let ShResult::WriteRemoteVault(result) = t {
                Ok(result)
            } else {
                Err(())
            }
        }
    }
}
