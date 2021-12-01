// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{
        registry::messages::GetSynchronizationActor, secure_messages::WriteToVault, GetTarget, RecordError, Registry,
    },
    enum_from_inner,
    procedures::CollectedOutput,
};
use actix::prelude::*;
use futures::{channel::mpsc, FutureExt, TryFutureExt};
use messages::*;
use p2p::{
    firewall::{FirewallRules, Rule},
    BehaviourState, ChannelSinkConfig, ConnectionLimits, DialErr, EventChannel, InitKeypair, ListenErr, ListenRelayErr,
    Multiaddr, OutboundFailure, ReceiveRequest, RelayNotSupported, StrongholdP2p, StrongholdP2pBuilder,
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
    (client, $request:ident => |$inner: ident| $body:block) => {
        match $request {
            ClientRequest::CheckVault($inner) => $body
            ClientRequest::CheckRecord($inner) => $body
            ClientRequest::WriteToStore($inner) => $body
            ClientRequest::ReadFromStore($inner) => $body
            ClientRequest::DeleteFromStore($inner) => $body
            ClientRequest::WriteToVault($inner) => $body
            ClientRequest::GarbageCollect($inner) => $body
            ClientRequest::ListIds($inner) => $body
            ClientRequest::ClearCache($inner) => $body
            ClientRequest::WriteToRemoteVault($inner) =>  {
                let $inner: WriteToVault = $inner.into();
                $body
            }

            #[cfg(test)]
            ClientRequest::ReadFromVault($inner) => $body
            ClientRequest::Procedure($inner) => $body
        }
    };
    (sync, $request:ident => |$inner: ident| $body:block) => {
        match $request {
            SynchronizationRequest::CalculateShapeRemote($inner) => $body
            SynchronizationRequest::CalculateShapeLocal($inner) => $body
            SynchronizationRequest::ComplementSynchronization($inner) => $body
            SynchronizationRequest::FullSynchronization($inner) => $body
            SynchronizationRequest::PartialSynchronization($inner) => $body
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

/// Actor that handles all network interaction.
///
/// On [`NetworkActor::new`] a new [`StrongholdP2p`] is created, which will spawn
/// a libp2p Swarm and continuously poll it.
pub struct NetworkActor {
    // Interface of stronghold-p2p for all network interaction.
    network: StrongholdP2p<ShRequest, ShResult>,
    // Actor registry from which the address of the target client and snapshot actor can be queried.
    registry: Addr<Registry>,
    // Channel through which inbound requests are received.
    // This channel is only inserted temporary on [`NetworkActor::new`], and is handed
    // to the stream handler in `<Self as Actor>::started`.
    _inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<ShRequest, ShResult>>>,
    // Cache the network config so it can be returned on `ExportConfig`.
    _config: NetworkConfig,
}

impl NetworkActor {
    pub async fn new(
        registry: Addr<Registry>,
        mut network_config: NetworkConfig,
        keypair: Option<InitKeypair>,
    ) -> Result<Self, io::Error> {
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
        if let Some(keypair) = keypair {
            builder = builder.with_keys(keypair);
        }

        let network = builder.build().await?;

        let actor = Self {
            network,
            _inbound_request_rx: Some(inbound_request_rx),
            registry,
            _config: network_config,
        };
        Ok(actor)
    }
}

impl Actor for NetworkActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let inbound_request_rx = self._inbound_request_rx.take().unwrap();
        Self::add_stream(inbound_request_rx, ctx);
    }
}

impl StreamHandler<ReceiveRequest<ShRequest, ShResult>> for NetworkActor {
    fn handle(&mut self, item: ReceiveRequest<ShRequest, ShResult>, ctx: &mut Self::Context) {
        let ReceiveRequest {
            request, response_tx, ..
        } = item;

        match request {
            ShRequest::ClientRequest(client) => {
                // handle calls to SecureClient
                sh_request_dispatch!(client, client => |inner| {
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
                })
            }
            ShRequest::SynchronizationRequest(sync) => {
                // handle calls to SynchronizationActor
                sh_request_dispatch!(sync, sync => |inner| {
                    let fut = self.registry
                        .send(GetSynchronizationActor)
                        .and_then(|sync| async move {
                            sync.send(inner).await
                        })
                        .map_ok(|response| response_tx.send(response.into()))
                        .map(|_| ())
                        .into_actor(self);
                    ctx.wait(fut);
                });
            }
        }
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

/// Snapshot handler
// impl<K> Handler<SnapshotRequest<K>> for NetworkActor where K: Zeroize + AsRef<Vec<u8>> {}

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
    use crate::{
        actors::sync::{
            messages::{
                CalculateShapeLocal, CalculateShapeRemote, ComplementSynchronization, EncryptedDataResult,
                FullSynchronizationRemote, PartialSynchronizationRemote,
            },
            SynchronizationError,
        },
        procedures::{Procedure, ProcedureError},
        utils::EntryShape,
        Location, RecordHint, RecordId,
    };
    use engine::vault::ClientId;
    use p2p::{firewall::RuleDirection, EstablishedConnections, Listener, Multiaddr, PeerId};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

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

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ClientRequest {
        CheckVault(CheckVault),
        CheckRecord(CheckRecord),
        ListIds(ListIds),
        WriteToVault(WriteToVault),
        WriteToRemoteVault(WriteToRemoteVault),
        ReadFromStore(ReadFromStore),
        WriteToStore(WriteToStore),
        DeleteFromStore(DeleteFromStore),
        GarbageCollect(GarbageCollect),
        ClearCache(ClearCache),
        Procedure(Procedure),

        #[cfg(test)]
        ReadFromVault(ReadFromVault),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum SynchronizationRequest {
        CalculateShapeRemote(CalculateShapeRemote),
        CalculateShapeLocal(CalculateShapeLocal),
        ComplementSynchronization(ComplementSynchronization),
        FullSynchronization(FullSynchronizationRemote),
        PartialSynchronization(PartialSynchronizationRemote),
    }

    /// Wrapper for Requests to a remote Secure Client
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShRequest {
        ClientRequest(ClientRequest),
        SynchronizationRequest(SynchronizationRequest),
    }

    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::CheckVault from CheckVault);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::CheckRecord from CheckRecord);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::ListIds from ListIds);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::WriteToVault from WriteToVault);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::WriteToRemoteVault from WriteToRemoteVault);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::ReadFromStore from ReadFromStore);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::WriteToStore from WriteToStore);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::DeleteFromStore from DeleteFromStore);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::GarbageCollect from GarbageCollect);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::ClearCache from ClearCache);
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::Procedure from Procedure);

    #[cfg(test)]
    enum_from_inner!(ShRequest::ClientRequest, ClientRequest::ReadFromVault from ReadFromVault);

    enum_from_inner!(ShRequest::SynchronizationRequest, SynchronizationRequest::CalculateShapeRemote from CalculateShapeRemote);
    enum_from_inner!(ShRequest::SynchronizationRequest, SynchronizationRequest::CalculateShapeLocal from CalculateShapeLocal);
    enum_from_inner!(ShRequest::SynchronizationRequest, SynchronizationRequest::ComplementSynchronization from ComplementSynchronization);
    enum_from_inner!(ShRequest::SynchronizationRequest, SynchronizationRequest::FullSynchronization from FullSynchronizationRemote);
    enum_from_inner!(ShRequest::SynchronizationRequest, SynchronizationRequest::PartialSynchronization from PartialSynchronizationRemote);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ShResult {
        Empty(()),
        Data(Option<Vec<u8>>),
        Bool(bool),
        WriteRemoteVault(Result<(), RemoteRecordError>),
        ListIds(Vec<(RecordId, RecordHint)>),
        Proc(Result<CollectedOutput, ProcedureError>),
        Shape(Result<HashMap<Location, EntryShape>, SynchronizationError>),

        Encrypted(Result<EncryptedDataResult, SynchronizationError>),
        FullSynchronization(Result<(ClientId, EncryptedDataResult), SynchronizationError>),
    }

    sh_result_mapping!(ShResult::Empty => ());
    sh_result_mapping!(ShResult::Bool => bool);
    sh_result_mapping!(ShResult::Data => Option<Vec<u8>>);
    sh_result_mapping!(ShResult::ListIds => Vec<(RecordId, RecordHint)>);
    sh_result_mapping!(ShResult::Proc => Result<CollectedOutput, ProcedureError>);

    sh_result_mapping!(ShResult::Shape =>  Result<HashMap<Location, EntryShape>, SynchronizationError>);
    sh_result_mapping!(ShResult::Encrypted =>  Result<EncryptedDataResult, SynchronizationError>);
    sh_result_mapping!(ShResult::FullSynchronization => Result<(ClientId, EncryptedDataResult), SynchronizationError>);

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
