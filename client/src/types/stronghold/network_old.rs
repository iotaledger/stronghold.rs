// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This is the port of client::state::p2p
//!
//! TODO:
//! - Request needs counter to improve security for replay attacks
//!     - both sides: check counters, send counters

use crate::{
    Client, ClientError, Location, RecordError, RemoteMergeError, RemoteVaultError, SnapshotHierarchy, Stronghold,
    SwarmInfo,
};
use crypto::keys::x25519;
use engine::vault::{BlobId, ClientId, RecordHint, RecordId, VaultId};
use futures::{channel::mpsc::TryRecvError, future, stream::FusedStream, Stream};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt, io,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use stronghold_p2p::{
    firewall::{FirewallRequest, FirewallRules, FwRequest, Rule},
    AddressInfo, ChannelSinkConfig, ConnectionLimits, DialErr, EventChannel, InitKeypair, ListenErr, ListenRelayErr,
    Multiaddr, PeerId, ReceiveRequest, RelayNotSupported, StrongholdP2p, StrongholdP2pBuilder,
};

use crate::procedures::{self, ProcedureError, ProcedureOutput, StrongholdProcedure};

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
/// On [`Network::new`] a new [`StrongholdP2p`] is created, which will spawn
/// a libp2p Swarm and continuously poll it.
#[derive(Default)]
pub struct Network {
    /// Interface of stronghold-p2p for all network interaction.
    pub inner:
        Arc<futures::lock::Mutex<Option<StrongholdP2p<StrongholdRequest, StrongholdNetworkResult, AccessRequest>>>>,
    /// Channel through which inbound requests are received.
    /// This channel is only inserted temporary on [`Network::new`], and is handed
    /// to the stream handler in `<Self as Actor>::started`.
    pub inbound_request_rx:
        Option<futures::channel::mpsc::Receiver<ReceiveRequest<StrongholdRequest, StrongholdNetworkResult>>>,
    /// Cache the network config so it can be returned on `ExportConfig`.
    pub config: Arc<futures::lock::Mutex<Option<NetworkConfig>>>,
}

impl Network {
    pub async fn new(mut network_config: NetworkConfig, keypair: Option<InitKeypair>) -> Result<Self, io::Error> {
        // If a firewall channel was given ignore the default rule and use this channel, else use a dummy
        // firewall-channel and set the default rule.
        let (firewall_tx, firewall_default) = match network_config.firewall_tx.clone() {
            Some(tx) => (tx, None),
            None => (
                futures::channel::mpsc::channel(0).0,
                Some(network_config.permissions_default.clone().into_rule()),
            ),
        };
        let (inbound_request_tx, inbound_request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
        let peer_permissions = network_config
            .peer_permissions
            .clone()
            .into_iter()
            .map(|(peer, permissions)| (peer, permissions.into_rule()))
            .collect();
        let rules = FirewallRules::new(firewall_default, peer_permissions);
        let mut builder = StrongholdP2pBuilder::new(firewall_tx, inbound_request_tx, None, rules)
            .with_mdns_support(network_config.enable_mdns)
            .with_relay_support(network_config.enable_relay);
        if let Some(address_info) = network_config.addresses.take() {
            builder = builder.load_addresses(address_info);
        };
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

        Ok(Self {
            inner: Arc::new(futures::lock::Mutex::new(Some(network))),
            inbound_request_rx: Some(inbound_request_rx),
            config: Arc::new(futures::lock::Mutex::new(Some(network_config))),
        })
    }

    /// Send a request
    ///
    /// # Example
    pub async fn send_request(
        &self,
        peer: PeerId,
        request: StrongholdRequest,
    ) -> Result<StrongholdNetworkResult, ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };

        let result = network
            .send_request(peer, request)
            .await
            .map_err(|e| ClientError::Inner(e.to_string()));

        result
    }

    pub async fn export_config(&self) -> Result<NetworkConfig, ClientError> {
        let mut config = self.config.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let config = match &mut *config {
            Some(config) => config,
            None => return Err(ClientError::Inner("No network config present".to_string())),
        };

        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };

        let config = config.clone();
        let address_info = network.export_address_info().await;
        let network_config = config.with_address_info(address_info);
        Ok(network_config)
    }

    /// Sets default firewall rules with [`Permissions`]
    ///
    /// # Example
    pub async fn set_firewall_default(&self, permissions: Permissions) -> Result<(), ClientError> {
        let mut config = self.config.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let config = match &mut *config {
            Some(config) => config,
            None => return Err(ClientError::Inner("No network config present".to_string())),
        };

        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };
        let default_permissions = config.permissions_default_mut();
        *default_permissions = permissions.clone();

        network.set_firewall_default(Some(permissions.into_rule())).await;

        Ok(())
    }

    /// Sets a firewall rule for [`PeerId`] with [`Permissions`]
    ///
    /// # Example
    pub async fn set_firewall_rule(&self, peer: PeerId, permissions: Permissions) -> Result<(), ClientError> {
        let mut config = self.config.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let config = match &mut *config {
            Some(config) => config,
            None => return Err(ClientError::Inner("No network config present".to_string())),
        };

        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };

        config.peer_permissions_mut().insert(peer, permissions.clone());
        network.set_peer_rule(peer, permissions.into_rule()).await;

        Ok(())
    }

    /// Removes a firewall rule for [`PeerId`]
    ///
    /// # Example
    pub async fn remove_firewall_rule(&self, peer: PeerId) -> Result<(), ClientError> {
        let mut config = self.config.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let config = match &mut *config {
            Some(config) => config,
            None => return Err(ClientError::Inner("No network config present".to_string())),
        };

        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };

        config.peer_permissions_mut().remove(&peer);
        network.remove_peer_rule(peer).await;

        Ok(())
    }

    /// Returns the [`SwarmInfo`]
    ///
    /// # Example
    pub async fn get_swarm_info(&self) -> Result<SwarmInfo, ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("".to_string())),
        };

        let listeners = network.listeners().await;
        let local_peer_id = network.peer_id();
        let connections = network.established_connections().await;
        Ok(SwarmInfo {
            local_peer_id,
            listeners,
            connections,
        })
    }

    /// Starts listening on given multiadress or `0.0.0.0` listen on all interfaces
    ///
    /// # Example
    pub async fn start_listenening(&self, multiaddr: Option<Multiaddr>) -> Result<Multiaddr, ListenErr> {
        let mut network = self.inner.try_lock().ok_or(ListenErr::Shutdown)?; // wrong error
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ListenErr::Shutdown), // wrong error
        };
        let addr = multiaddr.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        network.start_listening(addr).await
    }

    /// Start listening as relay
    ///
    /// # Example
    pub async fn start_listening_relay(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ListenRelayErr> {
        let mut network = self.inner.try_lock().ok_or(ListenRelayErr::ProtocolNotSupported)?; // wrong error
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ListenRelayErr::ProtocolNotSupported), // wrong return error
        };
        network.start_relayed_listening(relay, relay_addr).await
    }

    /// Stop listening
    ///
    /// # Example
    pub async fn stop_listening(&self) -> Result<(), ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())), // wrong return error
        };
        network.stop_listening().await;
        Ok(())
    }

    /// Stop listening on [`Multiaddr`]
    ///
    /// # Example
    pub async fn stop_listening_addr(&self, addr: Multiaddr) -> Result<(), ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())), // wrong return error
        };
        network.stop_listening_addr(addr).await;
        Ok(())
    }

    /// Stop listening has relay
    ///
    /// # Example
    pub async fn stop_listening_relay(&self, peer: PeerId) -> Result<(), ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())), // wrong return error
        };

        network.stop_listening_relay(peer).await;

        Ok(())
    }

    /// Try to connect to a peer
    ///
    /// # Example
    pub async fn connect_peer(&self, peer: PeerId) -> Result<Multiaddr, DialErr> {
        let mut network = self.inner.try_lock().ok_or(DialErr::Shutdown)?; // wrong error
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(DialErr::Shutdown), // wrong return error
        };
        network.connect_peer(peer).await
    }

    /// Try to get [`Multiaddr`] from [`PeerId`]
    ///
    /// # Example
    pub async fn get_peer_address(&self, peer: PeerId) -> Result<Vec<Multiaddr>, ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())),
        };

        Ok(network.get_addrs(peer).await)
    }

    /// Adds a [`PeerId`] [`Multiaddr`]
    ///
    /// # Example
    pub async fn add_peer_address(&self, peer: PeerId, address: Multiaddr) -> Result<(), DialErr> {
        let mut network = self.inner.lock().await;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(DialErr::Aborted),
        };

        network.add_address(peer, address).await;
        Ok(())
    }

    /// Removes a [`PeerId`]s [`Multiaddr`]
    ///
    /// # Example
    pub async fn remove_peer_address(&self, peer: PeerId, address: Multiaddr) -> Result<(), ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())),
        };

        network.remove_address(peer, address).await;
        Ok(())
    }

    /// Adds a dialing relay
    ///
    /// # Example
    pub async fn add_dialing_relay(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Result<Option<Multiaddr>, RelayNotSupported>, ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())),
        };

        Ok(network.add_dialing_relay(relay, relay_addr).await)
    }

    /// Removes the dialing relay
    ///
    /// # Example
    pub async fn remove_dialing_relay(&self, peer: PeerId) -> Result<bool, ClientError> {
        let mut network = self.inner.try_lock().ok_or(ClientError::LockAcquireFailed)?;
        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ClientError::Inner("No network handler present".to_string())),
        };

        Ok(network.remove_dialing_relay(peer).await)
    }
}

/// Config for the new network.
///
/// [`Default`] is implemented for [`NetworkConfig`] as [`NetworkConfig::new`] with [`Permissions::allow_none()`].
// Note: The firewall channel can not be serialized and deserialized. Therefore, the channel set via
// [`NetworkConfig::with_async_firewall`] is dropped on serialization, and a new channel has to be provided on
// deserialization. If none is set, the default-permissions will be used to directly approve/ reject requests.
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    request_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    connections_limit: Option<ConnectionLimits>,
    enable_mdns: bool,
    enable_relay: bool,
    addresses: Option<AddressInfo>,

    peer_permissions: HashMap<PeerId, Permissions>,
    permissions_default: Permissions,

    #[serde(skip)]
    firewall_tx: Option<futures::channel::mpsc::Sender<FirewallRequest<AccessRequest>>>,
}

impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("NetworkConfig")
            .field("request_timeout", &self.request_timeout)
            .field("connection_timeout", &self.connection_timeout)
            .field("connections_limit", &self.connections_limit)
            .field("enable_mdns", &self.enable_mdns)
            .field("enable_relay", &self.enable_relay)
            .field("addresses", &self.addresses)
            .field("peer_permissions", &self.peer_permissions)
            .field("permissions_default", &self.permissions_default)
            .field("firewall_tx", &"")
            .finish()
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let connection_limits = ConnectionLimits::default()
            .with_max_established_incoming(Some(10))
            .with_max_pending_incoming(Some(5))
            .with_max_established_per_peer(Some(5));
        NetworkConfig {
            request_timeout: Some(Duration::from_secs(30)),
            connection_timeout: Some(Duration::from_secs(30)),
            connections_limit: Some(connection_limits),
            enable_mdns: false,
            enable_relay: false,
            addresses: None,
            peer_permissions: HashMap::new(),
            permissions_default: Permissions::allow_none(),
            firewall_tx: None,
        }
    }
}

impl NetworkConfig {
    /// Create new network config with the given permission and default config:
    /// - Request-timeout and Connection-timeout are 10s.
    /// - For incoming connections: max 5 pending, max 10 established.
    /// - Max 5 connections to the same peer (per protocol only 1 is needed).
    /// - `libp2p::mdns` protocol is disabled. **Note**: Enabling mdns will broadcast our own address and id to the
    ///   local network.
    /// - `libp2p::relay` functionality is disabled.
    ///
    /// Note: If async firewall rules are enabled through `NetworkConfig::with_async_firewall`, the
    /// `default_permissions` will be ignored. In this case, they only serve as fallback once the channel
    /// gets dropped if the config is written to the stronghold store on [`Stronghold::stop_p2p`].
    pub fn new(default_permissions: Permissions) -> Self {
        NetworkConfig {
            permissions_default: default_permissions,
            ..Default::default()
        }
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

    /// Enable / Disable `libp2p::mdns` protocol.
    /// **Note**: Enabling mdns will broadcast our own address and id to the local network.
    pub fn with_mdns_enabled(mut self, is_enabled: bool) -> Self {
        self.enable_mdns = is_enabled;
        self
    }

    /// Enable / Disable `libp2p::relay` functionality.
    /// This also means that other peers can use us as relay/
    pub fn with_relay_enabled(mut self, is_enabled: bool) -> Self {
        self.enable_relay = is_enabled;
        self
    }

    /// Import known addresses and relays from a past network actor.
    pub fn with_address_info(mut self, info: AddressInfo) -> Self {
        self.addresses = Some(info);
        self
    }

    /// Interact with the firewall asynchronously.
    /// Ignore default rules in the firewall. Instead, when a remote peer sends an inbound request and no explicit
    /// permissions have been set for this peers, a [`PermissionsRequest`] is sent through this channel to
    /// query for the firewall rules that should be applied.
    ///
    /// ```skip
    /// # use iota_stronghold::{p2p::{FirewallChannel, NetworkConfig, Permissions}, Stronghold};
    /// # use futures::StreamExt;
    /// #
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client_path = "client".as_bytes().into();
    /// #
    /// let mut stronghold = Stronghold::init_stronghold_system(client_path, vec![]).await?;
    ///
    /// // Configure the network to use the firewall channel instead of the default permissions.
    /// let (firewall_tx, mut firewall_rx) = FirewallChannel::new();
    /// let mut config = NetworkConfig::new(Permissions::default()).with_async_firewall(firewall_tx);
    ///
    /// stronghold.spawn_p2p(config, None).await?;
    /// stronghold.start_listening(None).await??;
    ///
    /// // Spawn a new task to handle the messages sent through the firewall channel.
    /// actix::System::current().arbiter().spawn(async move {
    ///     loop {
    ///         // For each remote peer without individual permissions, a PermissionsRequest is received here.
    ///         let permission_setter = firewall_rx.select_next_some().await;
    ///         let sender = permission_setter.peer();
    ///
    ///         // Do some logic to set rules for this peer, e.g. by asking the user.
    ///         let permissions = todo!();
    ///
    ///         // Apply the rule for pending and future requests.
    ///         let _ = permission_setter.set_permissions(permissions);
    ///     }
    /// });
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_async_firewall(mut self, firewall_sender: FirewallChannelSender) -> Self {
        self.firewall_tx = Some(firewall_sender.0);
        self
    }

    /// Set default permissions for peers without a peer_specific rule.
    ///
    /// If
    pub fn with_default_permissions(mut self, permissions: Permissions) -> Self {
        self.permissions_default = permissions;
        self
    }

    /// Set the peer-specific permissions.
    pub fn with_peer_permission(mut self, peer: PeerId, permissions: Permissions) -> Self {
        self.peer_permissions.insert(peer, permissions);
        self
    }

    pub(crate) fn peer_permissions_mut(&mut self) -> &mut HashMap<PeerId, Permissions> {
        &mut self.peer_permissions
    }

    pub(crate) fn permissions_default_mut(&mut self) -> &mut Permissions {
        &mut self.permissions_default
    }
}

/// Request to the user to set firewall permissions for a remote peer.
///
/// While this request is pending, inbound requests will be cached and only forwarded or
/// dropped once rules have been set through [`PermissionsRequest::set_permissions`].
pub struct PermissionsRequest {
    peer: PeerId,
    inner_tx: futures::channel::oneshot::Sender<Rule<AccessRequest>>,
}

impl PermissionsRequest {
    /// The peer for which the permissions should be set.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Set firewall permissions for this peer, which will be used to approve pending and future
    /// requests.
    pub fn set_permissions(self, permissions: Permissions) -> Result<(), Permissions> {
        self.inner_tx
            .send(permissions.clone().into_rule())
            .map_err(|_| permissions)
    }
}

/// Sending side of a [`FirewallChannel`] created via [`FirewallChannel::new`].
/// To be passed to the Network on init via [`NetworkConfig::with_async_firewall`].
pub struct FirewallChannelSender(futures::channel::mpsc::Sender<FirewallRequest<AccessRequest>>);

/// Firewall channel for asynchronous firewall interaction.
/// For inbound requests from peers without an explicit firewall rule, this channel is used
/// on the very first inbound request to query for permissions for this peer.
/// If the [`FirewallChannel`] was dropped or not response is sent in time, the inbound requests will be rejected.
#[pin_project]
pub struct FirewallChannel {
    #[pin]
    inner_rx: futures::channel::mpsc::Receiver<FirewallRequest<AccessRequest>>,
}

impl FirewallChannel {
    /// Create a new [`FirewallChannel`] and [`FirewallChannelSender`] pair.
    ///
    /// The `FirewallChannelSender` shall be passed to the `Network` on init via
    /// [`NetworkConfig::with_async_firewall`] on init.
    pub fn new() -> (FirewallChannelSender, Self) {
        let (tx, rx) = futures::channel::mpsc::channel(10);
        (FirewallChannelSender(tx), FirewallChannel { inner_rx: rx })
    }

    /// Close the channel.
    ///
    /// See [`futures::channel::mpsc::Receiver::close`] for more info.
    pub fn close(&mut self) {
        self.inner_rx.close()
    }

    /// Tries to receive the next message.
    ///
    /// See [`futures::channel::mpsc::Receiver::try_next`] for more info.
    pub fn try_next(&mut self) -> Result<Option<PermissionsRequest>, TryRecvError> {
        let request = match self.inner_rx.try_next()? {
            Some(r) => r,
            None => return Ok(None),
        };
        Ok(Some(Self::map_request(request)))
    }

    fn map_request(request: FirewallRequest<AccessRequest>) -> PermissionsRequest {
        match request {
            FirewallRequest::PeerSpecificRule { peer, rule_tx } => PermissionsRequest {
                peer,
                inner_tx: rule_tx,
            },
            _ => unreachable!("Rule::Ask will never be set."),
        }
    }
}

impl Stream for FirewallChannel {
    type Item = PermissionsRequest;

    fn poll_next(self: Pin<&mut FirewallChannel>, cx: &mut Context<'_>) -> Poll<Option<PermissionsRequest>> {
        match self.project().inner_rx.poll_next(cx) {
            Poll::Ready(Some(r)) => Poll::Ready(Some(Self::map_request(r))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner_rx.size_hint()
    }
}

impl FusedStream for FirewallChannel {
    fn is_terminated(&self) -> bool {
        self.inner_rx.is_terminated()
    }
}

/// Permissions for remote peer to operate on the local vault or store of a client.
///
/// Example configuration that:
/// - Per default only allows remote peers to use secrets, but not copy any or write to the vault.
/// - Allows to specific client `open_client` full access.
///
/// ```skip
/// # use iota_stronghold::p2p::{Permissions, ClientAccess};
/// # let open_client = Vec::new();
/// // Only allow to use secrets, but not to clone them or write to the vault.
/// let default = ClientAccess::default().with_default_vault_access(true, false, false);
/// // Create permissions, add exception to allow full access to the client at path `open_client`.
/// let permissions = Permissions::new(default).with_client_permissions(open_client, ClientAccess::allow_all());
/// ```
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Permissions {
    default: ClientAccess,
    exceptions: HashMap<Vec<u8>, ClientAccess>,
}

impl Permissions {
    /// Set `default` permissions to restrict access to the vaults and store of all clients.
    ///
    /// Exceptions for specific client-paths can be set via [`Permissions::with_client_permissions`].
    pub fn new(default: ClientAccess) -> Self {
        Permissions {
            default,
            ..Default::default()
        }
    }

    /// No operations are permitted.
    pub fn allow_none() -> Self {
        Self::default()
    }

    /// All operations on all clients are permitted, including reading, writing and cloning secrets and reading/ writing
    /// to the store,
    pub fn allow_all() -> Self {
        Self {
            default: ClientAccess::allow_all(),
            ..Default::default()
        }
    }

    /// Set default permissions for accessing all clients without any explicit rules.
    pub fn with_default_permissions(mut self, permissions: ClientAccess) -> Self {
        self.default = permissions;
        self
    }

    /// Set permissions for access to specific `client_path`s.
    pub fn with_client_permissions(mut self, client_path: Vec<u8>, permissions: ClientAccess) -> Self {
        self.exceptions.insert(client_path, permissions);
        self
    }

    pub(crate) fn into_rule(self) -> Rule<AccessRequest> {
        let restriction = move |rq: &AccessRequest| self.is_permitted(rq);
        Rule::Restricted {
            restriction: Arc::new(restriction),
            // _maker: PhantomData,
        }
    }

    pub(crate) fn is_permitted(&self, request: &AccessRequest) -> bool {
        self.exceptions
            .get(&request.client_path)
            .unwrap_or(&self.default)
            .is_permitted(request)
    }
}

/// Restrict access to the vaults and store of a specific client.
///
/// - `use_` grants the remote temporary access to use the vault's secret in a procedure.
/// - `write` permits the remote to write to the vault, including the permission to delete secrets.
/// - `clone_` allow the remote to sync with this vault and to clone secrets to their own vault. If the remote cloned a
///   secret, it is not possible to revoke their access to it anymore.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientAccess {
    use_vault_default: bool,
    use_vault_exceptions: HashMap<Vec<u8>, bool>,

    write_vault_default: bool,
    write_vault_exceptions: HashMap<Vec<u8>, bool>,

    clone_vault_default: bool,
    clone_vault_exceptions: HashMap<Vec<u8>, bool>,

    read_store: bool,
    write_store: bool,
}

impl ClientAccess {
    /// Set `default` permissions to restrict access to the vaults and store of a clients.
    /// Exceptions for specific client-paths can be set via [`ClientAccess::with_vault_access`].
    ///
    /// See [`ClientAccess`] docs for more info in the parameters.
    pub fn new(
        use_vault_default: bool,
        write_vault_default: bool,
        clone_vault_default: bool,
        read_store: bool,
        write_store: bool,
    ) -> Self {
        ClientAccess {
            use_vault_default,
            write_vault_default,
            clone_vault_default,
            read_store,
            write_store,
            ..Default::default()
        }
    }

    /// No access to any structures of the vault is permitted.
    pub fn allow_none() -> Self {
        Self::default()
    }

    /// All operations on the client are permitted.
    /// This include reading, writing and cloning secrets, and reading/ writing to the store,
    pub fn allow_all() -> Self {
        ClientAccess {
            use_vault_default: true,
            write_vault_default: true,
            clone_vault_default: true,
            read_store: true,
            write_store: true,
            ..Default::default()
        }
    }

    /// Set default permission for accessing vaults in this client.
    ///
    /// See [`ClientAccess`] docs for more info in the parameters.
    pub fn with_default_vault_access(mut self, use_: bool, write: bool, clone_: bool) -> Self {
        self.use_vault_default = use_;
        self.write_vault_default = write;
        self.clone_vault_default = clone_;
        self
    }

    /// Set specific permissions for accessing the vault at `vault_path`.
    ///
    /// See [`ClientAccess`] docs for more info in the parameters.
    pub fn with_vault_access(mut self, vault_path: Vec<u8>, use_: bool, write: bool, clone_: bool) -> Self {
        self.use_vault_exceptions.insert(vault_path.clone(), use_);
        self.write_vault_exceptions.insert(vault_path.clone(), write);
        self.clone_vault_exceptions.insert(vault_path, clone_);
        self
    }

    /// Set read and write permissions for the client's store.
    pub fn with_store_access(mut self, read: bool, write: bool) -> Self {
        self.read_store = read;
        self.write_store = write;
        self
    }

    /// Check if a inbound request is permitted according to the set permissions.
    pub(crate) fn is_permitted(&self, request: &AccessRequest) -> bool {
        if let Some(approval) = self.fixed_approval() {
            return approval;
        }
        request.required_access.iter().all(|access| match access {
            Access::Use { vault_path } => self
                .use_vault_exceptions
                .get(vault_path)
                .copied()
                .unwrap_or(self.use_vault_default),
            Access::Write { vault_path } => self
                .write_vault_exceptions
                .get(vault_path)
                .copied()
                .unwrap_or(self.write_vault_default),
            Access::Clone { vault_path } => self
                .clone_vault_exceptions
                .get(vault_path)
                .copied()
                .unwrap_or(self.clone_vault_default),
            Access::List { vault_path } => {
                let use_ = self
                    .use_vault_exceptions
                    .get(vault_path)
                    .copied()
                    .unwrap_or(self.use_vault_default);
                let write = self
                    .write_vault_exceptions
                    .get(vault_path)
                    .copied()
                    .unwrap_or(self.write_vault_default);
                let clone_ = self
                    .clone_vault_exceptions
                    .get(vault_path)
                    .copied()
                    .unwrap_or(self.clone_vault_default);
                use_ || write || clone_
            }
            Access::ReadStore => self.read_store,
            Access::WriteStore => self.write_store,
        })
    }

    // Returns the approval that blindly applies for all requests independently
    // of type of access or target vault-path.
    //
    // If there are an vault-exceptions or the approval differs based on the type
    // of access `None is returned`.
    fn fixed_approval(&self) -> Option<bool> {
        if !self.use_vault_exceptions.is_empty()
            || !self.write_vault_exceptions.is_empty()
            || !self.clone_vault_exceptions.is_empty()
        {
            return None;
        }
        if self.use_vault_default
            && self.write_vault_default
            && self.clone_vault_default
            && self.read_store
            && self.write_store
        {
            return Some(true);
        }
        if !self.use_vault_default
            && !self.write_vault_default
            && !self.clone_vault_default
            && !self.read_store
            && !self.write_store
        {
            return Some(false);
        }
        None
    }
}

// Required client, vault and store access of an inbound `ShRequest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Client to which the request should be forwarded.
    pub client_path: Vec<u8>,
    /// List of vault and record access that the ShRequest needs.
    pub required_access: Vec<Access>,
}

// Required access to a vault or the store of a client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Access {
    // Write to a vault.
    Write { vault_path: Vec<u8> },
    // Clone the secret from a vault to the remote's local vault.
    Clone { vault_path: Vec<u8> },
    // Use the secret from the vault in a procedure.
    Use { vault_path: Vec<u8> },
    // List the ids and hints of all entries in the vault.
    List { vault_path: Vec<u8> },
    // Read from the client store.
    ReadStore,
    // Write to the client store.
    WriteStore,
}

impl FwRequest<StrongholdRequest> for AccessRequest {
    fn from_request(request: &StrongholdRequest) -> Self {
        match request {
            StrongholdRequest::ClientRequest { client_path, request } => {
                let client_path = client_path.clone();
                let required_access = match request {
                    ClientRequest::CheckVault { vault_path } => {
                        vec![Access::List {
                            vault_path: vault_path.clone(),
                        }]
                    }
                    ClientRequest::CheckRecord { location } => {
                        vec![Access::List {
                            vault_path: location.vault_path().to_vec(),
                        }]
                    }
                    ClientRequest::DeleteData { location } => {
                        vec![Access::List {
                            vault_path: location.vault_path().to_vec(),
                        }]
                    }
                    // #[cfg(test)]
                    // ClientRequest::ReadFromVault { location } => {
                    //     vec![Access::Clone {
                    //         vault_path: location.vault_path().to_vec(),
                    //     }]
                    // }
                    ClientRequest::WriteToRemoteVault { location, .. } | ClientRequest::RevokeData { location } => {
                        vec![Access::Write {
                            vault_path: location.vault_path().to_vec(),
                        }]
                    }
                    ClientRequest::ReadFromStore { .. } => vec![Access::ReadStore],
                    ClientRequest::WriteToStore { .. } | ClientRequest::DeleteFromStore { .. } => {
                        vec![Access::WriteStore]
                    }
                    ClientRequest::Procedures { procedures } => procedures
                        .iter()
                        .flat_map(|proc| match proc {
                            StrongholdProcedure::RevokeData(procedures::RevokeData { location, .. }) => {
                                vec![Access::Write {
                                    vault_path: location.vault_path().to_vec(),
                                }]
                            }
                            StrongholdProcedure::GarbageCollect(procedures::GarbageCollect { vault_path }) => {
                                vec![Access::Write {
                                    vault_path: vault_path.clone(),
                                }]
                            }
                            proc => {
                                let mut access = Vec::new();
                                if let Some(input) = proc.input() {
                                    access.push(Access::Use {
                                        vault_path: input.vault_path().to_vec(),
                                    });
                                }
                                if let Some(output) = proc.output() {
                                    access.push(Access::Write {
                                        vault_path: output.vault_path().to_vec(),
                                    });
                                }
                                access
                            }
                        })
                        .collect(),
                    ClientRequest::WriteToVault { location, payload } => {
                        vec![Access::Write {
                            vault_path: location.vault_path().to_vec(),
                        }]
                    }
                };
                AccessRequest {
                    client_path,
                    required_access,
                }
            }
            StrongholdRequest::SnapshotRequest { request } => match request {
                SnapshotRequest::GetRemoteHierarchy {} => {
                    // FIXME: this isn't right
                    AccessRequest {
                        client_path: vec![],
                        required_access: vec![Access::Use { vault_path: vec![] }],
                    }
                }
                SnapshotRequest::ExportRemoteDiff { diff, dh_pub_key } => {
                    // FIXME: this isn't right
                    AccessRequest {
                        client_path: vec![],
                        required_access: vec![Access::Use { vault_path: vec![] }],
                    }
                }
            },
        }
    }
}

// #[derive(Debug, Message, Clone, Serialize, Deserialize)]
// #[rtype(result = "Result<(), RemoteRecordError>")]
// pub struct WriteToRemoteVault {
//     pub location: Location,
//     pub payload: Vec<u8>,
//     pub hint: RecordHint,
// }

// impl From<WriteToRemoteVault> for WriteToVault {
//     fn from(t: WriteToRemoteVault) -> Self {
//         let WriteToRemoteVault {
//             location,
//             payload,
//             hint,
//         } = t;
//         WriteToVault {
//             location,
//             payload,
//             hint,
//         }
//     }
// }

// impl From<WriteToVault> for WriteToRemoteVault {
//     fn from(t: WriteToVault) -> Self {
//         let WriteToVault {
//             location,
//             payload,
//             hint,
//         } = t;
//         WriteToRemoteVault {
//             location,
//             payload,
//             hint,
//         }
//     }
// }

pub type RemoteRecordError = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrongholdRequest {
    ClientRequest {
        client_path: Vec<u8>,
        request: ClientRequest,
    },
    SnapshotRequest {
        request: SnapshotRequest,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotRequest {
    GetRemoteHierarchy,
    ExportRemoteDiff {
        diff: SnapshotHierarchy<RecordId>,
        dh_pub_key: [u8; x25519::PUBLIC_KEY_LENGTH],
    },
}

// Wrapper for Requests to a remote Secure Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientRequest {
    CheckVault {
        vault_path: Vec<u8>,
    },

    CheckRecord {
        location: Location,
    },
    // ListIds {
    //     vault_path: Vec<u8>,
    // },
    WriteToRemoteVault {
        location: Location,
        payload: Vec<u8>,
        // we can discard this
        // hint: RecordHint,
    },
    WriteToVault {
        location: Location,
        payload: Vec<u8>,
        // we can discard this
        // hint: RecordHint,
    },
    RevokeData {
        location: Location,
    },
    DeleteData {
        location: Location,
    },
    ReadFromStore {
        key: Vec<u8>,
    },
    WriteToStore {
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    },
    DeleteFromStore {
        key: Vec<u8>,
    },
    Procedures {
        procedures: Vec<StrongholdProcedure>,
    },
    // #[cfg(test)]
    // ReadFromVault {
    //     location: Location,
    // },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrongholdNetworkResult {
    Empty(()), // macro failure to require empty tuple
    Data(Option<Vec<u8>>),
    Bool(bool),
    WriteRemoteVault(Result<(), RemoteRecordError>),
    ListIds(Vec<(RecordId, RecordHint)>),
    Proc(Result<Vec<ProcedureOutput>, ProcedureError>),

    // add to support snapshot format
    Hierarchy(Result<SnapshotHierarchy<(RecordId, BlobId)>, RemoteVaultError>),
    Exported(Result<(Vec<u8>, [u8; x25519::PUBLIC_KEY_LENGTH]), RemoteMergeError>),
}

sh_result_mapping!(StrongholdNetworkResult::Empty => ());
sh_result_mapping!(StrongholdNetworkResult::Bool => bool);
sh_result_mapping!(StrongholdNetworkResult::Data => Option<Vec<u8>>);
sh_result_mapping!(StrongholdNetworkResult::ListIds => Vec<(RecordId, RecordHint)>);
sh_result_mapping!(StrongholdNetworkResult::Proc => Result<Vec<ProcedureOutput>, ProcedureError>);

// added support for snapshot
sh_result_mapping!(StrongholdNetworkResult::Hierarchy => Result<SnapshotHierarchy<(RecordId, BlobId)>, RemoteVaultError>);
sh_result_mapping!(StrongholdNetworkResult::Exported => Result<(Vec<u8>, [u8; x25519::PUBLIC_KEY_LENGTH]), RemoteMergeError>);

impl From<Result<(), RecordError>> for StrongholdNetworkResult {
    fn from(inner: Result<(), RecordError>) -> Self {
        StrongholdNetworkResult::WriteRemoteVault(inner.map_err(|e| e.to_string()))
    }
}

impl TryFrom<StrongholdNetworkResult> for Result<(), RemoteRecordError> {
    type Error = ();
    fn try_from(t: StrongholdNetworkResult) -> Result<Self, Self::Error> {
        if let StrongholdNetworkResult::WriteRemoteVault(result) = t {
            Ok(result)
        } else {
            Err(())
        }
    }
}
