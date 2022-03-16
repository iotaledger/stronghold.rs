// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{
        secure_messages::{
            CheckRecord, CheckVault, DeleteFromStore, ListIds, Procedures, ReadFromStore, RevokeData, WriteToStore,
            WriteToVault,
        },
        RecordError, Registry,
    },
    enum_from_inner,
    procedures::{self, ProcedureError, ProcedureOutput, StrongholdProcedure},
    Location, RecordHint, RecordId,
};
use actix::prelude::*;
use futures::{
    channel::{
        mpsc::{self, TryRecvError},
        oneshot,
    },
    stream::FusedStream,
    task::{Context, Poll},
};
use p2p::{
    firewall::{FirewallRequest, FirewallRules, FwRequest, Rule},
    AddressInfo, ChannelSinkConfig, ConnectionLimits, EventChannel, InitKeypair, PeerId, ReceiveRequest, StrongholdP2p,
    StrongholdP2pBuilder,
};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt, io, marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

#[cfg(test)]
use crate::actors::secure_testing::ReadFromVault;

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
pub struct Network {
    /// Interface of stronghold-p2p for all network interaction.
    pub network: StrongholdP2p<ShRequest, ShResult, AccessRequest>,
    /// Actor registry from which the address of the target client and snapshot actor can be queried.
    pub registry: Addr<Registry>,
    /// Channel through which inbound requests are received.
    /// This channel is only inserted temporary on [`Network::new`], and is handed
    /// to the stream handler in `<Self as Actor>::started`.
    pub _inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<ShRequest, ShResult>>>,
    /// Cache the network config so it can be returned on `ExportConfig`.
    pub _config: NetworkConfig,
}

impl Network {
    pub async fn new(
        registry: Addr<Registry>,
        mut network_config: NetworkConfig,
        keypair: Option<InitKeypair>,
    ) -> Result<Self, io::Error> {
        // If a firewall channel was given ignore the default rule and use this channel, else use a dummy
        // firewall-channel and set the default rule.
        let (firewall_tx, firewall_default) = match network_config.firewall_tx.clone() {
            Some(tx) => (tx, None),
            None => (
                mpsc::channel(0).0,
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
        let actor = Self {
            network,
            _inbound_request_rx: Some(inbound_request_rx),
            registry,
            _config: network_config,
        };
        Ok(actor)
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
    firewall_tx: Option<mpsc::Sender<FirewallRequest<AccessRequest>>>,
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
    /// - [`Mdns`][`libp2p::mdns`] protocol is disabled. **Note**: Enabling mdns will broadcast our own address and id
    ///   to the local network.
    /// - [`Relay`][`libp2p::relay`] functionality is disabled.
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

    /// Import known addresses and relays from a past network actor.
    pub fn with_address_info(mut self, info: AddressInfo) -> Self {
        self.addresses = Some(info);
        self
    }

    /// Interact with the firewall in an asynchronous manner.
    /// Ignore default rules in the firewall. Instead, when a remote peer sends an inbound request and no explicit
    /// permissions have been set for this peers, a [`PermissionsRequest`] is sent through this channel to
    /// query for the firewall rules that should be applied.
    ///
    /// ```
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
    inner_tx: oneshot::Sender<Rule<AccessRequest>>,
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
pub struct FirewallChannelSender(mpsc::Sender<FirewallRequest<AccessRequest>>);

/// Firewall channel for asynchronous firewall interaction.
/// For inbound requests from peers without an explicit firewall rule, this channel is used
/// on the very first inbound request to query for permissions for this peer.
/// If the [`FirewallChannel`] was dropped or not response is sent in time, the inbound requests will be rejected.
#[pin_project]
pub struct FirewallChannel {
    #[pin]
    inner_rx: mpsc::Receiver<FirewallRequest<AccessRequest>>,
}

impl FirewallChannel {
    /// Create a new [`FirewallChannel`] and [`FirewallChannelSender`] pair.
    ///
    /// The `FirewallChannelSender` shall be passed to the `Network` on init via
    /// [`NetworkConfig::with_async_firewall`] on init.
    pub fn new() -> (FirewallChannelSender, Self) {
        let (tx, rx) = mpsc::channel(10);
        (FirewallChannelSender(tx), FirewallChannel { inner_rx: rx })
    }

    /// Close the channel.
    ///
    /// See [`mpsc::Receiver::close`] for more info.
    pub fn close(&mut self) {
        self.inner_rx.close()
    }

    /// Tries to receive the next message.
    ///
    /// See [`mpsc::Receiver::try_next`] for more info.
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
/// ```
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
            _maker: PhantomData,
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

impl FwRequest<ShRequest> for AccessRequest {
    fn from_request(request: &ShRequest) -> Self {
        let client_path = request.client_path.clone();
        let required_access = match &request.request {
            Request::CheckVault(CheckVault { vault_path }) | Request::ListIds(ListIds { vault_path }) => {
                vec![Access::List {
                    vault_path: vault_path.clone(),
                }]
            }
            Request::CheckRecord(CheckRecord { location }) => {
                vec![Access::List {
                    vault_path: location.vault_path().to_vec(),
                }]
            }
            #[cfg(test)]
            Request::ReadFromVault(ReadFromVault { location }) => {
                vec![Access::Clone {
                    vault_path: location.vault_path().to_vec(),
                }]
            }
            Request::WriteToRemoteVault(WriteToRemoteVault { location, .. })
            | Request::RevokeData(RevokeData { location }) => {
                vec![Access::Write {
                    vault_path: location.vault_path().to_vec(),
                }]
            }
            Request::ReadFromStore(ReadFromStore { .. }) => vec![Access::ReadStore],
            Request::WriteToStore(WriteToStore { .. }) | Request::DeleteFromStore(DeleteFromStore { .. }) => {
                vec![Access::WriteStore]
            }
            Request::Procedures(p) => p
                .procedures
                .iter()
                .flat_map(|proc| match proc {
                    StrongholdProcedure::RevokeData(procedures::RevokeData { location, .. }) => vec![Access::Write {
                        vault_path: location.vault_path().to_vec(),
                    }],
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
        };
        AccessRequest {
            client_path,
            required_access,
        }
    }
}

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
pub struct ShRequest {
    pub client_path: Vec<u8>,
    pub request: Request,
}

// Wrapper for Requests to a remote Secure Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    CheckVault(CheckVault),
    CheckRecord(CheckRecord),
    ListIds(ListIds),
    #[cfg(test)]
    ReadFromVault(ReadFromVault),
    WriteToRemoteVault(WriteToRemoteVault),
    RevokeData(RevokeData),
    ReadFromStore(ReadFromStore),
    WriteToStore(WriteToStore),
    DeleteFromStore(DeleteFromStore),
    Procedures(Procedures),
}

enum_from_inner!(Request from CheckVault);
enum_from_inner!(Request from ListIds);
#[cfg(test)]
enum_from_inner!(Request from ReadFromVault);
enum_from_inner!(Request from WriteToRemoteVault);
enum_from_inner!(Request from RevokeData);
enum_from_inner!(Request from ReadFromStore);
enum_from_inner!(Request from WriteToStore);
enum_from_inner!(Request from DeleteFromStore);
enum_from_inner!(Request from Procedures);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShResult {
    Empty(()),
    Data(Option<Vec<u8>>),
    Bool(bool),
    WriteRemoteVault(Result<(), RemoteRecordError>),
    ListIds(Vec<(RecordId, RecordHint)>),
    Proc(Result<Vec<ProcedureOutput>, ProcedureError>),
}

sh_result_mapping!(ShResult::Empty => ());
sh_result_mapping!(ShResult::Bool => bool);
sh_result_mapping!(ShResult::Data => Option<Vec<u8>>);
sh_result_mapping!(ShResult::ListIds => Vec<(RecordId, RecordHint)>);
sh_result_mapping!(ShResult::Proc => Result<Vec<ProcedureOutput>, ProcedureError>);

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
