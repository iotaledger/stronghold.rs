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
use futures::channel::mpsc;
use p2p::{
    firewall::{FirewallConfiguration, FirewallRules, FwRequest, Rule},
    AddressInfo, ChannelSinkConfig, ConnectionLimits, EventChannel, InitKeypair, PeerId, ReceiveRequest, StrongholdP2p,
    StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, io, marker::PhantomData, sync::Arc, time::Duration};

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
    // Interface of stronghold-p2p for all network interaction.
    pub network: StrongholdP2p<ShRequest, ShResult, AccessRequest>,
    // Actor registry from which the address of the target client and snapshot actor can be queried.
    pub registry: Addr<Registry>,
    // Channel through which inbound requests are received.
    // This channel is only inserted temporary on [`Network::new`], and is handed
    // to the stream handler in `<Self as Actor>::started`.
    pub _inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<ShRequest, ShResult>>>,
    // Cache the network config so it can be returned on `ExportConfig`.
    pub _config: NetworkConfig,
}

impl Network {
    pub async fn new(
        registry: Addr<Registry>,
        mut network_config: NetworkConfig,
        keypair: Option<InitKeypair>,
    ) -> Result<Self, io::Error> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (inbound_request_tx, inbound_request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
        let firewall_default = FirewallRules {
            inbound: Some(network_config.permissions_default.clone().into_rule()),
            outbound: Some(Rule::AllowAll),
        };
        let peer_permissions = network_config
            .peer_permissions
            .clone()
            .into_iter()
            .map(|(peer, permissions)| {
                let rules = FirewallRules {
                    inbound: Some(permissions.into_rule()),
                    outbound: Some(Rule::AllowAll),
                };
                (peer, rules)
            })
            .collect();
        let firewall_config = FirewallConfiguration {
            default: firewall_default,
            peer_rules: peer_permissions,
        };
        let mut builder = StrongholdP2pBuilder::new(firewall_tx, inbound_request_tx, None, firewall_config)
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
/// Note: [`Default`] is implemented for [`NetworkConfig`] as [`NetworkConfig::new`] with [`Permissions::allow_none()`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    request_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    connections_limit: Option<ConnectionLimits>,
    enable_mdns: bool,
    enable_relay: bool,
    addresses: Option<AddressInfo>,

    peer_client_mapping: HashMap<PeerId, Option<ClientMapping>>,
    client_mapping_default: Option<ClientMapping>,

    peer_permissions: HashMap<PeerId, Permissions>,
    permissions_default: Permissions,
}

impl NetworkConfig {
    /// Create new network config with the given permission and default config:
    /// - No limit for simultaneous connections.
    /// - Request-timeout and Connection-timeout are 10s.
    /// - [`Mdns`][`libp2p::mdns`] protocol is disabled. **Note**: Enabling mdns will broadcast our own address and id
    ///   to the local network.
    /// - [`Relay`][`libp2p::relay`] functionality is disabled.
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

    /// Extend the peer-specific permissions.
    pub fn with_peer_permission(mut self, permissions: HashMap<PeerId, Permissions>) -> Self {
        self.peer_permissions.extend(permissions);
        self
    }

    /// Set default mapping for inbound requests to a target client.
    ///
    /// This maps the `client_path` that is sent from the remote (as part of their request) to a local
    /// target client with another `client_path`.
    /// In case of `None` the client_path remains unchanged.
    pub fn with_default_client_mapping(mut self, mapping: Option<ClientMapping>) -> Self {
        self.client_mapping_default = mapping;
        self
    }

    /// Extend mapping for inbound requests to a target client from specific peers.
    ///
    /// See [`NetworkConfig::with_default_client_mapping`].
    pub fn with_peer_client_mapping(mut self, map: HashMap<PeerId, Option<ClientMapping>>) -> Self {
        self.peer_client_mapping.extend(map);
        self
    }

    pub(crate) fn peer_permissions_mut(&mut self) -> &mut HashMap<PeerId, Permissions> {
        &mut self.peer_permissions
    }

    pub(crate) fn permissions_default_mut(&mut self) -> &mut Permissions {
        &mut self.permissions_default
    }

    pub(crate) fn peer_client_mapping_mut(&mut self) -> &mut HashMap<PeerId, Option<ClientMapping>> {
        &mut self.peer_client_mapping
    }

    pub(crate) fn client_mapping_default_mut(&mut self) -> &mut Option<ClientMapping> {
        &mut self.client_mapping_default
    }
}

/// Permissions for remote peers to operate on the local vault or store of a client.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Permissions {
    default: Option<ClientPermissions>,
    exceptions: HashMap<Vec<u8>, Option<ClientPermissions>>,
}

impl Permissions {
    /// No operations are permitted.
    pub fn allow_none() -> Self {
        Self::default()
    }

    /// All operations on all clients are permitted, including reading, writing and cloning secrets and reading/ writing
    /// to the store,
    pub fn allow_all() -> Self {
        Self {
            default: Some(ClientPermissions::all()),
            ..Default::default()
        }
    }

    /// Set default permissions for accessing all clients without any explicit rules.
    ///
    /// In case of `None` no access is permitted.
    pub fn with_default_permissions(mut self, permissions: Option<ClientPermissions>) -> Self {
        self.default = permissions;
        self
    }

    /// Extend permissions for access to specific `client_path`s.
    ///
    /// In case of `None` no access to this client is permitted.
    pub fn extend_client_permissions(mut self, permissions: HashMap<Vec<u8>, Option<ClientPermissions>>) -> Self {
        self.exceptions.extend(permissions);
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
        match self.exceptions.get(&request.client_path).unwrap_or(&self.default) {
            Some(p) => p.is_permitted(request),
            None => false,
        }
    }
}

/// Restrict access to the vaults and store of a specific client.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientPermissions {
    use_vault_default: bool,
    use_vault_exceptions: HashMap<Vec<u8>, bool>,

    write_vault_default: bool,
    write_vault_exceptions: HashMap<Vec<u8>, bool>,

    clone_vault_default: bool,
    clone_vault_exceptions: HashMap<Vec<u8>, bool>,

    read_store: bool,
    write_store: bool,
}

impl ClientPermissions {
    /// No access to any structures of the vault is permitted.
    pub fn none() -> Self {
        Self::default()
    }
    /// All operations on the client are permitted.
    /// This include reading, writing and cloning secrets, and reading/ writing to the store,
    pub fn all() -> Self {
        ClientPermissions {
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
    /// - `use_` grants the remote temporary access to use the vault's secret in a procedure.
    /// - `write` permits the remote to write to the vault, including the permission to delete secrets.
    /// - `clone_` allow the remote to sync with this vault and to clone secrets to their own vault. If the remote
    ///   cloned a secret, it is not possible to revoke their access to it anymore.
    pub fn with_default_vault_access(mut self, use_: bool, write: bool, clone_: bool) -> Self {
        self.use_vault_default = use_;
        self.write_vault_default = write;
        self.clone_vault_default = clone_;
        self
    }

    /// Set specific permissions for accessing the vault at `vault_path`.
    ///
    /// See [`ClientPermissions::with_default_vault_access`] for more info in the parameters.
    pub fn with_vault_access(mut self, vault_path: Vec<u8>, use_: bool, write: bool, clone_: bool) -> Self {
        self.use_vault_exceptions.insert(vault_path.clone(), use_);
        self.use_vault_exceptions.insert(vault_path.clone(), write);
        self.use_vault_exceptions.insert(vault_path, clone_);
        self
    }

    /// Set read and write permissions for the client's store.
    pub fn with_store_access(mut self, read: bool, write: bool) -> Self {
        self.read_store = read;
        self.write_store = write;
        self
    }

    // Check if a inbound request is permitted according to the set permissions.
    pub(crate) fn is_permitted(&self, request: &AccessRequest) -> bool {
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
}

// Required client, vault and store access of an inbound `ShRequest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessRequest {
    // Client to which the request should be forwarded.
    // Note: this is already the mapped client_path. See `ClientMapping`.
    pub client_path: Vec<u8>,
    // List of vault and record access that the ShRequest needs.
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

/// Map the `client_path` requested by the remote peer to a local
/// `client_path`.
///
/// Request from / to a remote peer include a path of the client to which
/// the requests should be forwarded. [`ClientMapping`] allows to map this
/// client_path to a local one. In case of `None` the requested `client_path` is kept
/// as it is.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientMapping {
    /// Map specific `client_path`s to local `client_path`s.
    pub map_client_paths: HashMap<Vec<u8>, Option<Vec<u8>>>,

    /// Default mapping for all requested `client_path`s for which not extra rule has been set.
    pub default: Option<Vec<u8>>,
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
