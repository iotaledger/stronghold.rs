// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Main Stronghold Interface
//!
//! All functionality can be accessed from the interface. Functions
//! are provided in an asynchronous way, and should be run by the
//! actor's system [`SystemRunner`].

use crate::{
    actors::{
        secure_messages::{
            CheckRecord, CheckVault, ClearCache, CreateVault, DeleteFromStore, GarbageCollect, GetData, ListIds,
            ReadFromStore, ReloadData, RevokeData, WriteToStore, WriteToVault,
        },
        snapshot_messages::{FillSnapshot, ReadFromSnapshot, WriteSnapshot},
        GetAllClients, GetClient, GetSnapshot, GetTarget, Registry, RemoveClient, SecureClient, SpawnClient,
        SwitchTarget, VaultError,
    },
    procedures::{CollectedOutput, Procedure, ProcedureError},
    state::snapshot::{ReadError, WriteError},
    utils::{LoadFromPath, StrongholdFlags, VaultFlags},
    Location,
};
use engine::vault::{ClientId, RecordHint, RecordId};
#[cfg(feature = "p2p")]
use p2p::{DialErr, ListenErr, ListenRelayErr, OutboundFailure, RelayNotSupported};

use actix::prelude::*;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use thiserror::Error as DeriveError;
use zeroize::Zeroize;

#[cfg(test)]
use crate::actors::ReadFromVault;
#[cfg(feature = "p2p")]
use crate::actors::{
    p2p::{messages as network_msg, NetworkActor, NetworkConfig, ShRequest, SwarmInfo},
    GetNetwork, InsertNetwork, StopNetwork,
};
#[cfg(feature = "p2p")]
use p2p::{
    firewall::{Rule, RuleDirection},
    Multiaddr, PeerId,
};
#[cfg(feature = "p2p")]
use std::io;

pub type StrongholdResult<T> = Result<T, ActorError>;

#[derive(DeriveError, Debug)]
pub enum ActorError {
    #[error("actor mailbox error: {0}")]
    Mailbox(#[from] MailboxError),
    #[error("target actor has not been spawned or was killed")]
    TargetNotFound,
}

#[cfg(feature = "p2p")]
pub type P2pResult<T> = Result<T, P2pError>;

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug)]
pub enum P2pError {
    #[error("local actor error: {0}")]
    Local(#[from] ActorError),
    #[error("sending request to remote stronghold failed: {0}")]
    SendRequest(#[from] OutboundFailure),
}

#[cfg(feature = "p2p")]
impl From<MailboxError> for P2pError {
    fn from(e: MailboxError) -> Self {
        P2pError::Local(e.into())
    }
}

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug)]
pub enum SpawnNetworkError {
    #[error("actor mailbox error: {0}")]
    ActorMailbox(#[from] MailboxError),

    #[error("network already running")]
    AlreadySpawned,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
#[error("fatal engine error {0}")]
pub struct FatalEngineError(String);

impl From<VaultError> for FatalEngineError {
    fn from(e: VaultError) -> Self {
        FatalEngineError(e.to_string())
    }
}

#[cfg(feature = "p2p")]
impl From<network_msg::RemoteVaultError> for FatalEngineError {
    fn from(e: network_msg::RemoteVaultError) -> Self {
        FatalEngineError(e.to_string())
    }
}

impl From<String> for FatalEngineError {
    fn from(e: String) -> Self {
        FatalEngineError(e)
    }
}

#[derive(Clone)]
/// The main type for the Stronghold System.  Used as the entry point for the actor model.  Contains various pieces of
/// metadata to interpret the data in the vault and store.
pub struct Stronghold {
    registry: Addr<Registry>,
}

impl Stronghold {
    /// Initializes a new instance of the system asynchronously.  Sets up the first client actor. Accepts
    /// the first client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
    /// The [`actix::SystemRunner`] is not being used directly by stronghold, and must be initialized externally.
    pub async fn init_stronghold_system(
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StrongholdResult<Self> {
        // Init actor registry.
        let registry = Registry::default().start();

        // create client actor
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        registry.send(SpawnClient { id: client_id }).await?;

        Ok(Self { registry })
    }

    /// Spawn a new client for the Stronghold system and switch the actor target to it.
    /// Accepts the client_path: [`Vec<u8>`] and the options: `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone());
        self.registry.send(SpawnClient { id: client_id }).await?;
        Ok(())
    }

    /// Switches the actor target to another actor in the system specified by the client_path: [`Vec<u8>`].
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        self.switch_client(client_id).await.map(|_| ())
    }

    /// Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified
    /// location of [`Location`] type. The payload must be specified as a [`Vec<u8>`] and a [`RecordHint`] can be
    /// provided. Also accepts [`VaultFlags`] for when a new Vault is created.
    pub async fn write_to_vault(
        &self,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let target = self.target().await?;

        let vault_path = location.vault_path().to_vec();

        let vault_exists = target.send(CheckVault { vault_path }).await?;
        if !vault_exists {
            // does not exist
            target
                .send(CreateVault {
                    location: location.clone(),
                })
                .await?;
        }
        // write to vault
        let res = target
            .send(WriteToVault {
                location,
                payload,
                hint,
            })
            .await?
            .map_err(FatalEngineError::from);
        Ok(res)
    }

    /// Writes data into an insecure cache.  This method, accepts a [`Vec<u8>`] as key, a [`Vec<u8>`] payload, and an
    /// optional [`Duration`]. The lifetime allows the data to be deleted after the specified duration has passed.
    /// If no lifetime is specified, the data will persist until it is manually deleted or over-written.
    /// Returns [`None`] if the key didn't exist yet. If the key is already present, the value is updated, and the old
    /// value is returned.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn write_to_store(
        &self,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let existing = target.send(WriteToStore { key, payload, lifetime }).await?;
        Ok(existing)
    }

    /// A method that reads from an insecure cache. This method, accepts a [`Vec<u8>`] as key and returns the payload
    /// in the form of a ([`Vec<u8>`].  If the key does not exist, `None` is returned.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn read_from_store(&self, key: Vec<u8>) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let data = target.send(ReadFromStore { key }).await?;
        Ok(data)
    }

    /// A method to delete data from an insecure cache. This method, accepts a [`Vec<u8>`] as key.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn delete_from_store(&self, key: Vec<u8>) -> StrongholdResult<()> {
        let target = self.target().await?;
        target.send(DeleteFromStore { key }).await?;
        Ok(())
    }

    /// Revokes the data from the specified location of type [`Location`]. Revoked data is not readable and can be
    /// removed from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call
    /// with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(
        &self,
        location: Location,
        should_gc: bool,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let target = self.target().await?;
        let res = target
            .send(RevokeData {
                location: location.clone(),
            })
            .await?;
        match res {
            Ok(_) => {}
            Err(e) => return Ok(Err(FatalEngineError::from(e))),
        };

        if should_gc {
            target.send(GarbageCollect { location }).await?;
        }
        Ok(Ok(()))
    }

    /// Garbage collects any revokes in a Vault based on the given `vault_path` and the current target actor.
    ///
    /// Return `false` if the vault does not exist.
    pub async fn garbage_collect<V: Into<Vec<u8>>>(&self, vault_path: V) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let vault_exists = target
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path: vault_path.into(),
                    record_path: Vec::new(),
                },
            })
            .await?;
        Ok(vault_exists)
    }

    /// Returns a list of the available [`RecordId`] and [`RecordHint`] values in a vault by the given `vault_path`.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> StrongholdResult<Vec<(RecordId, RecordHint)>> {
        let target = self.target().await?;
        let list = target
            .send(ListIds {
                vault_path: vault_path.into(),
            })
            .await?;
        Ok(list)
    }

    /// Executes a runtime command given a [`Procedure`].  Returns a [`ProcResult`] based off of the control_request
    /// specified.
    pub async fn runtime_exec<P>(&self, control_request: P) -> StrongholdResult<Result<CollectedOutput, ProcedureError>>
    where
        P: Into<Procedure>,
    {
        let target = self.target().await?;
        let result = target.send::<Procedure>(control_request.into()).await?;
        Ok(result)
    }

    /// Checks whether a record exists in the client based off of the given [`Location`].
    pub async fn record_exists(&self, location: Location) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let exists = target.send(CheckRecord { location }).await?;
        Ok(exists)
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists<V: Into<Vec<u8>>>(&self, vault_path: V) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let exists = target
            .send(CheckVault {
                vault_path: vault_path.into(),
            })
            .await?;
        Ok(exists)
    }

    /// Reads data from a given snapshot file.  Can only read the data for a single `client_path` at a time. If the new
    /// actor uses a new `client_path` the former client path may be passed into the function call to read the data into
    /// that actor. Also requires keydata to unlock the snapshot. A filename and filepath can be specified. The Keydata
    /// should implement and use Zeroize.
    pub async fn read_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        client_path: Vec<u8>,
        former_client_path: Option<Vec<u8>>,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StrongholdResult<Result<(), ReadError>> {
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        let former_client_id = former_client_path.map(|cp| ClientId::load_from_path(&cp, &cp));

        // this feature resembles the functionality given by the former riker
        // system dependence. if there is a former client id path present,
        // the new actor is being changed into the former one ( see old ReloadData impl.)
        let target;
        if let Some(id) = former_client_id {
            target = self.switch_client(id).await?;
        } else {
            target = self.target().await?;
        }

        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        // get address of snapshot actor
        let snapshot_actor = self.registry.send(GetSnapshot {}).await?;

        // read the snapshots contents
        let result = snapshot_actor
            .send(ReadFromSnapshot {
                key,
                filename,
                path,
                id: client_id,
                fid: former_client_id,
            })
            .await?;
        let content = match result {
            Ok(content) => content,
            Err(e) => return Ok(Err(e)),
        };

        // send data to secure actor and reload
        target
            .send(ReloadData {
                data: content.data,
                id: content.id,
            })
            .await?;
        Ok(Ok(()))
    }

    /// Writes the entire state of the [`Stronghold`] into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StrongholdResult<Result<(), WriteError>> {
        // this should be delegated to the secure client actor
        // wrapping the interior functionality inside it.
        let clients: Vec<(ClientId, Addr<SecureClient>)> = self.registry.send(GetAllClients).await?;

        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();
        key.copy_from_slice(keydata);

        // get snapshot actor
        let snapshot = self.registry.send(GetSnapshot {}).await?;

        for (id, client) in clients {
            // get data from secure actor
            let data = client.send(GetData {}).await?;

            // fill into snapshot
            snapshot.send(FillSnapshot { data, id }).await?;
        } // end loop

        // write snapshot
        let res = snapshot.send(WriteSnapshot { key, filename, path }).await?;
        Ok(res)
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true`, the actor will be removed from the system.  Otherwise, the cache of the
    /// current target actor will be cleared.
    ///
    /// **Note**: If `kill_actor` is set to `true` and the target is the currently active client, a new client has to be
    /// set via [`Stronghold::switch_actor_target`], before any following operations can be performed.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path.clone(), &client_path);
        let client;
        if kill_actor {
            client = self
                .registry
                .send(RemoveClient { id: client_id })
                .await?
                .ok_or(ActorError::TargetNotFound)?;
        } else {
            client = self
                .registry
                .send(GetClient { id: client_id })
                .await?
                .ok_or(ActorError::TargetNotFound)?;
        }
        client.send(ClearCache).await?;
        Ok(())
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    // API CHANGE!
    #[cfg(test)]
    pub async fn read_secret(&self, _client_path: Vec<u8>, location: Location) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let secret = target.send(ReadFromVault { location }).await?;
        Ok(secret)
    }

    async fn switch_client(&mut self, client_id: ClientId) -> StrongholdResult<Addr<SecureClient>> {
        self.registry
            .send(SwitchTarget { id: client_id })
            .await?
            .ok_or(ActorError::TargetNotFound)
    }

    async fn target(&self) -> StrongholdResult<Addr<SecureClient>> {
        self.registry.send(GetTarget).await?.ok_or(ActorError::TargetNotFound)
    }
}

#[cfg(feature = "p2p")]
impl Stronghold {
    /// Spawn the p2p-network actor and swarm.
    pub async fn spawn_p2p(
        &mut self,
        firewall_rule: Rule<ShRequest>,
        network_config: NetworkConfig,
    ) -> Result<(), SpawnNetworkError> {
        if self.registry.send(GetNetwork).await?.is_some() {
            return Err(SpawnNetworkError::AlreadySpawned);
        }
        let addr = NetworkActor::new(self.registry.clone(), firewall_rule, network_config)
            .await?
            .start();
        self.registry.send(InsertNetwork { addr }).await?;
        Ok(())
    }

    /// Gracefully stop the network actor and swarm.
    /// Return `false` if there is no active network actor.
    pub async fn stop_p2p(&mut self) -> StrongholdResult<()> {
        match self.registry.send(StopNetwork).await? {
            true => Ok(()),
            false => Err(ActorError::TargetNotFound),
        }
    }

    /// Start listening on the swarm to the given address. If not address is provided, it will be assigned by the OS.
    pub async fn start_listening(&self, address: Option<Multiaddr>) -> StrongholdResult<Result<Multiaddr, ListenErr>> {
        let actor = self.network_actor().await?;
        let result = actor.send(network_msg::StartListening { address }).await?;
        Ok(result)
    }

    /// Stop listening on the swarm.
    pub async fn stop_listening(&self) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_msg::StopListening).await?;
        Ok(())
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(&self) -> StrongholdResult<SwarmInfo> {
        let actor = self.network_actor().await?;
        let info = actor.send(network_msg::GetSwarmInfo).await?;
        Ok(info)
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by the address if one is provided, or by peer id
    /// if the peer is already known e.g. from multicast DNS.
    /// If the peer is not a relay and can not be reached directly, it will be attempted to reach it via the relays,
    /// if there are any.
    pub async fn add_peer(
        &self,
        peer: PeerId,
        address: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Multiaddr, DialErr>> {
        let actor = self.network_actor().await?;
        if let Some(address) = address {
            actor.send(network_msg::AddPeerAddr { peer, address }).await?;
        }
        let result = actor.send(network_msg::ConnectPeer { peer }).await?;
        Ok(result)
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Option<Multiaddr>, RelayNotSupported>> {
        let actor = self.network_actor().await?;
        let result = actor.send(network_msg::AddDialingRelay { relay, relay_addr }).await?;
        Ok(result)
    }

    /// Start listening via a relay peer on an address following the scheme
    /// `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    pub async fn start_relayed_listening(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Multiaddr, ListenRelayErr>> {
        let actor = self.network_actor().await?;
        let result = actor
            .send(network_msg::StartListeningRelay { relay, relay_addr })
            .await?;
        Ok(result)
    }

    /// Stop listening with the relay.
    pub async fn remove_listening_relay(&self, relay: PeerId) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_msg::StopListeningRelay { relay }).await?;
        Ok(())
    }

    /// Remove a peer from the list of peers used for dialing.
    pub async fn remove_dialing_relay(&self, relay: PeerId) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_msg::RemoveDialingRelay { relay }).await?;
        Ok(())
    }

    /// Change the firewall rule for specific peers, optionally also set it as the default rule, which applies if there
    /// are no specific rules for a peer. All inbound requests from the peers that this rule applies to, will be
    /// approved/ rejected based on this rule.
    pub async fn set_firewall_rule(
        &self,
        rule: Rule<ShRequest>,
        peers: Vec<PeerId>,
        set_default: bool,
    ) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;

        if set_default {
            actor
                .send(network_msg::SetFirewallDefault {
                    direction: RuleDirection::Inbound,
                    rule: rule.clone(),
                })
                .await?;
        }

        for peer in peers {
            actor
                .send(network_msg::SetFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                    rule: rule.clone(),
                })
                .await?;
        }
        Ok(())
    }

    /// Remove peer specific rules from the firewall configuration.
    pub async fn remove_firewall_rules(&self, peers: Vec<PeerId>) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        for peer in peers {
            actor
                .send(network_msg::RemoveFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                })
                .await?;
        }
        Ok(())
    }

    /// Write to the vault of a remote Stronghold.
    pub async fn write_remote_vault(
        &self,
        peer: PeerId,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> P2pResult<Result<(), FatalEngineError>> {
        let actor = self.network_actor().await?;

        let vault_path = location.vault_path().to_vec();

        // check if vault exists
        let send_request = network_msg::SendRequest {
            peer,
            request: CheckVault { vault_path },
        };
        let vault_exists = actor.send(send_request).await??;

        // no vault so create new one before writing.
        if !vault_exists {
            let send_request = network_msg::SendRequest {
                peer,
                request: CreateVault {
                    location: location.clone(),
                },
            };
            actor.send(send_request).await??;
        }

        // write data
        let send_request = network_msg::SendRequest {
            peer,
            request: network_msg::WriteToRemoteVault {
                location: location.clone(),
                payload: payload.clone(),
                hint,
            },
        };
        let res = actor.send(send_request).await??.map_err(FatalEngineError::from);
        Ok(res)
    }

    /// Write to the store of a remote Stronghold.
    ///
    /// Returns [`None`] if the key didn't exist yet. If the key is already present, the value is updated, and the old
    /// value is returned.
    pub async fn write_to_remote_store(
        &self,
        peer: PeerId,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> P2pResult<Option<Vec<u8>>> {
        let actor = self.network_actor().await?;
        let send_request = network_msg::SendRequest {
            peer,
            request: WriteToStore { key, payload, lifetime },
        };
        let existing = actor.send(send_request).await??;
        Ok(existing)
    }

    /// Read from the store of a remote Stronghold.
    pub async fn read_from_remote_store(&self, peer: PeerId, key: Vec<u8>) -> P2pResult<Option<Vec<u8>>> {
        let actor = self.network_actor().await?;
        let send_request = network_msg::SendRequest {
            peer,
            request: ReadFromStore { key },
        };
        let data = actor.send(send_request).await??;
        Ok(data)
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer: PeerId,
        vault_path: V,
    ) -> P2pResult<Vec<(RecordId, RecordHint)>> {
        let actor = self.network_actor().await?;
        let send_request = network_msg::SendRequest {
            peer,
            request: ListIds {
                vault_path: vault_path.into(),
            },
        };
        let list = actor.send(send_request).await??;
        Ok(list)
    }

    /// Executes a runtime command at a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn remote_runtime_exec<P>(
        &self,
        peer: PeerId,
        control_request: P,
    ) -> P2pResult<Result<CollectedOutput, ProcedureError>>
    where
        P: Into<Procedure>,
    {
        let actor = self.network_actor().await?;
        let send_request = network_msg::SendRequest::<Procedure> {
            peer,
            request: control_request.into(),
        };
        let result = actor.send(send_request).await??;
        Ok(result)
    }

    async fn network_actor(&self) -> StrongholdResult<Addr<NetworkActor>> {
        self.registry.send(GetNetwork).await?.ok_or(ActorError::TargetNotFound)
    }
}
