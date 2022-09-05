// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// THIS IS JUST A PLACEHOLDER MODULE AND SHALL BE REPLACED BY STRONGHOLD.rs MODULE
// ALL METHODS SHOWN HERE SHOULD BE MOVED / REPLACED BY THE NEW CLIENT INTERFACE UPDATE

use engine::vault::{RecordHint, RecordId};
use std::time::Duration;
use stronghold_p2p::{
    identity::Keypair, ConnectedPoint, DialErr, InitKeypair, ListenErr, ListenRelayErr, Listener, Multiaddr,
    OutboundFailure, PeerId, RelayNotSupported,
};

use crate::{
    network_old::{FirewallChannelSender, Network, NetworkConfig, Permissions},
    procedures::{FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, StrongholdProcedure},
    Client, ClientError, FatalEngineError, Location, SpawnNetworkError, Stronghold,
};
use thiserror::Error as DeriveError;
// moved from old actors code
pub struct SwarmInfo {
    pub local_peer_id: PeerId,
    pub listeners: Vec<Listener>,
    pub connections: Vec<(PeerId, Vec<ConnectedPoint>)>,
}

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    #[error("sending request to remote stronghold failed: {0}")]
    SendRequest(#[from] OutboundFailure),

    #[error("Local Error occured {0}")]
    Local(String),
}

impl Stronghold {
    /// Spawn the p2p-network actor and swarm, load the config from a former running network-actor.
    /// The `key` parameter species the location in which in the config is stored, i.e.
    /// the key that was set on [`Stronghold::stop_p2p`].
    ///
    /// Optionally pass a [`FirewallChannelSender`] for asynchronous firewall interaction.
    /// See [`NetworkConfig::with_async_firewall`] for more info.
    pub async fn spawn_p2p_load_config(
        &self,
        client_path: Vec<u8>, // we need a reference to the current client
        key: Vec<u8>,
        keypair: Option<Location>,
        firewall_sender: Option<FirewallChannelSender>,
    ) -> Result<(), SpawnNetworkError> {
        let client = self
            .load_client(client_path.clone())
            .map_err(|_| SpawnNetworkError::ClientNotFound)?;

        let store = client.store();

        let guard = store.get(&key).map_err(|e| SpawnNetworkError::Inner(e.to_string()))?;

        let config_bytes =
            guard.ok_or_else(|| SpawnNetworkError::LoadConfig(format!("No config found at key {:?}", key)))?;

        let mut config: NetworkConfig = bincode::deserialize(&config_bytes)
            .map_err(|e| SpawnNetworkError::LoadConfig(format!("Deserializing state failed: {}", e)))?;
        if let Some(tx) = firewall_sender {
            config = config.with_async_firewall(tx);
        }
        self.spawn_p2p(client_path, config, keypair).await
    }

    /// Gracefully stop the network actor and swarm.
    /// Return `false` if there is no active network actor.
    /// Optionally store the current config (known addresses of remote peers and firewall rules) in the store
    /// at the specified `key`.
    pub async fn stop_p2p(&self, write_config: Option<Vec<u8>>) -> Result<(), ClientError> {
        let mut network = self.network.lock().await;
        if network.is_none() {
            return Ok(());
        }

        if let Some(key) = write_config {
            let network = network.as_ref().unwrap();
            let config = network.export_config().await?;
            let payload = match bincode::serialize(&config) {
                Ok(bytes) => bytes,
                Err(e) => return Err(ClientError::Inner(e.to_string())),
            };

            self.store.insert(key, payload, None)?;
        }
        // remove network
        network.take();
        Ok(())
    }

    /// Export the config and state of the p2p-layer.
    pub async fn export_config(&self) -> NetworkConfig {
        todo!()
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(&self) -> SwarmInfo {
        todo!()
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        todo!()
    }

    /// Start listening via a relay peer on an address following the scheme
    /// `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    pub async fn start_relayed_listening(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ListenRelayErr> {
        todo!()
    }

    /// Stop listening with the relay.
    pub async fn remove_listening_relay(&self, relay: PeerId) -> Result<(), ClientError> {
        todo!()
    }

    /// Remove a peer from the list of peers used for dialing.
    pub async fn remove_dialing_relay(&self, relay: PeerId) -> Result<(), ClientError> {
        todo!()
    }

    /// Change the default firewall rule. All inbound requests from peers without an individual rule will be
    /// approved/ rejected based on this rule.
    ///
    /// **Note:** This rule is only active if the [`NetworkConfig::with_async_firewall`] was **not** enabled on init.
    pub async fn set_default_permission(&self, permissions: Permissions) -> Result<(), ClientError> {
        todo!()
    }

    /// Change the firewall rule for an individual peer. All inbound requests from this peer will be
    /// approved/ rejected based on this rule.
    pub async fn set_peer_permissions(&self, permissions: Permissions, peer: PeerId) -> Result<(), ClientError> {
        todo!()
    }

    /// Remove the individual firewall rule of an peer, Instead the default rule will be used,
    /// or the `FirewallChannel` in case of [`NetworkConfig::with_async_firewall`].
    pub async fn remove_peer_permissions(&self, peer: PeerId) -> Result<(), ClientError> {
        todo!()
    }

    /// Write to the vault of a remote Stronghold.
    pub async fn write_remote_vault(
        &self,
        peer: PeerId,
        client_path: Vec<u8>,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
    ) -> Result<Result<(), FatalEngineError>, P2pError> {
        todo!()
    }

    /// Write to the store of a remote Stronghold.
    ///
    /// Returns [`None`] if the key didn't exist yet. If the key is already present, the value is updated, and the old
    /// value is returned.
    pub async fn write_to_remote_store(
        &self,
        peer: PeerId,
        client_path: Vec<u8>,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> Result<Option<Vec<u8>>, P2pError> {
        todo!()
    }

    /// Read from the store of a remote Stronghold.
    pub async fn read_from_remote_store(
        &self,
        peer: PeerId,
        client_path: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, P2pError> {
        todo!()
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    #[deprecated]
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer: PeerId,
        client_path: Vec<u8>,
        vault_path: V,
    ) -> Result<Vec<(RecordId, RecordHint)>, P2pError> {
        todo!()
    }

    // Executes a runtime command at a remote Stronghold.
    // It is required that the peer has successfully been added with the `add_peer` method.
    // pub async fn remote_procedure_exec<P>(
    //     &self,
    //     peer: PeerId,
    //     client_path: Vec<u8>,
    //     procedure: P,
    // ) -> Result<Result<P::Output, ProcedureError>, P2pError>
    // where
    //     P: Procedure + Into<StrongholdProcedure>,
    // {
    //     todo!()
    // }

    // Executes multiple runtime commands at a remote Stronghold.
    // It is required that the peer has successfully been added with the `add_peer` method.
    // pub async fn remote_procedure_exec_chained(
    //     &self,
    //     peer: PeerId,
    //     client_path: Vec<u8>,
    //     procedures: Vec<StrongholdProcedure>,
    // ) -> Result<Result<Vec<ProcedureOutput>, ProcedureError>, P2pError> {
    //     todo!()
    // }
}
