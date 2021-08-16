// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Main Stronghold Interface
//!
//! All functionality can be accessed from the interface. Functions
//! are provided in an asynchronous way, and should be run by the
//! actor's system [`SystemRunner`].
use actix::{Addr, SystemService};
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroize;

use crate::{
    actors::{
        secure_messages::{CheckRecord, CheckVault, CreateVault, WriteToStore, WriteToVault},
        secure_procedures::{ProcResult, Procedure},
        GetClient, GetSnapshot, InsertClient, Registry, SecureClient,
    },
    internals, line_error,
    utils::{LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
    Location,
};
use engine::vault::{ClientId, RecordHint, RecordId};

#[cfg(feature = "communication")]
use comm::*;

#[cfg(feature = "communication")]
/// communication feature relevant imports are bundled here.
mod comm {

    pub use crate::utils::ResultMessage;
    use actix::{Actor, Context};

    pub use communication::{
        actor::{
            CommunicationActor, CommunicationActorConfig, CommunicationRequest, CommunicationResults,
            EstablishedConnection, FirewallPermission, FirewallRule, RelayDirection, RequestDirection,
            VariantPermission,
        },
        behaviour::BehaviourConfig,
        libp2p::{Keypair, Multiaddr, PeerId},
    };

    // that's a proxy communication actor to be used
    pub struct CommunicationActorProxy {}

    impl Actor for CommunicationActorProxy {
        type Context = Context<Self>;
    }
}

/// The main type for the Stronghold System.  Used as the entry point for the actor model.  Contains various pieces of
/// metadata to interpret the data in the vault and store.
pub struct Stronghold {
    registry: Addr<Registry>,
    target: Addr<SecureClient<internals::Provider>>,

    #[cfg(feature = "communication")]
    communication_actor: Option<Addr<CommunicationActorProxy>>,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor. Accepts an optional [`SystemRunner`],
    /// the first client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
    /// - The [`SystemRunner`] is not being used directly by stronghold, but is being initialized on the first run.
    /// - The initialization function can be made asynchronous as well, getting rid of internal explicit blocking
    pub async fn init_stronghold_system(
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> Result<Self, anyhow::Error> {
        // create client actor
        let client_id = ClientId::load_from_path(&client_path, &client_path)
            .unwrap_or_else(|_| panic!("{}", crate::Error::IDError));

        // the registry will be run as a system service
        let registry = Registry::from_registry();

        // we need to block for the target client actor
        let target = match registry.send(InsertClient { id: client_id }).await? {
            Ok(addr) => addr,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };

        Ok(Self {
            registry,
            target,

            #[cfg(feature = "communication")]
            communication_actor: None,
        })
    }

    /// Spawns a new set of actors for the Stronghold system. Accepts the client_path: [`Vec<u8>`] and the options:
    /// `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if let Ok(result) = self.registry.send(GetClient { id: client_id }).await {
            match result {
                Some(client) => {
                    self.target = client;
                }
                None => {
                    if let Ok(result) = self.registry.send(InsertClient { id: client_id }).await {
                        self.target = match result {
                            Ok(client) => client,
                            Err(_e) => return StatusMessage::Error("".to_string()),
                        };
                    }
                }
            }
        };

        StatusMessage::OK
    }

    /// Switches the actor target to another actor in the system specified by the client_path: [`Vec<u8>`].
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if let Ok(result) = self.registry.send(GetClient { id: client_id }).await {
            match result {
                Some(client) => self.target = client,
                None => return StatusMessage::Error("Could not find actor with provided client path".into()),
            }

            #[cfg(feature = "communication")]
            if let Some(_comm) = &self.communication_actor {
                // TODO set reference to client actor inside the communication actor
            }
        }

        StatusMessage::OK
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
    ) -> StatusMessage {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        if let Ok(result) = self.target.send(CheckVault { vault_path }).await {
            match result {
                Ok(_) => {
                    // exists
                    let _result = self
                        .target
                        .send(WriteToVault {
                            location,
                            payload,
                            hint,
                        })
                        .await;
                }
                Err(_) => {
                    // does not exist
                    match self
                        .target
                        .send(CreateVault {
                            location: location.clone(),
                        })
                        .await
                    {
                        Ok(_) => {
                            // write to vault
                            if let Ok(_result) = self
                                .target
                                .send(WriteToVault {
                                    location,
                                    payload,
                                    hint,
                                })
                                .await
                            {
                            } else {
                                return StatusMessage::Error("Error Writing data".into());
                            }
                        }
                        Err(_e) => {
                            return StatusMessage::Error("Cannot create new vault".into());
                        }
                    }
                }
            }
        }

        StatusMessage::Error("Failed to write the data".into())
    }

    /// Writes data into an insecure cache.  This method, accepts a [`Location`], a [`Vec<u8>`] and an optional
    /// [`Duration`]. The lifetime allows the data to be deleted after the specified duration has passed.  If no
    /// lifetime is specified, the data will persist until it is manually deleted or over-written. Note: One store
    /// is mapped to one client. Can specify the same location across multiple clients.
    pub async fn write_to_store(
        &self,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        // TODO move to top
        // use crate::actors::secure_messages::WriteToStore;

        match self
            .target
            .send(WriteToStore {
                location,
                payload,
                lifetime,
            })
            .await
        {
            Ok(status) => status.into(),
            Err(_e) => StatusMessage::Error("Failed to write to the store".into()),
        }
    }

    /// A method that reads from an insecure cache.  This method, accepts a [`Location`] and returns the payload in the
    /// form of a ([`Vec<u8>`], [`StatusMessage`]).  If the location does not exist, an empty vector will be returned
    /// along with an error [`StatusMessage`].  Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn read_from_store(&self, location: Location) -> (Vec<u8>, StatusMessage) {
        // TODO move to top
        use crate::actors::secure_messages::ReadFromStore;

        match self.target.send(ReadFromStore { location }).await {
            Ok(result) => match result {
                Ok(data) => (data, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
        }
    }

    /// A method to delete data from an insecure cache. This method, accepts a [`Location`] and returns a
    /// [`StatusMessage`]. Note: One store is mapped to one client. Can specify the same location across multiple
    /// clients.
    pub async fn delete_from_store(&self, location: Location) -> StatusMessage {
        // TODO move to top
        use crate::actors::secure_messages::DeleteFromStore;

        match self.target.send(DeleteFromStore { location }).await {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(_e) => StatusMessage::Error("Failed to delete from the store".into()),
        }
    }

    /// Revokes the data from the specified location of type [`Location`]. Revoked data is not readable and can be
    /// removed from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call
    /// with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(&self, location: Location, should_gc: bool) -> StatusMessage {
        use crate::actors::secure_messages::{GarbageCollect, RevokeData};

        // new actix impl
        match self
            .target
            .send(RevokeData {
                location: location.clone(),
            })
            .await
        {
            Ok(result) => match result {
                Ok(_ok) if should_gc => match self.target.send(GarbageCollect { location }).await {
                    Ok(result) => match result {
                        Ok(_) => StatusMessage::OK,
                        Err(e) => StatusMessage::Error(format!("{:?}", e)),
                    },
                    Err(_e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
                },
                Ok(_ok) => StatusMessage::OK,
                Err(_e) => StatusMessage::Error("Could not revoke data".into()),
            },
            Err(_e) => StatusMessage::Error("Could not revoke data".into()),
        }
    }

    /// Garbage collects any revokes in a Vault based on the given `vault_path` and the current target actor.
    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        use crate::actors::secure_messages::GarbageCollect;

        match self
            .target
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path,
                    record_path: Vec::new(), // this will be dropped.
                },
            })
            .await
        {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(_e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
        }
    }

    /// Returns a list of the available [`RecordId`] and [`RecordHint`] values in a vault by the given `vault_path`.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> (Vec<(RecordId, RecordHint)>, StatusMessage) {
        use crate::actors::secure_messages::ListIds;

        match self
            .target
            .send(ListIds {
                vault_path: vault_path.into(),
            })
            .await
        {
            Ok(success) => match success {
                Ok(result) => (result, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(_e) => (
                Vec::new(),
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            ),
        }
    }

    /// Executes a runtime command given a [`Procedure`].  Returns a [`ProcResult`] based off of the control_request
    /// specified.
    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        use crate::actors::secure_procedures::CallProcedure;

        match self.target.send(CallProcedure { proc: control_request }).await {
            Ok(success) => match success {
                Ok(result) => result,
                Err(e) => ProcResult::Error(format!("{}", e)),
            },
            Err(e) => ProcResult::Error(format!("{}", e)),
        }
    }

    /// Checks whether a record exists in the client based off of the given [`Location`].
    pub async fn record_exists(&self, location: Location) -> bool {
        match self.target.send(CheckRecord { location }).await {
            Ok(result) => result,
            Err(_e) => false,
        }
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists(&self, location: Location) -> bool {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        match self.target.send(CheckVault { vault_path }).await {
            Ok(success) => match success {
                Ok(_) => true,
                Err(_e) => false,
            },
            Err(_e) => false,
        }
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
    ) -> StatusMessage {
        use crate::actors::{secure_messages::ReloadData, snapshot_messages::ReadFromSnapshot};

        let client_id = ClientId::load_from_path(&client_path, &client_path).expect(line_error!());

        // this feature resembles the functionality given by the former riker
        // system dependence. if there is a former client id path present,
        // the new actor is being changed into the former one ( see old ReloadData impl.)
        if let Some(path) = former_client_path.clone() {
            self.switch_actor_target(path).await;
        }

        let former_client_id = former_client_path.map(|cp| ClientId::load_from_path(&cp, &cp).unwrap());
        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        // get address of snapshot actor
        let snapshot_actor = match self.registry.send(GetSnapshot {}).await {
            Ok(snapshot) => match snapshot {
                Some(actor) => actor,
                None => {
                    // This would indicate another serious error on snapshot actor
                    // creation side.
                    return StatusMessage::Error("No snapshot actor present".into());
                }
            },
            Err(e) => {
                return StatusMessage::Error(format!("{}", e));
            }
        };

        // read the snapshots contents
        let result = match snapshot_actor
            .send(ReadFromSnapshot {
                key,
                filename,
                path,
                id: client_id,
                fid: former_client_id,
            })
            .await
        {
            Ok(result) => match result {
                Ok(result) => result,
                Err(e) => return StatusMessage::Error(format!("{}", e)),
            },
            Err(e) => return StatusMessage::Error(format!("{}", e)),
        };

        // send data to secure actor and reload
        match self
            .target
            .send(ReloadData {
                data: result.data,
                id: result.id,
            })
            .await
        {
            Ok(_) => StatusMessage::OK,
            Err(e) => StatusMessage::Error(format!("Error requestion Reload Data: {}", e)),
        }
    }

    /// Writes the entire state of the [`Stronghold`] into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        // registry message
        // TODO move
        use crate::actors::{
            secure_messages::GetData,
            snapshot_messages::{FillSnapshot, WriteSnapshot},
            GetAllClients,
        };

        // use snapshot messages
        // TODO move
        // use crate::actors::{snapshot_messages::{FillSnapshot, WriteSnapshot},
        // snapshot_returntypes::ReturnReadSnapshot};

        // this should be delegated to the secure client actor
        // wrapping the interior functionality inside it.
        let clients: Vec<(ClientId, Addr<SecureClient<internals::Provider>>)> =
            match self.registry.send(GetAllClients).await {
                Ok(clients) => clients,
                Err(_e) => {
                    return StatusMessage::Error("Error retrieving SecureClientActors".into());
                }
            };

        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();
        key.copy_from_slice(keydata);

        // get snapshot actor
        let snapshot = match self.registry.send(GetSnapshot {}).await {
            Ok(result) => match result {
                Some(snapshot) => snapshot,
                None => return StatusMessage::Error("No snapshot actor present".to_string()),
            },
            Err(e) => {
                return StatusMessage::Error(format!("{}", e));
            }
        };

        for (id, client) in clients {
            // get data from secure actor
            let data = match client
                .send(GetData::<internals::Provider> {
                    _phantom: core::marker::PhantomData,
                })
                .await
            {
                Ok(success) => match success {
                    Ok(data) => data,
                    Err(_) => {
                        return StatusMessage::Error("No Data present".into());
                    }
                },

                Err(_) => {
                    return StatusMessage::Error("Error communicating with client actor".into());
                }
            };

            // fill into snapshot
            if let Err(_e) = snapshot.send(FillSnapshot { data, id }).await {
                return StatusMessage::Error("Error filling data for snapshot".into());
            }
        } // end loop

        // write snapshot
        return match snapshot.send(WriteSnapshot { key, filename, path }).await {
            Ok(success) => match success {
                Err(e) => StatusMessage::Error(format!("{}", e)),
                _ => StatusMessage::OK,
            },
            Err(e) => StatusMessage::Error(format!("{}", e)),
        };
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true`, the actor will be removed from the system.  Otherwise, the cache of the
    /// current target actor will be cleared.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StatusMessage {
        use crate::actors::{secure_messages::ClearCache, RemoveClient};

        let client_id = match ClientId::load_from_path(&client_path.clone(), &client_path)
            .map_err(|_| crate::Error::LoadClientByPathError("Loading client_id by path failed".into()))
        {
            Ok(client_id) => client_id,
            Err(e) => {
                return StatusMessage::Error(format!("{}", e));
            }
        };

        self.switch_actor_target(client_path).await;

        if kill_actor {
            match self.registry.send(RemoveClient { id: client_id }).await {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{}", e)),
            }
        } else {
            let client = match self.registry.send(GetClient { id: client_id }).await {
                Ok(option) => match option {
                    Some(client) => client,
                    None => {
                        return StatusMessage::Error("No client present".into());
                    }
                },
                Err(_e) => {
                    return StatusMessage::Error("Mailbox error".into());
                }
            };

            match client.send(ClearCache).await {
                Ok(success) => match success {
                    Ok(_) => StatusMessage::OK,
                    Err(e) => StatusMessage::Error(format!("Cache clearing failed: {}", e)),
                },
                Err(e) => StatusMessage::Error(format!("{}", e)),
            }
        }
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    // API CHANGE!
    #[cfg(test)]
    pub async fn read_secret(&self, _client_path: Vec<u8>, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        use crate::actors::ReadFromVault;

        let empty_response = Some(Vec::new());

        match self.target.send(ReadFromVault { location }).await {
            Ok(result) => match result {
                Ok(payload) => (Some(payload), StatusMessage::OK),
                Err(_e) => (empty_response, StatusMessage::Error("No payload present".into())),
            },
            Err(_e) => (empty_response, StatusMessage::Error("No secret present".into())),
        }
    }
}

#[cfg(feature = "communication")]
#[allow(clippy::all)]
impl Stronghold {
    /// Spawn the communication actor and swarm with a pre-existing keypair
    /// Per default, the firewall allows all outgoing, and reject all incoming requests.
    pub fn spawn_communication_with_keypair(&mut self, _keypair: Keypair) -> StatusMessage {
        // if self.communication_actor.is_some() {
        //     return StatusMessage::Error(String::from("Communication was already spawned"));
        // }

        // let behaviour_config = BehaviourConfig::default();
        // let actor_config = CommunicationActorConfig {
        //     client: self.target.clone(),
        //     firewall_default_in: FirewallPermission::all(),
        //     firewall_default_out: FirewallPermission::all(),
        // };

        // let communication_actor = self
        //     .system
        //     .actor_of_args::<CommunicationActor<_, SHResults, _, _>, _>(
        //         "communication",
        //         (keypair, actor_config, behaviour_config),
        //     )
        //     .expect(line_error!());
        // self.communication_actor = Some(communication_actor);
        todo!()
    }

    /// Spawn the communication actor and swarm.
    /// Per default, the firewall allows all outgoing, and reject all incoming requests.
    pub fn spawn_communication(&mut self) -> StatusMessage {
        self.spawn_communication_with_keypair(Keypair::generate_ed25519())
    }

    /// Gracefully stop the communication actor and swarm
    pub fn stop_communication(&mut self) {
        // if let Some(communication_actor) = self.communication_actor.as_ref() {
        //     self.system.stop(communication_actor);
        // }
    }

    /// Start listening on the swarm to the given address. If not address is provided, it will be assigned by the OS.
    pub async fn start_listening(&self, _addr: Option<Multiaddr>) -> ResultMessage<Multiaddr> {
        // match self
        //     .ask_communication_actor(CommunicationRequest::StartListening(addr))
        //     .await
        // {
        //     Ok(CommunicationResults::StartListeningResult(Ok(addr))) => ResultMessage::Ok(addr),
        //     Ok(CommunicationResults::StartListeningResult(Err(_))) => ResultMessage::Error("Listener Error".into()),
        //     Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => ResultMessage::Error(err),
        // }

        todo!()
    }

    /// Stop listening on the swarm.
    pub async fn stop_listening(&self) -> StatusMessage {
        // match self.ask_communication_actor(CommunicationRequest::RemoveListener).await {
        //     Ok(CommunicationResults::RemoveListenerAck) => StatusMessage::OK,
        //     Ok(_) => StatusMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => StatusMessage::Error(err),
        // }
        todo!()
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(
        &self,
    ) -> ResultMessage<(PeerId, Vec<Multiaddr>, Vec<(PeerId, EstablishedConnection)>)> {
        // match self.ask_communication_actor(CommunicationRequest::GetSwarmInfo).await {
        //     Ok(CommunicationResults::SwarmInfo {
        //         peer_id,
        //         listeners,
        //         connections,
        //     }) => ResultMessage::Ok((peer_id, listeners, connections)),
        //     Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => ResultMessage::Error(err),
        // }

        todo!()
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by the address if one is provided, or by peer id
    /// if the peer is already known e.g. from multicast DNS.
    /// If the peer is not a relay and can not be reached directly, it will be attempted to reach it via the relays,
    /// if there are any.
    /// Relays can be used to listen for incoming request, or to connect to a remote peer that can not
    /// be reached directly, and is listening to the same relay.
    /// Once the peer was successfully added, it can be used as target for operations on the remote stronghold.
    pub async fn add_peer(
        &self,
        _peer_id: PeerId,
        _addr: Option<Multiaddr>,
        _is_relay: Option<RelayDirection>,
    ) -> ResultMessage<PeerId> {
        // match self
        //     .ask_communication_actor(CommunicationRequest::AddPeer {
        //         peer_id,
        //         addr,
        //         is_relay,
        //     })
        //     .await
        // {
        //     Ok(CommunicationResults::AddPeerResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
        //     Ok(CommunicationResults::AddPeerResult(Err(err))) => {
        //         ResultMessage::Error(format!("Error connecting peer: {:?}", err))
        //     }
        //     Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => ResultMessage::Error(err),
        // }

        todo!()
    }

    /// Set / overwrite the direction for which relay is used.
    /// RelayDirection::Dialing adds the relay to the list of relay nodes that are tried if a peer can not
    /// be reached directly.
    /// RelayDirection::Listening connect the local system with the given relay and allows that it can
    /// be reached by remote peers that use the same relay for dialing.
    /// The relay has to be added beforehand with its multi-address via the `add_peer` method.
    pub async fn change_relay_direction(&self, _peer_id: PeerId, _direction: RelayDirection) -> ResultMessage<PeerId> {
        // match self
        //     .ask_communication_actor(CommunicationRequest::ConfigRelay { peer_id, direction })
        //     .await
        // {
        //     Ok(CommunicationResults::ConfigRelayResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
        //     Ok(CommunicationResults::ConfigRelayResult(Err(err))) => {
        //         ResultMessage::Error(format!("Error connecting peer: {:?}", err))
        //     }
        //     Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => ResultMessage::Error(err),
        // }

        todo!()
    }

    /// Remove a relay so that it will not be used anymore for dialing or listening.
    pub async fn remove_relay(&self, _peer_id: PeerId) -> StatusMessage {
        // match self
        //     .ask_communication_actor(CommunicationRequest::RemoveRelay(peer_id))
        //     .await
        // {
        //     Ok(CommunicationResults::RemoveRelayAck) => StatusMessage::OK,
        //     Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => ResultMessage::Error(err),
        // }

        todo!()
    }

    /// Allow all requests from the given peers, optionally also set default to allow all.
    pub async fn allow_all_requests(&self, peers: Vec<PeerId>, set_default: bool) -> StatusMessage {
        let rule = FirewallRule::SetRules {
            direction: RequestDirection::In,
            peers,
            set_default,
            permission: FirewallPermission::all(),
        };
        self.configure_firewall(rule).await
    }

    /// Change or add rules in the firewall to allow the given requests for the peers, optionally also change the
    /// default rule to allow it.
    /// The `SHRequestPermission` copy the `SHRequest` with Unit-type variants with individual permission, e.g.
    /// ```no_run
    /// // use iota_stronghold::SHRequestPermission;
    ///
    /// // let permissions = vec![SHRequestPermission::CheckVault, SHRequestPermission::CheckRecord];
    /// ```
    /// Existing permissions for other `SHRequestPermission`s will not be changed by this.
    /// If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn allow_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        // requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::AddPermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: vec![],
        };
        self.configure_firewall(rule).await
    }

    /// Change or add rules in the firewall to reject the given requests from the peers, optionally also remove the
    /// permission from the default rule.
    /// The `SHRequestPermission` copy the `SHRequest` with Unit-type variants with individual permission, e.g.
    /// ```no_run
    /// // use iota_stronghold::SHRequestPermission;
    ///
    /// //  let permissions = vec![SHRequestPermission::CheckVault, SHRequestPermission::CheckRecord];
    /// ```
    /// Existing permissions for other `SHRequestPermission`s will not be changed
    /// by this. If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn reject_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        // requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::RemovePermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: vec![],
        };
        self.configure_firewall(rule).await
    }

    /// Configure the firewall to reject all requests from the given peers, optionally also set default rule to reject
    /// all.
    pub async fn reject_all_requests(&self, peers: Vec<PeerId>, set_default: bool) -> StatusMessage {
        let rule = FirewallRule::SetRules {
            direction: RequestDirection::In,
            peers,
            set_default,
            permission: FirewallPermission::none(),
        };
        self.configure_firewall(rule).await
    }

    /// Remove peer specific rules from the firewall configuration.
    pub async fn remove_firewall_rules(&self, peers: Vec<PeerId>) -> StatusMessage {
        let rule = FirewallRule::RemoveRule {
            direction: RequestDirection::In,
            peers,
        };
        self.configure_firewall(rule).await
    }

    /// Write to the vault of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_remote_vault(
        &self,
        _peer_id: PeerId,
        _location: Location,
        _payload: Vec<u8>,
        _hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        // let vault_path = &location.vault_path();
        // let vault_path = vault_path.to_vec();
        // // check if vault exists
        // let vault_exists = match self
        //     .ask_remote(peer_id, SHRequest::CheckVault(vault_path.clone()))
        //     .await
        // {
        //     Ok(SHResults::ReturnExistsVault(b)) => b,
        //     Ok(_) => return StatusMessage::Error("Failed to check at remote if vault exists".into()),
        //     Err(err) => return StatusMessage::Error(err),
        // };
        // if !vault_exists {
        //     // no vault so create new one before writing.
        //     match self
        //         .ask_remote(peer_id, SHRequest::CreateNewVault(location.clone()))
        //         .await
        //     {
        //         Ok(SHResults::ReturnCreateVault(_)) => {}
        //         Ok(_) => return StatusMessage::Error("Failed to create vault at remote".into()),
        //         Err(err) => return StatusMessage::Error(err),
        //     };
        // }
        // // write data
        // match self
        //     .ask_remote(
        //         peer_id,
        //         SHRequest::WriteToVault {
        //             location: location.clone(),
        //             payload: payload.clone(),
        //             hint,
        //         },
        //     )
        //     .await
        // {
        //     Ok(SHResults::ReturnWriteVault(status)) => status,
        //     Ok(_) => StatusMessage::Error("Failed to write the data at remote vault".into()),
        //     Err(err) => StatusMessage::Error(err),
        // }

        todo!()
    }

    /// Write to the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_to_remote_store(
        &self,
        _peer_id: PeerId,
        _location: Location,
        _payload: Vec<u8>,
        _lifetime: Option<Duration>,
    ) -> StatusMessage {
        // match self
        //     .ask_remote(
        //         peer_id,
        //         SHRequest::WriteToStore {
        //             location,
        //             payload,
        //             lifetime,
        //         },
        //     )
        //     .await
        // {
        //     Ok(SHResults::ReturnWriteStore(status)) => status,
        //     Ok(_) => StatusMessage::Error("Failed to write at the remote store".into()),
        //     Err(err) => StatusMessage::Error(err),
        // }

        todo!()
    }

    /// Read from the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn read_from_remote_store(&self, _peer_id: PeerId, _location: Location) -> (Vec<u8>, StatusMessage) {
        // match self.ask_remote(peer_id, SHRequest::ReadFromStore { location }).await {
        //     Ok(SHResults::ReturnReadStore(payload, status)) => (payload, status),
        //     Ok(_) => (
        //         vec![],
        //         StatusMessage::Error("Failed to read at the remote store".into()),
        //     ),
        //     Err(err) => (vec![], StatusMessage::Error(err)),
        // }

        todo!()
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        _peer_id: PeerId,
        _vault_path: V,
    ) -> (Vec<(RecordId, RecordHint)>, StatusMessage) {
        // match self.ask_remote(peer_id, SHRequest::ListIds(vault_path.into())).await {
        //     Ok(SHResults::ReturnList(ids, status)) => (ids, status),
        //     Ok(_) => (
        //         vec![],
        //         StatusMessage::Error("Failed to list hints and indexes from at remote vault".into()),
        //     ),
        //     Err(err) => (vec![], StatusMessage::Error(err)),
        // }

        todo!()
    }

    /// Executes a runtime command at a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn remote_runtime_exec(&self, _peer_id: PeerId, _control_request: Procedure) -> ProcResult {
        // match self
        //     .ask_remote(peer_id, SHRequest::ControlRequest(control_request))
        //     .await
        // {
        //     Ok(SHResults::ReturnControlRequest(pr)) => pr,
        //     Ok(_) => ProcResult::Error("Invalid procedure result".into()),
        //     Err(err) => ProcResult::Error(err),
        // }

        todo!()
    }

    // Wrap the SHRequest in an CommunicationRequest::RequestMsg and send it to the communication actor, to send it to
    // the remote peer. Fails if no communication actor is present, if sending the request failed or if an invalid event
    // was returned from the communication actor,
    async fn ask_remote(
        &self,
        _peer_id: PeerId,
        // request: SHRequest
    ) -> Result<(), String> {
        // Result<SHResults, String> {
        // match self
        //     .ask_communication_actor(CommunicationRequest::RequestMsg { peer_id, request })
        //     .await
        // {
        //     Ok(CommunicationResults::RequestMsgResult(Ok(ok))) => Ok(ok),
        //     Ok(CommunicationResults::RequestMsgResult(Err(e))) => Err(format!("Error sending request to peer {:?}",
        // e)), Ok(_) => Err("Invalid communication actor response".into()),
        //     Err(err) => Err(err),
        // }

        todo!()
    }

    // Send a request to the communication actor to configure the firewall by adding, changing or removing rules.
    async fn configure_firewall(&self, _rule: FirewallRule) -> StatusMessage {
        // match self
        //     .ask_communication_actor(CommunicationRequest::ConfigureFirewall(rule))
        //     .await
        // {
        //     Ok(CommunicationResults::ConfigureFirewallAck) => StatusMessage::OK,
        //     Ok(_) => StatusMessage::Error("Invalid communication actor response".into()),
        //     Err(err) => StatusMessage::Error(err),
        // }

        todo!()
    }

    // Send request to communication actor, fails if none is present.
    async fn ask_communication_actor(
        &self,
        // request: CommunicationRequest<SHRequest, ClientMsg>,
    ) -> Result<(), String> {
        // -> Result<CommunicationResults<SHResults>, String> {
        // if let Some(communication_actor) = self.communication_actor.as_ref() {
        //     let res = ask(&self.system, communication_actor, request).await;
        //     Ok(res)
        // } else {
        //     Err(String::from("No communication spawned"))
        // }

        todo!()
    }

    // Keeps stronghold in a running state. This call is blocking.
    //
    // This function accepts an optional function for more control over how long
    // stronghold shall block.
    // #[cfg(test)]
    // pub fn keep_alive<F>(&self, callback: Option<F>)
    // where
    //     F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    // {
    //     match callback {
    //         Some(cb) => {
    //             block_on(async {
    //                 cb().expect("Calling blocker function failed");
    //             });
    //         }
    //         None => {
    //             // create a channel, read from it, but never write.
    //             // this might be a trivial method to keep an instance running.
    //             let (_tx, rx): (Sender<usize>, Receiver<usize>) = channel(1);

    //             let waiter = async {
    //                 rx.map(|f| f).collect::<Vec<usize>>().await;
    //             };
    //             block_on(waiter);
    //         }
    //     }
    // }
}
