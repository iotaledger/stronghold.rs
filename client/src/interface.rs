// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use futures::future::RemoteHandle;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use zeroize::Zeroize;

use engine::vault::RecordHint;

#[cfg(feature = "communication")]
use crate::actors::SHRequestPermission;
#[cfg(feature = "communication")]
use crate::utils::ResultMessage;
use crate::{
    actors::{InternalActor, InternalMsg, ProcResult, Procedure, SHRequest, SHResults},
    line_error,
    state::{
        client::{Client, ClientMsg},
        snapshot::Snapshot,
    },
    utils::{LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
    ClientId, Location, Provider,
};
use communication::actor::RelayDirection;
#[cfg(feature = "communication")]
use communication::{
    actor::{
        CommunicationActor, CommunicationActorConfig, CommunicationRequest, CommunicationResults,
        EstablishedConnection, FirewallPermission, FirewallRule, RequestDirection, VariantPermission,
    },
    behaviour::BehaviourConfig,
    libp2p::{Keypair, Multiaddr, PeerId},
};
use stronghold_utils::ask;

/// The main type for the Stronghold System.  Used as the entry point for the actor model.  Contains various pieces of
/// metadata to interpret the data in the vault and store.
pub struct Stronghold {
    // actor system.
    pub system: ActorSystem,
    // clients in the system.
    client_ids: Vec<ClientId>,

    // Actor references in the system.
    actors: Vec<ActorRef<ClientMsg>>,

    // data derived from the client_paths.
    derive_data: HashMap<Vec<u8>, Vec<u8>>,

    // current index of the client.
    current_target: usize,

    #[cfg(feature = "communication")]
    // communication actor ref
    communication_actor: Option<ActorRef<CommunicationRequest<SHRequest, ClientMsg>>>,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor. Accepts a `ActorSystem`, the first
    /// client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
    pub fn init_stronghold_system(system: ActorSystem, client_path: Vec<u8>, _options: Vec<StrongholdFlags>) -> Self {
        let client_id = ClientId::load_from_path(&client_path, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let client_ids = vec![client_id];

        let mut derive_data = HashMap::new();

        derive_data.insert(client_path.clone(), client_path);

        let client = system
            .actor_of_args::<Client, _>(&id_str, client_id)
            .expect(line_error!());
        system
            .actor_of_args::<InternalActor<Provider>, _>(&format!("internal-{}", id_str), client_id)
            .expect(line_error!());

        system.actor_of::<Snapshot>("snapshot").expect(line_error!());

        let actors = vec![client];

        Self {
            system,
            client_ids,
            derive_data,
            actors,
            current_target: 0,
            #[cfg(feature = "communication")]
            communication_actor: None,
        }
    }

    /// Spawns a new set of actors for the Stronghold system. Accepts the client_path: `Vec<u8>` and the options:
    /// `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());
        let id_str: String = client_id.into();
        let counter = self.actors.len();

        if self.client_ids.contains(&client_id) {
            self.switch_actor_target(client_path).await;
        } else {
            let client = self
                .system
                .actor_of_args::<Client, _>(&id_str, client_id)
                .expect(line_error!());
            self.system
                .actor_of_args::<InternalActor<Provider>, _>(&format!("internal-{}", id_str), client_id)
                .expect(line_error!());

            self.actors.push(client);
            self.client_ids.push(client_id);
            self.derive_data.insert(client_path.clone(), client_path);
            self.current_target = counter;
        }

        StatusMessage::OK
    }

    /// Switches the actor target to another actor in the system specified by the client_path: `Vec<u8>`.
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if self.client_ids.contains(&client_id) {
            let idx = self.client_ids.iter().position(|cid| cid == &client_id);

            if let Some(idx) = idx {
                self.current_target = idx;

                #[cfg(feature = "communication")]
                if let Some(communication_actor) = self.communication_actor.as_ref() {
                    match ask(
                        &self.system,
                        communication_actor,
                        CommunicationRequest::SetClientRef(self.actors[idx].clone()),
                    )
                    .await
                    {
                        CommunicationResults::<SHResults>::SetClientRefAck => {}
                        _ => {
                            return StatusMessage::Error("Could not set communication client target".into());
                        }
                    }
                }
            }
            StatusMessage::OK
        } else {
            StatusMessage::Error("Unable to find the actor with that client path".into())
        }
    }

    /// Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified
    /// location of `Location` type. The payload must be specified as a `Vec<u8>` and a `RecordHint` can be provided.
    /// Also accepts `VaultFlags` for when a new Vault is created.
    pub async fn write_to_vault(
        &self,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        if let SHResults::ReturnExistsVault(b) =
            ask(&self.system, client, SHRequest::CheckVault(vault_path.clone())).await
        {
            // check if vault exists
            if b {
                if let SHResults::ReturnExistsRecord(b) = ask(
                    &self.system,
                    client,
                    SHRequest::CheckRecord {
                        location: location.clone(),
                    },
                )
                .await
                {
                    if b {
                        if let SHResults::ReturnWriteVault(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteToVault {
                                location: location.clone(),
                                payload: payload.clone(),
                                hint,
                            },
                        )
                        .await
                        {
                            return status;
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    } else {
                        let (_idx, _) = if let SHResults::ReturnInitRecord(status) = ask(
                            &self.system,
                            client,
                            SHRequest::InitRecord {
                                location: location.clone(),
                            },
                        )
                        .await
                        {
                            (Some(idx), status)
                        } else {
                            (None, StatusMessage::Error("Unable to initialize record".into()))
                        };

                        if let SHResults::ReturnWriteVault(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteToVault {
                                location: location.clone(),
                                payload: payload.clone(),
                                hint,
                            },
                        )
                        .await
                        {
                            return status;
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    }
                };
            } else {
                // no vault so create new one before writing.
                if let SHResults::ReturnCreateVault(status) =
                    ask(&self.system, client, SHRequest::CreateNewVault(location.clone())).await
                {
                    status
                } else {
                    return StatusMessage::Error("Invalid Message".into());
                };

                if let SHResults::ReturnWriteVault(status) = ask(
                    &self.system,
                    client,
                    SHRequest::WriteToVault {
                        location,
                        payload,
                        hint,
                    },
                )
                .await
                {
                    return status;
                } else {
                    return StatusMessage::Error("Error Writing data".into());
                };
            }
        };

        StatusMessage::Error("Failed to write the data".into())
    }

    /// Writes data into an insecure cache.  This method, accepts a `Location`, a `Vec<u8>` and an optional `Duration`.
    /// The lifetime allows the data to be deleted after the specified duration has passed.  If not lifetime is
    /// specified, the data will persist until it is manually deleted or over-written. Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn write_to_store(
        &self,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(
            &self.system,
            client,
            SHRequest::WriteToStore {
                location,
                payload,
                lifetime,
            },
        )
        .await;

        if let SHResults::ReturnWriteStore(status) = res {
            status
        } else {
            StatusMessage::Error("Failed to write to the store".into())
        }
    }

    /// A method that reads from an insecure cache.  This method, accepts a `Location` and returns the payload in the
    /// form of a `Vec<u8>`.  If the location does not exist, an empty vector will be returned along with an error
    /// `StatusMessage`.  Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn read_from_store(&self, location: Location) -> (Vec<u8>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::ReadFromStore { location }).await;

        if let SHResults::ReturnReadStore(payload, status) = res {
            (payload, status)
        } else {
            (vec![], StatusMessage::Error("Failed to read from the store".into()))
        }
    }

    /// A method to delete data from an insecure cache. This method, accepts a `Location` and returns a `StatusMessage`.
    /// Note: One store is mapped to one client. Can specify the same location across multiple clients.
    pub async fn delete_from_store(&self, location: Location) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::DeleteFromStore(location)).await;

        if let SHResults::ReturnDeleteStore(status) = res {
            status
        } else {
            StatusMessage::Error("Failed to delete from the store".into())
        }
    }

    /// Revokes the data from the specified location of type `Location`. Revoked data is not readable and can be removed
    /// from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call with
    /// automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(&self, location: Location, should_gc: bool) -> StatusMessage {
        let idx = self.current_target;
        let status;
        let client = &self.actors[idx];
        let vault_path = location.vault_path().to_vec();

        if should_gc {
            let _ = if let SHResults::ReturnRevoke(status) =
                ask(&self.system, client, SHRequest::RevokeData { location }).await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            status = if let SHResults::ReturnGarbage(status) =
                ask(&self.system, client, SHRequest::GarbageCollect(vault_path.clone())).await
            {
                status
            } else {
                return StatusMessage::Error("Failed to garbage collect the vault".into());
            };

            status
        } else {
            status = if let SHResults::ReturnRevoke(status) =
                ask(&self.system, client, SHRequest::RevokeData { location }).await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            status
        }
    }

    /// Garbage collects any revokes in a Vault based on the given vault_path and the current target actor.
    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnGarbage(status) = ask(&self.system, client, SHRequest::GarbageCollect(vault_path)).await
        {
            status
        } else {
            StatusMessage::Error("Failed to garbage collect the vault".into())
        }
    }

    /// Returns a list of the available records and their `RecordHint` values in a vault by the given vault_path.
    /// Records are returned as `usize` based on their index if they are written with counter `Locations`.  Generic
    /// `Locations` will not return a readable index.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> (Vec<(usize, RecordHint)>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnList(ids, status) =
            ask(&self.system, client, SHRequest::ListIds(vault_path.into())).await
        {
            (ids, status)
        } else {
            (
                vec![],
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            )
        }
    }

    /// Executes a runtime command given a `Procedure`.  Returns a `ProcResult` based off of the control_request
    /// specified.
    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        let idx = self.current_target;

        let client = &self.actors[idx];
        let shr = ask(&self.system, client, SHRequest::ControlRequest(control_request)).await;
        match shr {
            SHResults::ReturnControlRequest(pr) => pr,
            _ => ProcResult::Error("Invalid communication event".into()),
        }
    }

    /// Checks whether a record exists in the client.
    pub async fn record_exists(&self, location: Location) -> bool {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnExistsRecord(b) = ask(
            &self.system,
            client,
            SHRequest::CheckRecord {
                location: location.clone(),
            },
        )
        .await
        {
            b
        } else {
            false
        }
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists(&self, location: Location) -> bool {
        let idx = self.current_target;

        let client = &self.actors[idx];
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        if let SHResults::ReturnExistsVault(b) = ask(&self.system, client, SHRequest::CheckVault(vault_path)).await {
            b
        } else {
            false
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
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let former_cid = if let Some(cp) = former_client_path {
            self.derive_data.insert(cp.clone(), cp.clone());

            Some(ClientId::load_from_path(&cp, &cp).expect(line_error!()))
        } else {
            None
        };

        let idx = self.client_ids.iter().position(|id| id == &client_id);
        if let Some(idx) = idx {
            let client = &self.actors[idx];

            let mut key: [u8; 32] = [0u8; 32];

            let keydata = keydata.as_ref();

            key.copy_from_slice(keydata);

            if let SHResults::ReturnReadSnap(status) = ask(
                &self.system,
                client,
                SHRequest::ReadSnapshot {
                    key,
                    filename,
                    path,
                    cid: client_id,
                    former_cid,
                },
            )
            .await
            {
                status
            } else {
                StatusMessage::Error("Unable to read snapshot".into())
            }
        } else {
            StatusMessage::Error("Unable to find client actor".into())
        }
    }

    /// Writes the entire state of the `Stronghold` into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let num_of_actors = self.actors.len();
        let idx = self.current_target;
        let client = &self.actors[idx];

        let mut futures = vec![];
        let mut key: [u8; 32] = [0u8; 32];

        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        if num_of_actors != 0 {
            for (_, actor) in self.actors.iter().enumerate() {
                let res: RemoteHandle<SHResults> = ask(&self.system, actor, SHRequest::FillSnapshot);
                futures.push(res);
            }
        } else {
            return StatusMessage::Error("Unable to write snapshot without any actors.".into());
        }

        for fut in futures {
            fut.await;
        }

        let res: SHResults = ask(&self.system, client, SHRequest::WriteSnapshot { key, filename, path }).await;

        if let SHResults::ReturnWriteSnap(status) = res {
            status
        } else {
            StatusMessage::Error("Unable to write snapshot".into())
        }
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true` both the internal actor and the client actor will be killed.  Otherwise, the cache of the
    /// current target actor will be cleared.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StatusMessage {
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let idx = self.client_ids.iter().position(|id| id == &client_id);

        let client_str: String = client_id.into();

        if let Some(idx) = idx {
            if kill_actor {
                let client = &self.actors.remove(idx);
                self.client_ids.remove(idx);
                self.derive_data.remove(&client_path).expect(line_error!());

                self.system.stop(client);
                let internal = self
                    .system
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());
                internal.try_tell(InternalMsg::KillInternal, None);

                StatusMessage::OK
            } else {
                let client = &self.actors[idx];

                if let SHResults::ReturnClearCache(status) = ask(&self.system, client, SHRequest::ClearCache).await {
                    status
                } else {
                    StatusMessage::Error("Unable to clear the cache".into())
                }
            }
        } else {
            StatusMessage::Error("Unable to find client actor".into())
        }
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    #[cfg(test)]
    pub async fn read_secret(&self, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::ReadFromVault { location }).await;

        if let SHResults::ReturnReadVault(payload, status) = res {
            (Some(payload), status)
        } else {
            (None, StatusMessage::Error("Unable to read data".into()))
        }
    }
}

#[cfg(feature = "communication")]
impl Stronghold {
    /// Spawn the communication actor and swarm.
    /// Per default, the firewall allows all outgoing, and reject all incoming requests.
    /// The `configure_firewall` methods allows to configure this behaviour by either changing the default regulation,
    /// or adding explicit rules for for specific peers.
    pub fn spawn_communication(&mut self) -> StatusMessage {
        if self.communication_actor.is_some() {
            return StatusMessage::Error(String::from("Communication was already spawned"));
        }

        let idx = self.current_target;
        let client = self.actors[idx].clone();

        let local_keys = Keypair::generate_ed25519();
        let behaviour_config = BehaviourConfig::default();
        let actor_config = CommunicationActorConfig {
            client,
            firewall_default_in: FirewallPermission::all(),
            firewall_default_out: FirewallPermission::all(),
        };

        let communication_actor = self
            .system
            .actor_of_args::<CommunicationActor<_, SHResults, _, _>, _>(
                "communication",
                (local_keys, actor_config, behaviour_config),
            )
            .expect(line_error!());
        self.communication_actor = Some(communication_actor);
        StatusMessage::OK
    }

    /// Kill communication actor and swarm
    pub fn stop_communication(&mut self) {
        if let Some(communication_actor) = self.communication_actor.as_ref() {
            self.system.stop(communication_actor);
        }
    }

    ///  Start listening on the swarm
    pub async fn start_listening(&self, addr: Option<Multiaddr>) -> ResultMessage<Multiaddr> {
        match self
            .ask_communication_actor(CommunicationRequest::StartListening(addr))
            .await
        {
            Ok(CommunicationResults::StartListeningResult(Ok(addr))) => ResultMessage::Ok(addr),
            Ok(CommunicationResults::StartListeningResult(Err(_))) => ResultMessage::Error("Listener Error".into()),
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    ///  Get the peer id and listening addresses of the local peer
    pub async fn get_swarm_info(
        &self,
    ) -> ResultMessage<(PeerId, Vec<Multiaddr>, Vec<(PeerId, EstablishedConnection)>)> {
        match self.ask_communication_actor(CommunicationRequest::GetSwarmInfo).await {
            Ok(CommunicationResults::SwarmInfo {
                peer_id,
                listeners,
                connections,
            }) => ResultMessage::Ok((peer_id, listeners, connections)),
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by via the peer id if the peer is already
    /// known e.g. via multicast DNS, or with the given address if one is provided.
    /// If the peer is a relay, an address has to be provided.
    /// Relays can be used to listen for incoming request, or to connect to a remote peer that can not
    /// be reached directly, and is listening to the same relay.
    /// Once the peer was successfully added, it can be used as target for operations on the remote stronghold.
    pub async fn add_peer(
        &self,
        peer_id: PeerId,
        addr: Option<Multiaddr>,
        is_relay: Option<RelayDirection>,
    ) -> ResultMessage<PeerId> {
        match self
            .ask_communication_actor(CommunicationRequest::AddPeer {
                peer_id,
                addr,
                is_relay,
            })
            .await
        {
            Ok(CommunicationResults::AddPeerResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
            Ok(CommunicationResults::AddPeerResult(Err(err))) => {
                ResultMessage::Error(format!("Error connecting peer: {:?}", err))
            }
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Set / overwrite the direction for which relay is used.
    /// RelayDirection::Dialing adds the relay to the list of relay nodes that are tried if a peer can not
    /// be reached directly.
    /// RelayDirection::Listening connect the local system with the given relay and allows that it can
    /// be reached by remote peers that use the same relay for dialing.
    /// The relay has to be added beforehand with its multi-address via the `add_peer` method.
    pub async fn change_relay_direction(&self, peer_id: PeerId, direction: RelayDirection) -> ResultMessage<PeerId> {
        match self
            .ask_communication_actor(CommunicationRequest::ConfigRelay { peer_id, direction })
            .await
        {
            Ok(CommunicationResults::ConfigRelayResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
            Ok(CommunicationResults::ConfigRelayResult(Err(err))) => {
                ResultMessage::Error(format!("Error connecting peer: {:?}", err))
            }
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Remove a relay so that it will not be used anymore for dialing or listening.
    pub async fn remove_relay(&self, peer_id: PeerId) -> StatusMessage {
        match self
            .ask_communication_actor(CommunicationRequest::RemoveRelay(peer_id))
            .await
        {
            Ok(CommunicationResults::RemoveRelayAck) => StatusMessage::OK,
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
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
    /// default rule to allow it. Existing permissions for other `SHRequestPermission`s will not be changed by this.
    /// If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn allow_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::AddPermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: requests.iter().map(|req| req.permission()).collect(),
        };
        self.configure_firewall(rule).await
    }

    /// Change or add rules in the firewall to reject the given requests from the peers, optionally also remove the
    /// permission from the default rule. Existing permissions for other `SHRequestPermission`s will not be changed
    /// by this. If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn reject_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::RemovePermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: requests.iter().map(|req| req.permission()).collect(),
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
    pub async fn write_remote_vault(
        &self,
        peer_id: PeerId,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();
        // check if vault exists
        let vault_exists = match self
            .ask_remote(peer_id, SHRequest::CheckVault(vault_path.clone()))
            .await
        {
            Ok(SHResults::ReturnExistsVault(b)) => b,
            Ok(_) => return StatusMessage::Error("Failed to check at remote if vault exists".into()),
            Err(err) => return StatusMessage::Error(err),
        };
        if vault_exists {
            // check if record exists
            let record_exists = match self
                .ask_remote(
                    peer_id,
                    SHRequest::CheckRecord {
                        location: location.clone(),
                    },
                )
                .await
            {
                Ok(SHResults::ReturnExistsRecord(b)) => b,
                Ok(_) => return StatusMessage::Error("Failed to check at remote if record exists".into()),
                Err(err) => return StatusMessage::Error(err),
            };
            if !record_exists {
                // initialize a new record
                match self
                    .ask_remote(
                        peer_id,
                        SHRequest::InitRecord {
                            location: location.clone(),
                        },
                    )
                    .await
                {
                    Ok(SHResults::ReturnInitRecord(status)) => status,
                    Ok(_) => return StatusMessage::Error("Failed to initialize record at remote".into()),
                    Err(err) => return StatusMessage::Error(err),
                };
            }
        } else {
            // no vault so create new one before writing.
            match self
                .ask_remote(peer_id, SHRequest::CreateNewVault(location.clone()))
                .await
            {
                Ok(SHResults::ReturnCreateVault(_)) => {}
                Ok(_) => return StatusMessage::Error("Failed to create vault at remote".into()),
                Err(err) => return StatusMessage::Error(err),
            };
        }
        // write data
        match self
            .ask_remote(
                peer_id,
                SHRequest::WriteToVault {
                    location: location.clone(),
                    payload: payload.clone(),
                    hint,
                },
            )
            .await
        {
            Ok(SHResults::ReturnWriteVault(status)) => status,
            Ok(_) => StatusMessage::Error("Failed to write the data at remote vault".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    /// Write to the store of a remote Stronghold.
    pub async fn write_to_remote_store(
        &self,
        peer_id: PeerId,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        match self
            .ask_remote(
                peer_id,
                SHRequest::WriteToStore {
                    location,
                    payload,
                    lifetime,
                },
            )
            .await
        {
            Ok(SHResults::ReturnWriteStore(status)) => status,
            Ok(_) => StatusMessage::Error("Failed to write at the remote store".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    /// Read from the store of a remote Stronghold.
    pub async fn read_from_remote_store(&self, peer_id: PeerId, location: Location) -> (Vec<u8>, StatusMessage) {
        match self.ask_remote(peer_id, SHRequest::ReadFromStore { location }).await {
            Ok(SHResults::ReturnReadStore(payload, status)) => (payload, status),
            Ok(_) => (
                vec![],
                StatusMessage::Error("Failed to read at the remote store".into()),
            ),
            Err(err) => (vec![], StatusMessage::Error(err)),
        }
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer_id: PeerId,
        vault_path: V,
    ) -> (Vec<(usize, RecordHint)>, StatusMessage) {
        match self.ask_remote(peer_id, SHRequest::ListIds(vault_path.into())).await {
            Ok(SHResults::ReturnList(ids, status)) => (ids, status),
            Ok(_) => (
                vec![],
                StatusMessage::Error("Failed to list hints and indexes from at remote vault".into()),
            ),
            Err(err) => (vec![], StatusMessage::Error(err)),
        }
    }

    /// Executes a runtime command at a remote Stronghold.
    pub async fn remote_runtime_exec(&self, peer_id: PeerId, control_request: Procedure) -> ProcResult {
        match self
            .ask_remote(peer_id, SHRequest::ControlRequest(control_request))
            .await
        {
            Ok(SHResults::ReturnControlRequest(pr)) => pr,
            Ok(_) => ProcResult::Error("Invalid procedure result".into()),
            Err(err) => ProcResult::Error(err),
        }
    }

    // Wrap the SHRequest in an CommunicationRequest::RequestMsg and send it to the communication actor, to send it to
    // the remote peer. Fails if no communication actor is present, if sending the request failed or if an invalid event
    // was returned from the communication actor,
    async fn ask_remote(&self, peer_id: PeerId, request: SHRequest) -> Result<SHResults, String> {
        match self
            .ask_communication_actor(CommunicationRequest::RequestMsg { peer_id, request })
            .await
        {
            Ok(CommunicationResults::RequestMsgResult(Ok(ok))) => Ok(ok),
            Ok(CommunicationResults::RequestMsgResult(Err(e))) => Err(format!("Error sending request to peer {:?}", e)),
            Ok(_) => Err("Invalid communication actor response".into()),
            Err(err) => Err(err),
        }
    }

    async fn configure_firewall(&self, rule: FirewallRule) -> StatusMessage {
        match self
            .ask_communication_actor(CommunicationRequest::ConfigureFirewall(rule))
            .await
        {
            Ok(CommunicationResults::ConfigureFirewallAck) => StatusMessage::OK,
            Ok(_) => StatusMessage::Error("Invalid communication actor response".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    // Send request to communication actor, fails if none is present.
    async fn ask_communication_actor(
        &self,
        request: CommunicationRequest<SHRequest, ClientMsg>,
    ) -> Result<CommunicationResults<SHResults>, String> {
        if let Some(communication_actor) = self.communication_actor.as_ref() {
            let res = ask(&self.system, communication_actor, request).await;
            Ok(res)
        } else {
            Err(String::from("No communication spawned"))
        }
    }
}
