// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{AddressInfo, PeerAddress};

use libp2p::core::{multihash, PeerId};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SerdePeerId(Vec<u8>);

impl From<PeerId> for SerdePeerId {
    fn from(peer_id: PeerId) -> Self {
        SerdePeerId(peer_id.to_bytes())
    }
}

impl TryFrom<SerdePeerId> for PeerId {
    type Error = multihash::Error;
    fn try_from(peer_id: SerdePeerId) -> Result<Self, Self::Error> {
        PeerId::from_bytes(&peer_id.0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerdeAddressInfo {
    peers: HashMap<SerdePeerId, PeerAddress>,
    relays: Vec<SerdePeerId>,
}

impl From<AddressInfo> for SerdeAddressInfo {
    fn from(info: AddressInfo) -> Self {
        let relays = info.relays.into_iter().map(SerdePeerId::from).collect();
        let peers = info.peers.into_iter().map(|(k, v)| (SerdePeerId::from(k), v)).collect();
        SerdeAddressInfo { peers, relays }
    }
}

impl TryFrom<SerdeAddressInfo> for AddressInfo {
    type Error = multihash::Error;

    fn try_from(info: SerdeAddressInfo) -> Result<Self, Self::Error> {
        let mut peers = HashMap::new();
        for (k, v) in info.peers {
            let peer_id = PeerId::try_from(k)?;
            peers.insert(peer_id, v);
        }
        let mut relays = SmallVec::new();
        for peer in info.relays {
            let peer_id = PeerId::try_from(peer)?;
            relays.push(peer_id)
        }
        Ok(AddressInfo { peers, relays })
    }
}
