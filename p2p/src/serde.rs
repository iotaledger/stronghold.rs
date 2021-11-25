// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    behaviour::{AddressInfo, PeerAddress},
    firewall::{FirewallConfiguration, FirewallRules, Rule},
};

use libp2p::core::{multihash, PeerId};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

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

#[derive(Serialize, Deserialize)]
pub enum SerdeRule {
    AllowAll,
    RejectAll,
    Ask,
    Restricted,
}

impl SerdeRule {
    pub fn into_rule_with_restriction<TRq, F>(self, restriction: F) -> Rule<TRq, F>
    where
        F: Fn(&TRq) -> bool,
    {
        Rule::try_from(self).unwrap_or(Rule::Restricted {
            restriction,
            _maker: PhantomData,
        })
    }
}

impl<TRq, F> From<Rule<TRq, F>> for SerdeRule
where
    F: Fn(&TRq) -> bool,
{
    fn from(rule: Rule<TRq, F>) -> Self {
        match rule {
            Rule::AllowAll => SerdeRule::AllowAll,
            Rule::RejectAll => SerdeRule::RejectAll,
            Rule::Ask => SerdeRule::Ask,
            Rule::Restricted { .. } => SerdeRule::Restricted,
        }
    }
}

impl<TRq, F> TryFrom<SerdeRule> for Rule<TRq, F>
where
    F: Fn(&TRq) -> bool,
{
    type Error = ();
    fn try_from(rule: SerdeRule) -> Result<Self, Self::Error> {
        match rule {
            SerdeRule::AllowAll => Ok(Rule::AllowAll),
            SerdeRule::RejectAll => Ok(Rule::RejectAll),
            SerdeRule::Ask => Ok(Rule::Ask),
            SerdeRule::Restricted => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerdeFirewallRules {
    inbound: Option<SerdeRule>,
    outbound: Option<SerdeRule>,
}

impl<TRq: Clone> From<FirewallRules<TRq>> for SerdeFirewallRules {
    fn from(rules: FirewallRules<TRq>) -> Self {
        SerdeFirewallRules {
            inbound: rules.inbound.map(|r| r.into()),
            outbound: rules.outbound.map(|r| r.into()),
        }
    }
}

impl<TRq: Clone> From<SerdeFirewallRules> for FirewallRules<TRq> {
    fn from(rules: SerdeFirewallRules) -> Self {
        FirewallRules {
            inbound: rules.inbound.and_then(|r| r.try_into().ok()),
            outbound: rules.outbound.and_then(|r| r.try_into().ok()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerdeFirewallConfig {
    default: SerdeFirewallRules,
    peer_rules: HashMap<SerdePeerId, SerdeFirewallRules>,
}

impl<TRq: Clone> From<FirewallConfiguration<TRq>> for SerdeFirewallConfig {
    fn from(config: FirewallConfiguration<TRq>) -> Self {
        let default = config.default.into();
        let peer_rules = config
            .peer_rules
            .into_iter()
            .filter_map(|(k, v)| {
                let rules = SerdeFirewallRules::from(v);
                if rules.inbound.is_some() || rules.outbound.is_some() {
                    Some((SerdePeerId::from(k), rules))
                } else {
                    None
                }
            })
            .collect();
        SerdeFirewallConfig { default, peer_rules }
    }
}

impl<TRq: Clone> TryFrom<SerdeFirewallConfig> for FirewallConfiguration<TRq> {
    type Error = multihash::Error;

    fn try_from(config: SerdeFirewallConfig) -> Result<Self, Self::Error> {
        let default = config.default.into();
        let mut peer_rules = HashMap::new();
        for (k, v) in config.peer_rules.into_iter() {
            let peer_id = PeerId::try_from(k)?;
            peer_rules.insert(peer_id, v.into());
        }
        Ok(FirewallConfiguration { default, peer_rules })
    }
}
