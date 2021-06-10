// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod permissions;
use crate::{Query, RequestDirection};
use libp2p::PeerId;
pub use permissions::*;
use std::collections::HashMap;

pub type PeerRuleQuery = Query<(PeerId, RuleDirection), FirewallRules>;
pub type RequestApprovalQuery<P> = Query<(PeerId, RequestDirection, P), bool>;

#[derive(Debug)]
pub enum FirewallRequest<P> {
    PeerSpecificRule(PeerRuleQuery),
    RequestApproval(RequestApprovalQuery<P>),
}

#[derive(Debug, Clone)]
pub enum Rule {
    Permission(FirewallPermission),
    Ask,
}

impl Default for Rule {
    fn default() -> Self {
        Self::reject_all()
    }
}

impl Rule {
    pub fn is_reject_all(&self) -> bool {
        match self {
            Rule::Ask => false,
            Rule::Permission(permissions) => permissions.is_no_permissions(),
        }
    }

    pub fn allow_all() -> Self {
        Rule::Permission(FirewallPermission::all())
    }

    pub fn reject_all() -> Self {
        Rule::Permission(FirewallPermission::none())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RuleDirection {
    Inbound,
    Outbound,
    Both,
}

impl RuleDirection {
    pub fn is_inbound(&self) -> bool {
        matches!(self, RuleDirection::Inbound | RuleDirection::Both)
    }
    pub fn is_outbound(&self) -> bool {
        matches!(self, RuleDirection::Outbound | RuleDirection::Both)
    }

    pub fn reduce(&self, other: RuleDirection) -> Option<RuleDirection> {
        match other {
            RuleDirection::Inbound if self.is_outbound() => Some(RuleDirection::Outbound),
            RuleDirection::Outbound if self.is_inbound() => Some(RuleDirection::Inbound),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FirewallRules {
    inbound: Option<Rule>,
    outbound: Option<Rule>,
}

impl FirewallRules {
    pub fn empty() -> Self {
        FirewallRules {
            inbound: None,
            outbound: None,
        }
    }
    pub fn permit_all() -> Self {
        FirewallRules {
            inbound: Some(Rule::Permission(FirewallPermission::all())),
            outbound: Some(Rule::Permission(FirewallPermission::all())),
        }
    }

    pub fn new(inbound: Option<Rule>, outbound: Option<Rule>) -> Self {
        FirewallRules { inbound, outbound }
    }

    pub fn set_rule(&mut self, rule: Option<Rule>, direction: RuleDirection) {
        direction.is_inbound().then(|| self.inbound = rule.clone());
        direction.is_outbound().then(|| self.outbound = rule);
    }

    pub fn inbound(&self) -> Option<&Rule> {
        self.inbound.as_ref()
    }

    pub fn outbound(&self) -> Option<&Rule> {
        self.outbound.as_ref()
    }

    pub fn is_reject_all_inbound(&self) -> bool {
        match self.inbound() {
            Some(Rule::Permission(permissions)) => permissions.is_no_permissions(),
            _ => false,
        }
    }

    pub fn is_reject_all_outbound(&self) -> bool {
        match self.outbound() {
            Some(Rule::Permission(permissions)) => permissions.is_no_permissions(),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct FirewallConfiguration {
    default: FirewallRules,
    peer_rules: HashMap<PeerId, FirewallRules>,
}

impl Default for FirewallConfiguration {
    fn default() -> Self {
        FirewallConfiguration {
            default: FirewallRules::empty(),
            peer_rules: HashMap::new(),
        }
    }
}

impl FirewallConfiguration {
    pub fn new(default_in: Option<Rule>, default_out: Option<Rule>) -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: default_in,
                outbound: default_out,
            },
            peer_rules: HashMap::new(),
        }
    }

    pub fn allow_all() -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: Some(Rule::allow_all()),
                outbound: Some(Rule::allow_all()),
            },
            peer_rules: HashMap::new(),
        }
    }

    pub fn get_default_in(&self) -> Option<&Rule> {
        self.default.inbound()
    }

    pub fn get_default_out(&self) -> Option<&Rule> {
        self.default.outbound()
    }

    pub fn get_default_rules(&self) -> &FirewallRules {
        &self.default
    }

    pub fn set_default(&mut self, default: Rule, direction: RuleDirection) {
        self.default.set_rule(Some(default), direction);
    }

    pub fn remove_default(&mut self, direction: RuleDirection) {
        self.default.set_rule(None, direction);
    }

    pub fn get_in_rule(&self, peer: &PeerId) -> Option<&Rule> {
        self.peer_rules.get(peer).and_then(|rules| rules.inbound.as_ref())
    }

    pub fn get_out_rule(&self, peer: &PeerId) -> Option<&Rule> {
        self.peer_rules.get(peer).and_then(|rules| rules.outbound.as_ref())
    }

    pub fn get_in_rule_or_default(&self, peer: &PeerId) -> Option<&Rule> {
        self.peer_rules
            .get(peer)
            .and_then(|rules| rules.inbound.as_ref())
            .or_else(|| self.get_default_in())
    }

    pub fn get_out_rule_or_default(&self, peer: &PeerId) -> Option<&Rule> {
        self.peer_rules
            .get(peer)
            .and_then(|rules| rules.outbound.as_ref())
            .or_else(|| self.get_default_out())
    }

    pub fn get_rules(&self, peer: &PeerId) -> Option<&FirewallRules> {
        self.peer_rules.get(peer)
    }

    pub fn set_rule(&mut self, peer: PeerId, rule: Rule, direction: RuleDirection) {
        let rules = self.peer_rules.entry(peer).or_insert_with(FirewallRules::empty);
        rules.set_rule(Some(rule), direction);
    }

    pub fn set_rules(&mut self, peer: PeerId, rules: FirewallRules, direction: RuleDirection) {
        let current = self.peer_rules.entry(peer).or_insert_with(FirewallRules::empty);
        direction
            .is_inbound()
            .then(|| current.set_rule(rules.inbound().cloned(), RuleDirection::Inbound));
        direction
            .is_outbound()
            .then(|| current.set_rule(rules.outbound().cloned(), RuleDirection::Outbound));
    }

    pub fn remove_rule(&mut self, peer: &PeerId, direction: RuleDirection) -> bool {
        if let Some(rules) = self.peer_rules.get_mut(peer) {
            let removed_rule = rules.outbound.is_some() && direction.is_outbound()
                || rules.inbound.is_some() && direction.is_inbound();
            match direction {
                RuleDirection::Both => {
                    self.peer_rules.remove(peer);
                }
                RuleDirection::Inbound if rules.outbound.is_none() => {
                    self.peer_rules.remove(peer);
                }
                RuleDirection::Outbound if rules.inbound.is_none() => {
                    self.peer_rules.remove(peer);
                }
                _ => rules.set_rule(None, direction),
            };
            removed_rule
        } else {
            false
        }
    }
}
