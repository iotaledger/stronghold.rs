// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod permissions;
use crate::{Query, RequestDirection};
use libp2p::PeerId;
pub use permissions::*;
use std::collections::HashMap;

/// Query for rules for a specific peer and direction.
/// From the returned [`FirewallRules`], only the rules for the demanded [`RuleDirection`] are handled.
pub type PeerRuleQuery = Query<(PeerId, RuleDirection), FirewallRules>;

/// Query for approval for an individual request.
pub type RequestApprovalQuery<P> = Query<(PeerId, RequestDirection, P), bool>;

/// Requests to the firewall.
#[derive(Debug)]
pub enum FirewallRequest<P> {
    /// Query for a peer specific rule.
    /// This is necessary if there is neither a default- nor a peer-specific rule for that peer.
    PeerSpecificRule(PeerRuleQuery),
    /// Request approval for a specific request due a [`Rule::Ask`] setting for this direction.
    RequestApproval(RequestApprovalQuery<P>),
}

/// Rules for request in a specific direction.
#[derive(Debug, Clone)]
pub enum Rule {
    /// Approve / Deny the request base on the set permission and request type.
    Permission(FirewallPermission),
    /// Ask for individual approval for each request by sending a [`FirewallRequest::RequestApproval`] through the
    /// firewall-channel provided to the `NetBehaviour`.
    Ask,
}

impl Default for Rule {
    fn default() -> Self {
        Self::reject_all()
    }
}

impl Rule {
    /// New Rule that permits all requests.
    pub fn allow_all() -> Self {
        Rule::Permission(FirewallPermission::all())
    }

    /// New Rule that rejects all requests.
    pub fn reject_all() -> Self {
        Rule::Permission(FirewallPermission::none())
    }

    /// Is the rule rejecting all types of requests i.g. is permission set to 0.
    pub fn is_reject_all(&self) -> bool {
        match self {
            Rule::Ask => false,
            Rule::Permission(permissions) => permissions.is_no_permissions(),
        }
    }
}

/// The direction for which a rule is applicable for.
#[derive(Debug, Clone, Copy)]
pub enum RuleDirection {
    /// Only inbound requests.
    Inbound,
    /// Only outbound requests.
    Outbound,
    /// All requests.
    Both,
}

impl RuleDirection {
    pub fn is_inbound(&self) -> bool {
        matches!(self, RuleDirection::Inbound | RuleDirection::Both)
    }
    pub fn is_outbound(&self) -> bool {
        matches!(self, RuleDirection::Outbound | RuleDirection::Both)
    }

    /// "Subtract" a different [`RuleDirection`] from self.
    /// This checks if the other rule is applicable for a direction that self is not.
    pub fn reduce(&self, other: RuleDirection) -> Option<RuleDirection> {
        match other {
            RuleDirection::Inbound if self.is_outbound() => Some(RuleDirection::Outbound),
            RuleDirection::Outbound if self.is_inbound() => Some(RuleDirection::Inbound),
            _ => None,
        }
    }
}

/// Rule configuration for inbound and outbound requests.
/// If not rules for a direction are set in the default and peer specific rules,
/// a [`FirewallRequest::PeerSpecificRule`] will be sent through the firewall-channel upon receiving a requests.
#[derive(Debug, Clone)]
pub struct FirewallRules {
    /// Rule for inbound requests.
    inbound: Option<Rule>,
    /// Rule for outbound requests.
    outbound: Option<Rule>,
}

impl FirewallRules {
    /// Create a new instance with no rules.
    pub fn empty() -> Self {
        FirewallRules {
            inbound: None,
            outbound: None,
        }
    }

    /// Create a new instance that permits all inbound and outbound requests.
    pub fn permit_all() -> Self {
        FirewallRules {
            inbound: Some(Rule::Permission(FirewallPermission::all())),
            outbound: Some(Rule::Permission(FirewallPermission::all())),
        }
    }

    /// Create a new instance with the provided rules.
    pub fn new(inbound: Option<Rule>, outbound: Option<Rule>) -> Self {
        FirewallRules { inbound, outbound }
    }

    /// Change one or both rules to the given rule.
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

/// Configuration for the firewall of the `NetBehaviour`.
#[derive(Debug)]
pub struct FirewallConfiguration {
    /// Default rules that are used if there are no peer-specific ones for a peer.
    default: FirewallRules,
    /// Peer specific rules.
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
    /// Create a new instance with the given default rules.
    pub fn new(default_in: Option<Rule>, default_out: Option<Rule>) -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: default_in,
                outbound: default_out,
            },
            peer_rules: HashMap::new(),
        }
    }

    /// Create a new instance with default configuration allowing all requests.
    pub fn allow_all() -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: Some(Rule::allow_all()),
                outbound: Some(Rule::allow_all()),
            },
            peer_rules: HashMap::new(),
        }
    }

    /// Create a new instance with default configuration rejecting all requests.
    pub fn reject_all() -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: Some(Rule::reject_all()),
                outbound: Some(Rule::reject_all()),
            },
            peer_rules: HashMap::new(),
        }
    }

    /// Get default firewall rules that are used if there are no peer-specific ones for a direction.
    pub fn get_default_rules(&self) -> &FirewallRules {
        &self.default
    }

    /// Set the default rules for one or both directions.
    /// In case of [`None`], the rule(s) are removed
    pub fn set_default(&mut self, default: Option<Rule>, direction: RuleDirection) {
        self.default.set_rule(default, direction);
    }

    /// Get the peer specific rules.
    pub fn get_rules(&self, peer: &PeerId) -> Option<&FirewallRules> {
        self.peer_rules.get(peer)
    }

    /// Get effective rules for a peer i.g. peer-specific rules or else the default rules for each direction.
    pub fn get_effective_rules(&self, peer: &PeerId) -> FirewallRules {
        let rules = self.peer_rules.get(peer);
        let inbound = rules
            .and_then(|r| r.inbound())
            .or_else(|| self.default.inbound())
            .cloned();
        let outbound = rules
            .and_then(|r| r.outbound())
            .or_else(|| self.default.outbound())
            .cloned();
        FirewallRules::new(inbound, outbound)
    }

    /// Set one or both rules for a specific peer.
    /// In case of [`None`], the rule(s) are removed.
    pub fn set_rule(&mut self, peer: PeerId, rule: Option<Rule>, direction: RuleDirection) {
        let rules = self.peer_rules.entry(peer).or_insert_with(FirewallRules::empty);
        if rule.is_some() {
            rules.set_rule(rule, direction);
        } else {
            match direction {
                RuleDirection::Both => {
                    self.peer_rules.remove(&peer);
                }
                RuleDirection::Inbound if rules.outbound.is_none() => {
                    self.peer_rules.remove(&peer);
                }
                RuleDirection::Outbound if rules.inbound.is_none() => {
                    self.peer_rules.remove(&peer);
                }
                _ => rules.set_rule(rule, direction),
            };
        }
    }
}
