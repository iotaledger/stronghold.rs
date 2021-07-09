// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod permissions;
use crate::{Query, RequestDirection};
use libp2p::PeerId;
pub use permissions::*;
use std::{collections::HashMap, marker::PhantomData};

/// Query for rules of a specific peer and direction.
/// From the returned [`FirewallRules`], only the rules for the demanded [`RuleDirection`] are handled.
/// If the response channel is dropped or [`None`] is returned for a direction, pending requests will be rejected.
pub type PeerRuleQuery<Rq> = Query<(PeerId, RuleDirection), FirewallRules<Rq>>;

/// Query for approval of an individual request.
/// If the response channel is dropped, the request will be rejected.
pub type RequestApprovalQuery<Rq> = Query<(PeerId, RequestDirection, Rq), bool>;

/// Requests for approval and rules that are not covered by the current [`FirewallConfiguration`].
pub enum FirewallRequest<Rq: Clone> {
    /// Query for a peer specific rule.
    /// This is necessary if there is neither a default- nor a peer-specific rule for that peer.
    PeerSpecificRule(PeerRuleQuery<Rq>),
    /// Request approval for a specific request due a [`Rule::Ask`] setting for this direction.
    RequestApproval(RequestApprovalQuery<Rq>),
}

/// Rules for requests in a specific [`RequestDirection`].
#[derive(Clone)]
pub enum Rule<Rq, F = fn(&Rq) -> bool>
where
    F: Fn(&Rq) -> bool,
{
    /// Allow all requests
    AllowAll,
    /// Reject all requests
    RejectAll,
    /// Approve /  Reject request based on the set function.
    Restricted { restriction: F, _maker: PhantomData<Rq> },
    /// Ask for individual approval for each request by sending a [`FirewallRequest::RequestApproval`] through the
    /// firewall-channel provided to the `NetBehaviour`.
    Ask,
}

impl<Rq, F> Default for Rule<Rq, F>
where
    F: Fn(&Rq) -> bool,
{
    fn default() -> Self {
        Rule::RejectAll
    }
}

/// The direction for which a rule is applicable.
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
    /// Check if the rule is applicable for inbound requests.
    pub fn is_inbound(&self) -> bool {
        matches!(self, RuleDirection::Inbound | RuleDirection::Both)
    }

    /// Check if the rule is applicable for outbound requests.
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
#[derive(Clone)]
pub struct FirewallRules<Rq: Clone> {
    /// Rule for inbound requests.
    inbound: Option<Rule<Rq>>,
    /// Rule for outbound requests.
    outbound: Option<Rule<Rq>>,
}

impl<Rq: Clone> FirewallRules<Rq> {
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
            inbound: Some(Rule::AllowAll),
            outbound: Some(Rule::AllowAll),
        }
    }

    /// Create a new instance with the given rules.
    pub fn new(inbound: Option<Rule<Rq>>, outbound: Option<Rule<Rq>>) -> Self {
        FirewallRules { inbound, outbound }
    }

    /// Change one or both rules to the new rule.
    pub fn set_rule(&mut self, rule: Option<Rule<Rq>>, direction: RuleDirection) {
        direction.is_inbound().then(|| self.inbound = rule.clone());
        direction.is_outbound().then(|| self.outbound = rule);
    }

    /// Current inbound Rule (if there is one).
    pub fn inbound(&self) -> Option<&Rule<Rq>> {
        self.inbound.as_ref()
    }

    /// Current outbound Rule (if there is one).
    pub fn outbound(&self) -> Option<&Rule<Rq>> {
        self.outbound.as_ref()
    }
}

/// Configuration for the firewall of the `NetBehaviour`.
/// This config specifies what inbound and requests from/ to which peer are allowed.
/// If there are neither default rules, nor a peer specific rule for a request from/ to a peer,
/// a [`FirewallRequest::PeerSpecificRule`] will be sent through the firewall-channel that is passed to
/// `ShCommunication`.
pub struct FirewallConfiguration<Rq: Clone> {
    /// Default rules that are used if there are no peer-specific ones for a peer.
    default: FirewallRules<Rq>,
    /// Peer specific rules.
    peer_rules: HashMap<PeerId, FirewallRules<Rq>>,
}

impl<Rq: Clone> Default for FirewallConfiguration<Rq> {
    fn default() -> Self {
        FirewallConfiguration {
            default: FirewallRules::empty(),
            peer_rules: HashMap::new(),
        }
    }
}

impl<Rq: Clone> FirewallConfiguration<Rq> {
    /// Create a new instance with the given default rules.
    pub fn new(default_in: Option<Rule<Rq>>, default_out: Option<Rule<Rq>>) -> Self {
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
                inbound: Some(Rule::AllowAll),
                outbound: Some(Rule::AllowAll),
            },
            peer_rules: HashMap::new(),
        }
    }

    /// Create a new instance with default configuration rejecting all requests.
    pub fn reject_all() -> Self {
        FirewallConfiguration {
            default: FirewallRules {
                inbound: Some(Rule::RejectAll),
                outbound: Some(Rule::RejectAll),
            },
            peer_rules: HashMap::new(),
        }
    }

    /// Get default firewall rules that are used if there are no peer-specific ones for a direction.
    pub fn get_default_rules(&self) -> &FirewallRules<Rq> {
        &self.default
    }

    /// Set the default rules for one or both directions.
    /// In case of [`None`], the rule(s) are removed
    pub fn set_default(&mut self, default: Option<Rule<Rq>>, direction: RuleDirection) {
        self.default.set_rule(default, direction);
    }

    /// Get the peer specific rules.
    pub fn get_rules(&self, peer: &PeerId) -> Option<&FirewallRules<Rq>> {
        self.peer_rules.get(peer)
    }

    /// Get effective rules for a peer i.g. peer-specific rules or else the default rules for each direction.
    pub fn get_effective_rules(&self, peer: &PeerId) -> FirewallRules<Rq> {
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
    pub fn set_rule(&mut self, peer: PeerId, rule: Option<Rule<Rq>>, direction: RuleDirection) {
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
