// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Firewall in [`StrongholdP2p`][`crate::StrongholdP2p`] for filtering inbound requests.

pub mod permissions;
use core::fmt;
use futures::channel::oneshot;
use libp2p::PeerId;
use std::{borrow::Borrow, collections::HashMap, fmt::Debug, marker::PhantomData, sync::Arc};

/// Derive new type from the received request, that only contains firewall-relevant information.
///
/// ```
/// # use serde::{Serialize, Deserialize};
/// # use p2p::firewall::FwRequest;
/// #
/// #[derive(Debug, PartialEq)]
/// enum Request {
///     Read { key: Vec<u8> },
///     Write { key: Vec<u8>, data: Vec<u8> },
/// }
///
/// #[derive(Debug, Clone, PartialEq)]
/// enum RequestType {
///     Read,
///     Write,
/// }
///
/// impl FwRequest<Request> for RequestType {
///     fn from_request(request: &Request) -> Self {
///         match request {
///             Request::Read { .. } => RequestType::Read,
///             Request::Write { .. } => RequestType::Write,
///         }
///     }
/// }
/// ```
pub trait FwRequest<Rq>: Send + 'static {
    fn from_request(request: &Rq) -> Self;
}

impl<T: Clone + Send + 'static, U: Borrow<T>> FwRequest<U> for T {
    fn from_request(request: &U) -> Self {
        request.borrow().clone()
    }
}

/// Requests for approval and rules that are not covered by the current [`FirewallRules`].
pub enum FirewallRequest<TRq> {
    /// Query for a peer specific rule.
    /// This is necessary if there is neither a default- nor a peer-specific rule for that peer.
    PeerSpecificRule {
        /// The remote peer for which the rule is required.
        peer: PeerId,
        /// Channel for returning the new firewall rule.
        /// If the `Sender` is dropped, all request that are awaiting the rule will be rejected.
        rule_tx: oneshot::Sender<Rule<TRq>>,
    },
    /// Request approval for a specific request due a [`Rule::Ask`] setting.
    RequestApproval {
        /// The peer from which the request is received.
        peer: PeerId,
        /// The request message.
        request: TRq,
        /// Channel for returning the approval.
        /// If the `Sender` is dropped, the request will be rejected.
        approval_tx: oneshot::Sender<bool>,
    },
}

/// Rules for inbound requests.
pub enum Rule<TRq> {
    /// Allow all requests
    AllowAll,
    /// Reject all requests
    RejectAll,
    /// Approve /  Reject request based on the set function.
    Restricted {
        restriction: Arc<dyn Fn(&TRq) -> bool + Send + Sync>,
        _maker: PhantomData<TRq>,
    },
    /// Ask for individual approval for each request by sending a [`FirewallRequest::RequestApproval`] through the
    /// firewall-channel.
    Ask,
}

impl<TRq> fmt::Debug for Rule<TRq> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::AllowAll { .. } => write!(f, "Rule::AllowAll"),
            Rule::RejectAll { .. } => write!(f, "Rule::RejectAll"),
            Rule::Ask { .. } => write!(f, "Rule::Ask"),
            Rule::Restricted { .. } => write!(f, "Rule::Restricted"),
        }
    }
}

impl<TRq> Clone for Rule<TRq> {
    fn clone(&self) -> Self {
        match self {
            Rule::AllowAll => Rule::AllowAll,
            Rule::RejectAll => Rule::RejectAll,
            Rule::Restricted { restriction, _maker } => Rule::Restricted {
                restriction: restriction.clone(),
                _maker: *_maker,
            },
            Rule::Ask => Rule::Ask,
        }
    }
}

/// Rules for the firewall of [`StrongholdP2p`][crate::StrongholdP2p].
/// These rules specifies what inbound requests from which peers are allowed.
/// If there is neither a default rule, nor a peer specific one for a request from a peer,
/// a [`FirewallRequest::PeerSpecificRule`] will be sent through the firewall-channel that is passed to
/// `StrongholdP2p`.
///
/// Per default no rule is set.
#[derive(Debug)]
pub struct FirewallRules<TRq> {
    /// Default rule that is used if there is no peer-specific one for a peer.
    default: Option<Rule<TRq>>,
    /// Peer specific rules.
    peer_rules: HashMap<PeerId, Rule<TRq>>,
}

impl<TRq> Default for FirewallRules<TRq> {
    fn default() -> Self {
        FirewallRules {
            default: None,
            peer_rules: HashMap::new(),
        }
    }
}

impl<TRq> Clone for FirewallRules<TRq> {
    fn clone(&self) -> Self {
        FirewallRules {
            default: self.default.clone(),
            peer_rules: self.peer_rules.clone(),
        }
    }
}

impl<TRq> FirewallRules<TRq> {
    /// Create a new instance with the given default rule.
    /// If no  is set, a a [`FirewallRequest::PeerSpecificRule`] will be sent through the firewall-channel on
    /// inbound requests.
    pub fn new(default: Option<Rule<TRq>>, peer_rules: HashMap<PeerId, Rule<TRq>>) -> Self {
        FirewallRules { default, peer_rules }
    }

    /// Don't set any rules.
    /// In case of an inbound request, a [`FirewallRequest::PeerSpecificRule`] request is sent through the
    /// `firewall_channel` to specify the rule for the remote peer.
    pub fn empty() -> Self {
        FirewallRules {
            default: None,
            peer_rules: HashMap::new(),
        }
    }

    /// Create a new instance with default rules that allow all requests.
    pub fn allow_all() -> Self {
        FirewallRules {
            default: Some(Rule::AllowAll),
            peer_rules: HashMap::new(),
        }
    }

    /// Create a new instance with default rules that reject all requests.
    pub fn allow_none() -> Self {
        FirewallRules {
            default: Some(Rule::RejectAll),
            peer_rules: HashMap::new(),
        }
    }

    /// Get default firewall rule.
    pub fn get_default_rule(&self) -> Option<&Rule<TRq>> {
        self.default.as_ref()
    }

    /// Set the default rule.
    pub fn set_default(&mut self, default: Option<Rule<TRq>>) {
        self.default = default
    }

    /// Get the peer specific rule.
    pub fn get_rule(&self, peer: &PeerId) -> Option<&Rule<TRq>> {
        self.peer_rules.get(peer)
    }

    /// Get effective rule for a peer, which is the peer-specific rule or else the default rule.
    pub fn get_effective_rule(&self, peer: &PeerId) -> Option<&Rule<TRq>> {
        self.peer_rules.get(peer).or(self.default.as_ref())
    }

    /// Set the rule for a specific peer.
    pub fn set_rule(&mut self, peer: PeerId, rule: Rule<TRq>) {
        self.peer_rules.insert(peer, rule);
    }

    /// Remove the rule for a specific peer.
    pub fn remove_rule(&mut self, peer: &PeerId) {
        self.peer_rules.remove(peer);
    }
}
