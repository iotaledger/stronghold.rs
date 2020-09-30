// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{
    types::{
        transactions::{TransactionType, Transaction},
        utils::{TransactionId, Val},
    },
};

pub struct Chain {
    garbage: Vec<TransactionId>,
    subchain: Vec<TransactionId>,
    init: Option<TransactionId>,
    data: Option<TransactionId>,
    highest_ctr: Option<Val>,
}

impl Chain {
    pub fn data(&self) -> Option<TransactionId> {
        assert!(self.data.is_some() <= self.init.is_some());
        self.data
    }

    pub fn init(&self) -> Option<TransactionId> {
        self.init
    }

    pub fn highest_ctr(&self) -> Option<Val> {
        self.highest_ctr
    }

    pub fn garbage(&self) -> &Vec<TransactionId> {
        &self.garbage
    }

    pub fn subchain(&self) -> &Vec<TransactionId> {
        &self.subchain
    }

    pub fn len(&self) -> usize {
        self.subchain.len()
    }

    pub fn balance(&self) -> (usize, usize) {
        (self.len(), self.len() + self.garbage.len())
    }

    pub fn prune<'a>(chain: impl Iterator<Item = &'a Transaction>) -> crate::Result<Chain> {
        let mut res = Chain {
            garbage: vec![],
            subchain: vec![],
            init: None,
            data: None,
            highest_ctr: None,
        };

        let mut chain: Vec<_> = chain.map(|tx| tx.untyped()).collect();
        chain.sort_by_key(|tx| tx.ctr);

        let mut revocation_score = 0;
        for tx in chain {
            res.highest_ctr = Some(tx.ctr); // NB assumed to sorted ascending

            if res.init.is_none() {
                match tx.r#type()? {
                    TransactionType::Init => {
                        res.init = Some(tx.id);
                        res.subchain.push(tx.id);
                    }
                    _ => res.garbage.push(tx.id),
                }
            } else {
                match tx.r#type()? {
                    TransactionType::Data => {
                        if let Some(previous) = res.data {
                            res.garbage.push(previous);
                            res.subchain.retain(|i| i != &previous);
                        }
                        res.data = Some(tx.id);

                        // Scenario: init, data, revoke, data
                        // that is: data cancels revoke
                        revocation_score = 0;
                    }
                    TransactionType::Init => {
                        res.garbage.append(&mut res.subchain);
                        res.init = Some(tx.id);
                        res.data = None;
                        revocation_score = 0;
                    }
                    TransactionType::Revocation => {
                        revocation_score += 1;
                    }
                    //TransactionType::Unrevocation => {
                    //    if revocation_score <= 0 {
                    //        res.garbage.push(tx.id);
                    //    } else {
                    //        revocation_score -= 1;
                    //    }
                    //}
                }

                res.subchain.push(tx.id);
            }
        }

        if revocation_score > 0 {
            res.garbage.append(&mut res.subchain);
            res.init = None;
            res.data = None;
        } else {
            // TODO: track revokes and unrevokes and consider them as garbage if the chain
            // survives
        }

        Ok(res)
    }
}

