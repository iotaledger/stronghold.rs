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
        transactions::{DataTransaction, InitTransaction, RevocationTransaction},
        utils::{TransactionId, ChainId},
    },
    vault::results::Record,
};

use std::collections::HashMap;

// /// A record identifier
//#[repr(transparent)]
//#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
//pub struct RecordId(ChainId);

//impl Debug for RecordId {
    //fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        //write!(f, "Record({})", (self.0).0.base64())
    //}
//}

/// List over all records by an owner and ordered by the counter
#[derive(Debug)]
pub struct ChainRecord(HashMap<ChainId, Vec<Record>>);

impl ChainRecord {
    /// create a new chain of records
    pub fn new<'a>(i: impl Iterator<Item = &'a Record>) -> crate::Result<Self> {
        // TODO: review this in light of the new changes => is this equivalent to a gc/prune

        // sort records by owner
        let mut chains: HashMap<_, Vec<Record>> = HashMap::new();
        i.for_each(|e| chains.entry(e.chain()).or_default().push(e.clone()));

        // order chains and remove all non-referenced transactions
        for (_, chain) in chains.iter_mut() {
            // sort transactions by counter
            chain.sort_by_key(|e| e.ctr());
            let result = chain
                .iter()
                .enumerate()
                .rev()
                .find_map(|(start, e)| Some((start, e.typed::<InitTransaction>()?.ctr)));

            if result.is_none() {
                return Err(crate::Error::ChainError(String::from(
                    "Chain does not contain an initial transaction",
                )));
            }

            let (start, mut ctr) = result.unwrap();

            // get transactions that are ancestors of the InitTransaction
            *chain = chain
                .iter()
                .skip(start)
                .take_while(|e| e.ctr() == ctr.postfix_increment())
                .cloned()
                .collect();
        }
        Ok(ChainRecord(chains))
    }

    /// get chains
    pub fn chains(&self) -> impl Iterator<Item = (&ChainId, &[Record])> {
        self.0.iter().map(|(id, chain)| (id, chain.as_slice()))
    }

    /// get a record in the chain by chain identifier
    pub fn get(&self, chain: &ChainId) -> Option<&[Record]> {
        self.0.get(chain).map(|e| e.as_slice())
    }

    /// get all records owned by the chain identifier or panic
    pub fn force_get(&self, chain: &ChainId) -> &[Record] {
        self.get(chain).expect("There is no chain for this owner")
    }

    /// get the last record of a chain by chain identifier
    pub fn force_last(&self, chain: &ChainId) -> &Record {
        self.force_get(chain)
            .last()
            .expect("The chain is empty and thus has no last record")
    }

    /// get all records in the vault
    pub fn all(&self) -> impl Iterator<Item = &Record> {
        self.0.values().flatten()
    }

    /// get all revoked transactions in the chain by chain identifier
    pub fn own_revoked(&self, chain: &ChainId) -> impl Iterator<Item = (TransactionId, &Record)> {
        let chain = self.force_get(chain);
        chain
            .iter()
            .filter_map(|e| Some((e.typed::<RevocationTransaction>()?.id, e)))
    }

    /// get all foreign data not owned by the owner id
    pub fn foreign_data(&self, except: &ChainId) -> impl Iterator<Item = &Record> {
        let except = *except;
        self.0
            .iter()
            .filter(move |(id, _)| **id != except)
            .map(|(_, chain)| chain)
            .flatten()
            .filter(|e| e.typed::<DataTransaction>().is_some())
    }
}

/// List of all valid data transactions
#[derive(Debug)]
pub struct ValidRecord(HashMap<ChainId, DataTransaction>);

impl ValidRecord {
    /// create a new valid record chain
    pub fn new(chains: &ChainRecord) -> Self {
        // collect the data and remove revoked ones
        let mut valid: HashMap<_, _> = chains
            .all()
            .filter_map(|e| e.typed::<DataTransaction>())
            .map(|dtx| (dtx.chain, dtx))
            .collect();
        chains
            .all()
            .filter_map(|e| e.typed::<RevocationTransaction>())
            .for_each(|r| {
                valid.remove(&r.chain);
            });

        // shrink the map
        valid.shrink_to_fit();
        unimplemented!("TODO: remove")
    }

    /// get chain by id
    pub fn get(&self, id: &ChainId) -> Option<&DataTransaction> {
        self.0.get(id)
    }

    /// get all valid records
    pub fn all(&self) -> impl Iterator<Item = &DataTransaction> + ExactSizeIterator {
        self.0.values()
    }

    /// get all valid for chain identifier
    // TODO: does this still make sense? i.e. can there be more than one valid record per chain?
    pub fn all_for_chain(&self, chain: &ChainId) -> impl Iterator<Item = &DataTransaction> {
        let chain = *chain;
        self.all().filter(move |e| e.chain == chain)
    }
}
