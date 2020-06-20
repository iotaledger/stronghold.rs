use crate::{
    types::{
        commits::{DataCommit, InitCommit, RevocationCommit},
        utils::Id,
    },
    vault::entries::Entry,
};

use std::collections::HashMap;

pub struct ChainIndex(HashMap<Id, Vec<Entry>>);

pub struct ValidIndex(HashMap<Id, Entry>);

impl ChainIndex {
    pub fn new(i: impl Iterator<Item = Entry>) -> crate::Result<Self> {
        let mut chains: HashMap<_, Vec<Entry>> = HashMap::new();
        i.for_each(|e| chains.entry(e.owner()).or_default().push(e.clone()));

        for (_, chain) in chains.iter_mut() {
            chain.sort_by_key(|e| e.ctr());
            let (start, mut ctr) = chain
                .iter()
                .enumerate()
                .rev()
                .find_map(|(start, e)| Some((start, e.typed::<InitCommit>()?.ctr)))
                .ok_or(crate::Error::ChainError(String::from(
                    "Chain does not contain a start commit",
                )))?;

            *chain = chain
                .iter()
                .skip(start)
                .take_while(|e| e.ctr() == ctr.postfix_increment())
                .cloned()
                .collect();
        }
        Ok(ChainIndex(chains))
    }

    pub fn owners(&self) -> impl Iterator<Item = (&Id, &[Entry])> {
        self.0.iter().map(|(uid, chain)| (uid, chain.as_slice()))
    }

    pub fn get(&self, owner: &Id) -> Option<&[Entry]> {
        self.0.get(owner).map(|e| e.as_slice())
    }
    pub fn force_get(&self, owner: &Id) -> &[Entry] {
        self.get(owner).expect("There is no chain for this owner")
    }
    pub fn force_last(&self, owner: &Id) -> &Entry {
        self.force_get(owner)
            .last()
            .expect("The chain is empty and thus has no last entry")
    }

    pub fn all(&self) -> impl Iterator<Item = &Entry> {
        self.0.values().flatten()
    }

    pub fn own_revoked(&self, owner: &Id) -> impl Iterator<Item = (Id, &Entry)> {
        let chain = self.force_get(owner);
        chain
            .iter()
            .filter_map(|e| Some((e.typed::<RevocationCommit>()?.uid, e)))
    }

    pub fn foreign_data(&self, except: &Id) -> impl Iterator<Item = &Entry> {
        let except = *except;
        self.0
            .iter()
            .filter(move |(owner, _)| **owner != except)
            .map(|(_, chain)| chain)
            .flatten()
            .filter(|e| e.typed::<DataCommit>().is_some())
    }
}

impl ValidIndex {
    pub fn new(chains: &ChainIndex) -> Self {
        let mut valid: HashMap<_, _> = chains
            .all()
            .filter_map(|e| Some((e.typed::<DataCommit>()?.uid, e.clone())))
            .collect();
        chains
            .all()
            .filter_map(|e| e.typed::<RevocationCommit>())
            .for_each(|r| {
                valid.remove(&r.uid);
            });

        valid.shrink_to_fit();
        Self(valid)
    }

    pub fn get(&self, uid: &Id) -> Option<&Entry> {
        self.0.get(uid)
    }

    pub fn all(&self) -> impl Iterator<Item = &Entry> + ExactSizeIterator {
        self.0.values()
    }

    pub fn all_for_owner(&self, owner: &Id) -> impl Iterator<Item = &Entry> {
        let owner = *owner;
        self.all().filter(move |e| e.owner() == owner)
    }
}
