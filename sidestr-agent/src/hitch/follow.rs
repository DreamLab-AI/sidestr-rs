//! The chain watch: a producer's or a mirror's blocks, followed with
//! reorganisations found and measured.
//!
//! A source serves `blocks.json` (the index: height, hash, offset, size)
//! and `blocks.dat` (the records), as siding's producer and the Pages
//! mirror both do. [`ChainFollower::plan`] compares the index with the
//! blocks already held and names the first height that differs, so one
//! ranged read from that record's offset fetches exactly the tail needed.
//! [`ChainFollower::apply`] checks each block in that tail before it is
//! kept:
//!
//! - it decodes as a block of the chain's family;
//! - its hash is the one the index gives;
//! - it links to the block below it;
//! - its solution satisfies the chain's challenge. On a level-1 chain this
//!   is the signer's key-path signature, so a mirror cannot forge a block.
//!
//! A tail that replaces blocks already held is a reorganisation.
//! [`Advance::Reorg`] reports where it forks, how deep it goes and which
//! transactions it undid. Transactions are indexed by id and by the
//! outpoints they spend, which is what a channel's watch asks for: whether
//! the funding confirmed, which transaction spent it, and which spent each
//! output of a close.
//!
//! The transactions are not validated here. See the [module
//! documentation](super) for why.
//!
//! ```
//! use sidestr_agent::hitch::follow::{Advance, ChainFollower, Plan};
//! use sidestr_core::block::{challenge_for, pubkey_of};
//! use sidestr_core::blockfile::{Entry, Index};
//! use sidestr_core::document::ChainDocument;
//! use sidestr_core::mirror::encode_record;
//! use sidestr_core::state::State;
//!
//! let producer = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
//! let doc = ChainDocument::from_json(&format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"{}",
//!   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
//!   "genesisTime":1790000000,"pegs":[]}}"#, challenge_for(&pubkey_of(&producer)).to_hex_string())).unwrap();
//! let genesis = bitcoin::consensus::encode::serialize(&State::genesis_block_for(&doc, &producer).unwrap());
//! let hash = State::genesis_block_for(&doc, &producer).unwrap().block_hash().to_string();
//! let index = Index { network: doc.id.clone(), from: 0, to: 0,
//!     blocks: vec![Entry { height: 0, hash, offset: 0, size: genesis.len() as u32 }] };
//!
//! let mut follower = ChainFollower::new(&doc).unwrap();
//! let Plan::Fetch { from, offset } = follower.plan(&index).unwrap() else { unreachable!() };
//! assert_eq!((from, offset), (0, 0));
//! let advance = follower.apply(&index, from, &encode_record(0, &genesis)).unwrap();
//! assert_eq!(advance, Advance::Extended { from: 0, to: 0 });
//! assert_eq!(follower.plan(&index).unwrap(), Plan::UpToDate);
//! ```

use std::collections::{HashMap, HashSet};

use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use sidestr_core::block::{verify_block_solution, HeaderFamily, SidestrBlock, Stock};
use sidestr_core::blockfile::Index;
use sidestr_core::document::ChainDocument;
use sidestr_core::mirror::records;
use sidestr_core::parents::Family;
use sidestr_header::Blake2bV2;

use super::{Error, Result};

/// What the next read of a source should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// The source agrees with every block held.
    UpToDate,
    /// The source is shorter than what is held, and agrees up to `len`
    /// blocks: a reorganisation to a shorter chain. Call
    /// [`ChainFollower::truncate`].
    Truncate {
        /// Blocks the source still has.
        len: u32,
    },
    /// Read `blocks.dat` from byte `offset` to its end, then call
    /// [`ChainFollower::apply`] with `from`.
    Fetch {
        /// The first height to (re)read.
        from: u32,
        /// That record's offset in the block file.
        offset: u64,
    },
}

/// What a read changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    /// Nothing.
    Unchanged,
    /// New blocks on top of those held.
    Extended {
        /// The first new height.
        from: u32,
        /// The new tip.
        to: u32,
    },
    /// Blocks held were replaced: a reorganisation.
    Reorg {
        /// The first height replaced.
        fork: u32,
        /// How many held blocks were replaced or dropped.
        depth: u32,
        /// The new tip, or `None` if the chain is now empty.
        to: Option<u32>,
        /// Transactions that were in a replaced block and are in no block
        /// now.
        undone: Vec<Txid>,
    },
}

#[derive(Debug, Clone)]
struct Held {
    hash: BlockHash,
    txdata: Vec<Transaction>,
}

/// A chain followed from its genesis: hashes, transactions, spends.
#[derive(Debug, Clone)]
pub struct ChainFollower {
    family: Family,
    challenge: ScriptBuf,
    blocks: Vec<Held>,
    txs: HashMap<Txid, (u32, usize)>,
    spends: HashMap<OutPoint, (Txid, u32)>,
}

impl ChainFollower {
    /// A follower for the chain `doc` describes, holding no blocks yet:
    /// stock 80-byte headers beside `btc`/`tbtc4`, or Knots' 164-byte
    /// BLAKE2b v2 headers beside `xbt`/`txbt4` ([`Blake2bV2`]).
    pub fn new(doc: &ChainDocument) -> Result<Self> {
        Ok(Self {
            family: doc.family()?,
            challenge: doc.challenge_script()?,
            blocks: Vec::new(),
            txs: HashMap::new(),
            spends: HashMap::new(),
        })
    }

    /// The tip height, if any block is held.
    pub fn height(&self) -> Option<u32> {
        self.blocks.len().checked_sub(1).map(|h| h as u32)
    }

    /// The hash at `height`.
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.blocks.get(height as usize).map(|b| b.hash)
    }

    /// The tip's height and hash.
    pub fn tip(&self) -> Option<(u32, BlockHash)> {
        let h = self.height()?;
        Some((h, self.blocks[h as usize].hash))
    }

    /// Confirmations of a block at `height`: one at the tip.
    pub fn confirmations(&self, height: u32) -> u32 {
        self.height()
            .map_or(0, |tip| tip.saturating_add(1).saturating_sub(height))
    }

    /// A transaction in a held block, and that block's height.
    pub fn find_tx(&self, txid: &Txid) -> Option<(u32, &Transaction)> {
        let (h, i) = *self.txs.get(txid)?;
        Some((h, &self.blocks[h as usize].txdata[i]))
    }

    /// The transaction that spends `outpoint` in a held block, with its id
    /// and height.
    pub fn spender(&self, outpoint: &OutPoint) -> Option<(Txid, u32, &Transaction)> {
        let (txid, h) = *self.spends.get(outpoint)?;
        let (_, tx) = self.find_tx(&txid)?;
        Some((txid, h, tx))
    }

    /// Every held block's transactions with its height, oldest first: for
    /// the assets view a wallet keeps funding off carriers with.
    pub fn transactions(&self) -> impl Iterator<Item = (u32, &[Transaction])> {
        self.blocks
            .iter()
            .enumerate()
            .map(|(h, b)| (h as u32, b.txdata.as_slice()))
    }

    /// Compare a source's index with the blocks held.
    pub fn plan(&self, index: &Index) -> Result<Plan> {
        for (i, e) in index.blocks.iter().enumerate() {
            if e.height as usize != i {
                return Err(Error::Chain(format!(
                    "the index lists height {} at position {i}",
                    e.height
                )));
            }
        }
        let common = self
            .blocks
            .iter()
            .zip(&index.blocks)
            .take_while(|(held, e)| held.hash.to_string() == e.hash)
            .count();
        if common < index.blocks.len() {
            return Ok(Plan::Fetch {
                from: common as u32,
                offset: index.blocks[common].offset,
            });
        }
        if common < self.blocks.len() {
            return Ok(Plan::Truncate { len: common as u32 });
        }
        Ok(Plan::UpToDate)
    }

    /// Drop every block from height `len` on (a source that went back to a
    /// shorter chain).
    pub fn truncate(&mut self, len: u32) -> Advance {
        let len = len as usize;
        if len >= self.blocks.len() {
            return Advance::Unchanged;
        }
        let depth = (self.blocks.len() - len) as u32;
        let removed: Vec<Txid> = self.blocks[len..]
            .iter()
            .flat_map(|b| b.txdata.iter().map(Transaction::compute_txid))
            .collect();
        self.blocks.truncate(len);
        self.reindex();
        Advance::Reorg {
            fork: len as u32,
            depth,
            to: self.height(),
            undone: removed
                .into_iter()
                .filter(|t| !self.txs.contains_key(t))
                .collect(),
        }
    }

    /// Take the tail read for a [`Plan::Fetch`]: `tail` is the block file
    /// from the record at height `from` onward. Every block the index lists
    /// from `from` must be there and pass the checks in the module
    /// documentation. Records past the index's end (a file read just after
    /// the index) are ignored. On an error nothing changes.
    pub fn apply(&mut self, index: &Index, from: u32, tail: &[u8]) -> Result<Advance> {
        let from_us = from as usize;
        if from_us > self.blocks.len() || from_us > index.blocks.len() {
            return Err(Error::Chain(format!(
                "a tail from height {from} leaves a gap"
            )));
        }
        let want = index.blocks.len() - from_us;
        let recs = records(tail)?;
        if recs.len() < want {
            return Err(Error::Chain(format!(
                "the block file holds {} records from height {from}; the index lists {want}",
                recs.len()
            )));
        }
        let mut fresh: Vec<Held> = Vec::with_capacity(want);
        for (i, r) in recs.iter().take(want).enumerate() {
            let height = from + i as u32;
            if r.height != height {
                return Err(Error::Chain(format!(
                    "record {i} of the tail is height {}, not {height}",
                    r.height
                )));
            }
            let entry = &index.blocks[height as usize];
            let (hash, prev, txdata) = match self.family {
                Family::Stock => read_block(&Stock, r.bytes, &self.challenge),
                Family::Blake2b => read_block(&Blake2bV2, r.bytes, &self.challenge),
            }
            .map_err(|e| Error::Chain(format!("block {height}: {e}")))?;
            if hash.to_string() != entry.hash {
                return Err(Error::Chain(format!(
                    "block {height} hashes to {hash}, the index says {}",
                    entry.hash
                )));
            }
            if height > 0 {
                let below = if i == 0 {
                    self.blocks[height as usize - 1].hash
                } else {
                    fresh[i - 1].hash
                };
                if prev != below {
                    return Err(Error::Chain(format!(
                        "block {height} does not link to block {}",
                        height - 1
                    )));
                }
            }
            fresh.push(Held { hash, txdata });
        }
        if fresh.is_empty() && from_us == self.blocks.len() {
            return Ok(Advance::Unchanged);
        }
        let replaced = self.blocks.len() - from_us;
        let removed: Vec<Txid> = self.blocks[from_us..]
            .iter()
            .flat_map(|b| b.txdata.iter().map(Transaction::compute_txid))
            .collect();
        self.blocks.truncate(from_us);
        self.blocks.extend(fresh);
        self.reindex();
        let to = self.height();
        if replaced == 0 {
            return Ok(match to {
                Some(to) if to >= from => Advance::Extended { from, to },
                _ => Advance::Unchanged,
            });
        }
        let undone: Vec<Txid> = {
            let mut seen = HashSet::new();
            removed
                .into_iter()
                .filter(|t| !self.txs.contains_key(t) && seen.insert(*t))
                .collect()
        };
        Ok(Advance::Reorg {
            fork: from,
            depth: replaced as u32,
            to,
            undone,
        })
    }

    /// The header family followed.
    pub fn family(&self) -> Family {
        self.family
    }

    fn reindex(&mut self) {
        self.txs.clear();
        self.spends.clear();
        for (h, b) in self.blocks.iter().enumerate() {
            for (i, tx) in b.txdata.iter().enumerate() {
                let txid = tx.compute_txid();
                self.txs.insert(txid, (h as u32, i));
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.input {
                    self.spends.insert(input.previous_output, (txid, h as u32));
                }
            }
        }
    }
}

/// Decode a block of family `F`, and check its solution against the
/// challenge: its hash, its parent's hash and its transactions.
fn read_block<F: HeaderFamily>(
    family: &F,
    bytes: &[u8],
    challenge: &ScriptBuf,
) -> core::result::Result<(BlockHash, BlockHash, Vec<Transaction>), String> {
    let block = F::Block::decode(bytes).map_err(|e| e.to_string())?;
    verify_block_solution(family, &block, challenge)
        .map_err(|e| format!("the solution does not satisfy the challenge: {e:?}"))?;
    Ok((
        family.block_hash(block.header()),
        family.prev(block.header()),
        block.txdata().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::secp256k1::SecretKey;
    use sidestr_core::block::{challenge_for, pubkey_of, Block};
    use sidestr_core::blockfile::Entry;
    use sidestr_core::document::Peg;
    use sidestr_core::mirror::encode_record;
    use sidestr_core::state::{NextBlock, State};
    use sidestr_wallet::coins::from_state;

    use crate::{prepare, AgentKey, Payment};

    struct Served {
        index: Index,
        dat: Vec<u8>,
    }

    fn serve(doc: &ChainDocument, blocks: &[Block]) -> Served {
        let mut dat = Vec::new();
        let mut entries = Vec::new();
        for (h, b) in blocks.iter().enumerate() {
            let bytes = serialize(b);
            entries.push(Entry {
                height: h as u32,
                hash: b.block_hash().to_string(),
                offset: dat.len() as u64,
                size: bytes.len() as u32,
            });
            dat.extend(encode_record(h as u32, &bytes));
        }
        Served {
            index: Index {
                network: doc.id.clone(),
                from: 0,
                to: blocks.len() as i64 - 1,
                blocks: entries,
            },
            dat,
        }
    }

    fn sync(f: &mut ChainFollower, s: &Served) -> Advance {
        match f.plan(&s.index).unwrap() {
            Plan::UpToDate => Advance::Unchanged,
            Plan::Truncate { len } => f.truncate(len),
            Plan::Fetch { from, offset } => {
                f.apply(&s.index, from, &s.dat[offset as usize..]).unwrap()
            }
        }
    }

    /// Two branches from one genesis: both mint heights 1–100 (the pegs
    /// mature); `a` pays bob at height 101 and runs to 103, `b` runs to 104
    /// without the payment.
    fn branches() -> (ChainDocument, Vec<Block>, Vec<Block>, Txid, AgentKey) {
        let producer = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let alice = AgentKey::parse(&"11".repeat(32)).unwrap();
        let bob = AgentKey::parse(&"22".repeat(32)).unwrap();
        let mut doc = ChainDocument::from_json(&format!(
            r#"{{"id":"sidestr:follow","name":"follow","parent":"tbtc4","challenge":"{}",
            "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"fw",
            "genesisTime":1790000000,"signer":"{}","minFeeRate":1,"pegs":[]}}"#,
            challenge_for(&pubkey_of(&producer)).to_hex_string(),
            pubkey_of(&producer)
        ))
        .unwrap();
        doc.pegs.push(Peg {
            txid: "a".repeat(64),
            vout: 0,
            amount: 100_000,
            script: alice.script().to_hex_string(),
            extra: Default::default(),
        });
        let genesis = State::genesis_block_for(&doc, &producer).unwrap();
        let mut a = State::with_key(doc.clone(), &producer).unwrap();
        let mut b = State::with_key(doc.clone(), &producer).unwrap();
        let mut ablocks = vec![genesis.clone()];
        let mut bblocks = vec![genesis];
        let next = |t: u32| NextBlock {
            time: 1_790_000_000 + t,
            claims: vec![],
        };
        for t in 1..=100 {
            ablocks.push(a.produce(&producer, &next(t), None).unwrap().1);
            bblocks.push(b.produce(&producer, &next(t), None).unwrap().1);
        }
        let coins = from_state(&a, &alice.script());
        let p = prepare(
            &alice,
            &doc,
            &coins,
            a.height(),
            Payment::Send,
            &bob.script().to_hex_string(),
            30_000,
            None,
            1,
        )
        .unwrap();
        let paid = p.spend.tx.compute_txid();
        a.submit(p.spend.tx).unwrap();
        for t in 101..=103 {
            ablocks.push(a.produce(&producer, &next(t), None).unwrap().1);
        }
        for t in 101..=104 {
            bblocks.push(b.produce(&producer, &next(t + 100), None).unwrap().1);
        }
        (doc, ablocks, bblocks, paid, bob)
    }

    #[test]
    fn a_reorganisation_is_found_measured_and_undone() {
        let (doc, a, b, paid, bob) = branches();
        let mut f = ChainFollower::new(&doc).unwrap();
        assert_eq!(
            sync(&mut f, &serve(&doc, &a)),
            Advance::Extended { from: 0, to: 103 }
        );
        let (h, tx) = f.find_tx(&paid).unwrap();
        assert_eq!(h, 101);
        let spent = tx.input[0].previous_output;
        assert_eq!(f.spender(&spent).unwrap().0, paid);
        assert_eq!(f.confirmations(101), 3);
        assert!(tx.output.iter().any(|o| o.script_pubkey == bob.script()));

        // the producer restarts on the other branch: heights 101–103 replaced
        match sync(&mut f, &serve(&doc, &b)) {
            Advance::Reorg {
                fork,
                depth,
                to,
                undone,
            } => {
                assert_eq!((fork, depth, to), (101, 3, Some(104)));
                assert!(undone.contains(&paid));
            }
            other => panic!("{other:?}"),
        }
        assert!(f.find_tx(&paid).is_none());
        assert!(f.spender(&spent).is_none());
        assert_eq!(f.hash_at(104).unwrap(), b[104].block_hash());

        // back to a shorter chain that agrees up to height 102
        let shorter = serve(&doc, &b[..103]);
        assert_eq!(f.plan(&shorter.index).unwrap(), Plan::Truncate { len: 103 });
        assert!(matches!(
            f.truncate(103),
            Advance::Reorg {
                fork: 103,
                depth: 2,
                to: Some(102),
                ..
            }
        ));
    }

    #[test]
    fn a_forged_or_unlinked_block_is_refused_and_nothing_changes() {
        let (doc, a, _, _, _) = branches();
        let mut f = ChainFollower::new(&doc).unwrap();
        sync(&mut f, &serve(&doc, &a[..3]));
        // a block signed by another key, its hash honestly indexed
        let stranger = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let mut forged = a[3].clone();
        let other = sidestr_core::block::sign_block(
            &Stock,
            &forged,
            &challenge_for(&pubkey_of(&stranger)),
            &stranger,
            &[0u8; 32],
        )
        .unwrap();
        forged = other;
        let mut blocks = a[..3].to_vec();
        blocks.push(forged);
        let s = serve(&doc, &blocks);
        let Plan::Fetch { from, offset } = f.plan(&s.index).unwrap() else {
            panic!()
        };
        assert!(f.apply(&s.index, from, &s.dat[offset as usize..]).is_err());
        assert_eq!(f.height(), Some(2));
        // a hash the index lies about
        let mut lying = serve(&doc, &a[..4]);
        lying.index.blocks[3].hash = a[4].block_hash().to_string();
        let Plan::Fetch { from, offset } = f.plan(&lying.index).unwrap() else {
            panic!()
        };
        assert!(f
            .apply(&lying.index, from, &lying.dat[offset as usize..])
            .is_err());
        // a block that skips its parent
        let mut skipping = a[..3].to_vec();
        skipping.push(a[4].clone());
        let s = serve(&doc, &skipping);
        let Plan::Fetch { from, offset } = f.plan(&s.index).unwrap() else {
            panic!()
        };
        assert!(f.apply(&s.index, from, &s.dat[offset as usize..]).is_err());
        assert_eq!(f.height(), Some(2));
    }

    #[test]
    fn the_live_dreamlab_txbt4_genesis_is_followed() {
        // sidestr:dreamlab-txbt4 as sealed on 2026-10-02: BLAKE2b v2 headers
        let doc = ChainDocument::from_json(include_str!(
            "../../tests/fixtures/dreamlab-txbt4-chain.json"
        ))
        .unwrap();
        let index: Index = serde_json::from_str(include_str!(
            "../../tests/fixtures/dreamlab-txbt4-blocks.json"
        ))
        .unwrap();
        let dat = include_bytes!("../../tests/fixtures/dreamlab-txbt4-blocks.dat");
        let mut f = ChainFollower::new(&doc).unwrap();
        assert_eq!(f.family(), Family::Blake2b);
        let Plan::Fetch { from, offset } = f.plan(&index).unwrap() else {
            panic!()
        };
        f.apply(&index, from, &dat[offset as usize..]).unwrap();
        assert_eq!(
            f.hash_at(0).unwrap().to_string(),
            doc.genesis_hash.clone().unwrap()
        );
        // the same bytes under another signer's challenge are refused
        let mut other = doc.clone();
        other.challenge = format!(
            "5120{}",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        let mut g = ChainFollower::new(&other).unwrap();
        assert!(g.apply(&index, 0, &dat[..]).is_err());
    }
}
